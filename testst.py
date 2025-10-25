# app_streamlit.py
import streamlit as st
from PIL import Image, ImageDraw, ImageFont
import hashlib, datetime, random, os, json, io, tempfile, base64

# ----------------------------- Yardımcı: Session State Başlatma -----------------------------
if "current_image_path" not in st.session_state:
    st.session_state.current_image_path = ""
if "current_image_bytes" not in st.session_state:
    st.session_state.current_image_bytes = None
if "decrypted_image" not in st.session_state:
    st.session_state.decrypted_image = None
if "watermarked_image" not in st.session_state:
    st.session_state.watermarked_image = None
if "hidden_message" not in st.session_state:
    st.session_state.hidden_message = ""
if "secret_key_hash" not in st.session_state:
    st.session_state.secret_key_hash = ""
if "log_lines" not in st.session_state:
    st.session_state.log_lines = []
if "progress" not in st.session_state:
    st.session_state.progress = 0.0

# ----------------------------- Fonksiyonlar (Orijinal mantık korunuyor) -----------------------------
def normalize_time(t):
    return t.strftime("%Y-%m-%d %H:%M") if isinstance(t, datetime.datetime) else str(t)

def hash_image_content(img: Image.Image) -> str:
    return hashlib.sha256(img.tobytes()).hexdigest()

def generate_key(password, open_time_str, image_hash=""):
    combo = (password or "") + open_time_str + image_hash
    return hashlib.sha256(combo.encode("utf-8")).hexdigest()

def make_paths(image_path):
    folder = os.path.dirname(image_path) or "."
    base = os.path.splitext(os.path.basename(image_path))[0]
    enc = os.path.join(folder, f"{base}_encrypted.png")
    dec = os.path.join(folder, f"{base}_decrypted.png")
    meta = os.path.join(folder, f"{base}_encrypted.meta")
    return enc, dec, meta

def create_keystream(key_hex, w, h):
    random.seed(int(key_hex, 16))
    return [random.randint(0, 255) for _ in range(w * h * 3)]

def pil_from_bytes(b: bytes) -> Image.Image:
    return Image.open(io.BytesIO(b)).convert("RGB")

def bytes_from_pil(img: Image.Image, format="PNG") -> bytes:
    b = io.BytesIO()
    img.save(b, format=format)
    return b.getvalue()

# Log helper
def log(text):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    st.session_state.log_lines.append(f"[{ts}] {text}")

def get_log_text():
    return "\n".join(st.session_state.log_lines)

# ----------------------------- Encrypt / Decrypt (Mantık aynı) -----------------------------
def encrypt_image_file_from_bytes(original_bytes, password, open_time_str, secret_text, secret_key, out_enc_path, meta_path, allow_no_password, progress_callback=None):
    img = pil_from_bytes(original_bytes)
    w, h = img.size
    px = img.load()
    image_hash = hash_image_content(img)

    key_hex = generate_key(password, open_time_str, image_hash)
    ks = create_keystream(key_hex, w, h)

    enc_img = Image.new("RGB", (w, h))
    enc_px = enc_img.load()
    i = 0
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            enc_px[x, y] = (r ^ ks[i], g ^ ks[i+1], b ^ ks[i+2])
            i += 3
        if progress_callback and (y % 10 == 0 or y == h-1):
            progress_callback((y + 1) / h)

    enc_img.save(out_enc_path)

    verify_tag = hashlib.sha256(key_hex.encode("utf-8") + img.tobytes()).hexdigest()
    secret_key_hash = hashlib.sha256(secret_key.encode('utf-8')).hexdigest() if secret_key else ""

    meta = {
        "open_time": open_time_str,
        "allow_no_password": bool(allow_no_password),
        "verify_tag": verify_tag,
        "hidden_message": secret_text,
        "image_content_hash": image_hash,
        "secret_key_hash": secret_key_hash
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    if progress_callback:
        progress_callback(1.0)
    return verify_tag, out_enc_path, image_hash

def decrypt_image_from_file(enc_path, password, open_time_str, image_hash, progress_callback=None):
    img = Image.open(enc_path).convert("RGB")
    w, h = img.size
    px = img.load()

    key_hex = generate_key(password, open_time_str, image_hash)
    ks = create_keystream(key_hex, w, h)

    dec_img = Image.new("RGB", (w, h))
    dec_px = dec_img.load()
    i = 0
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            dec_px[x, y] = (r ^ ks[i], g ^ ks[i+1], b ^ ks[i+2])
            i += 3
        if progress_callback and (y % 10 == 0 or y == h-1):
            progress_callback((y + 1) / h)

    if progress_callback:
        progress_callback(1.0)
    return dec_img, key_hex

# ----------------------------- Filigran (Aynı) -----------------------------
def add_text_watermark(img: Image.Image, hidden_message: str) -> Image.Image:
    img_copy = img.copy()
    draw = ImageDraw.Draw(img_copy, 'RGBA')
    w, h = img_copy.size

    if not hidden_message.strip():
        return img

    text_lines = [
        "*** GİZLİ MESAJ ***",
        f"{hidden_message}"
    ]
    full_text = "\n".join(text_lines)

    try:
        font = ImageFont.truetype("arial.ttf", 24)
    except IOError:
        font = ImageFont.load_default()

    text_color = (255, 0, 0, 255)
    try:
        bbox = draw.textbbox((0, 0), full_text, font=font, anchor="ls")
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
    except AttributeError:
        text_w, text_h = draw.textsize(full_text, font=font)

    x = w - text_w - 20
    y = h - text_h - 20

    padding = 10
    draw.rectangle([x - padding, y - padding, x + text_w + padding, y + text_h + padding], fill=(0, 0, 0, 150))
    draw.text((x, y), full_text, font=font, fill=text_color)

    return img_copy

# ----------------------------- UI: Sağ/Tek sayfa düzeni -----------------------------
st.set_page_config(page_title="Zamanlı Görsel Şifreleme", layout="wide")
st.title("🖼️ Zaman Ayarlı Görsel Şifreleme")

# Sidebar (tema seçimi ve işlemler)
with st.sidebar:
    st.header("Ayarlar & Araçlar")
    theme_choice = st.selectbox("Tema Seçimi:", ["Dark", "Light"], index=0)
    # (Streamlit temayı doğrudan değiştirmez; ama yine gösteriyoruz)
    st.write("Seçili Tema:", theme_choice)
    if st.button("Örnek Resim Oluştur"):
        # Orijinal create_sample_image mantığı
        img = Image.new("RGB", (600,400), color=(70,130,180))
        for y in range(img.height):
            for x in range(img.width):
                img.putpixel((x,y), (70 + int(x/img.width*80), 130 + int(y/img.height*40), 180))
        sample_path = os.path.join(os.getcwd(), "sample_for_encrypt.png")
        img.save(sample_path)
        st.session_state.current_image_path = sample_path
        st.session_state.current_image_bytes = bytes_from_pil(img, "PNG")
        st.session_state.decrypted_image = None
        log(f"Örnek resim oluşturuldu: {sample_path}")
        st.success(f"Örnek resim oluşturuldu: {sample_path}")

    if st.button("Klasörü Aç (Sunucu tarafı)"):
        # Streamlit sunucusunda klasör açmak istemeyiz; sadece log atalım
        log("Klasör açma talebi: Sunucuda tarayıcı penceresi açılamaz. Çalışma dizinine göz atın.")
        st.info("Sunucu tarafında klasör açma yapılamaz; çıktı dosyalar çalışma dizinine kaydedilir.")

# Main columns: sol - ayarlar, sağ - önizleme & log
col1, col2 = st.columns([0.45, 0.55])

with col1:
    st.subheader("Dosya & Ayarlar")

    uploaded = st.file_uploader("Resim seçin veya örnek oluştur", type=["png","jpg","jpeg","bmp"])
    if uploaded is not None:
        # kaydet belleğe ve geçici dosyaya
        bytes_data = uploaded.read()
        st.session_state.current_image_bytes = bytes_data
        # temp dosya path (kullanıcı orijinali yerine temp path)
        fd, tmp_path = tempfile.mkstemp(suffix=os.path.splitext(uploaded.name)[1])
        os.close(fd)
        with open(tmp_path, "wb") as f:
            f.write(bytes_data)
        st.session_state.current_image_path = tmp_path
        st.session_state.decrypted_image = None
        st.session_state.secret_key_hash = ""
        log("Dosya seçildi: " + tmp_path)

    entry_pass = st.text_input("Görsel Şifresi (Çözme için):", type="password")
    # pw strength (aynı mantık)
    score = 0.0
    if len(entry_pass) >= 8: score += 0.3
    if any(c.isdigit() for c in entry_pass): score += 0.2
    if any(c.isupper() for c in entry_pass): score += 0.2
    if any(not c.isalnum() for c in entry_pass): score += 0.3
    st.progress(min(score, 1.0), text="Şifre Güç Göstergesi")

    allow_no_pass = st.checkbox("Şifresiz açılmaya izin ver", value=False)

    entry_secret_text = st.text_input("Gizli Mesaj (Meta veriye saklanır):", value="")

    entry_secret_key = st.text_input("Gizli Mesaj Şifresi (Filigranı görmek için):", type="password")

    entry_time = st.text_input("Açılma Zamanı (YYYY-AA-GG SS:DD):", placeholder="Örn: 2025-12-31 23:59")

    # Butonlar
    btn_encrypt = st.button("🔒 Şifrele")
    btn_decrypt = st.button("🔓 Çöz")

    # Hidden state toggles
    show_hidden_toggle = st.button("Gizli Mesajı Göster/Gizle")

with col2:
    st.subheader("Önizleme")
    preview_slot = st.empty()
    if st.session_state.current_image_bytes:
        try:
            preview_img = pil_from_bytes(st.session_state.current_image_bytes)
            # eğer çözülmüş bir resim varsa öncelik ona
            if st.session_state.decrypted_image is not None:
                display_img = st.session_state.decrypted_image.copy()
            else:
                display_img = preview_img.copy()
            preview_slot.image(display_img, use_column_width=True)
        except Exception as e:
            preview_slot.write("Önizleme yüklenemedi: " + str(e))
    else:
        preview_slot.write("(Resim seçilmedi)")

    st.subheader("İşlem Durumu")
    progress_bar = st.progress(st.session_state.progress)
    log_container = st.empty()
    log_container.text_area("İşlem Günlüğü", value=get_log_text(), height=220)

    # Gizli mesaj label
    if st.session_state.hidden_message.strip():
        if st.session_state.secret_key_hash:
            st.info("Not: Gizli mesaj meta veride bulundu. Filigran için gizli şifre gerekir.")
        else:
            st.info("Not: Gizli mesaj meta veride bulundu. Filigran için şifre yok.")

# ----------------------------- İşlem Fonksiyonları (Buton tetiklendiğinde) -----------------------------
def set_progress(p):
    st.session_state.progress = float(p)
    # güncelleme için streamlit progress objesini güncelle
    try:
        progress_bar.progress(min(max(p, 0.0), 1.0))
    except Exception:
        pass

def save_bytes_to_path(b: bytes, path: str):
    with open(path, "wb") as f:
        f.write(b)

# Şifrele butonu
if btn_encrypt:
    st.session_state.log_lines = []  # temizle
    set_progress(0.0)
    image_bytes = st.session_state.current_image_bytes
    if not image_bytes:
        st.error("Hata: Lütfen bir resim dosyası seçin veya örnek oluşturun.")
        log("Hata: Dosya ve zaman gerekli.")
    elif not entry_time.strip():
        st.error("Hata: Lütfen açılma zamanını belirtin.")
        log("Hata: Dosya ve zaman gerekli.")
    else:
        try:
            # parse zamanı
            ot_dt = datetime.datetime.strptime(entry_time.strip(), "%Y-%m-%d %H:%M")
            open_time_str = normalize_time(ot_dt)
            # output paths - çalışma dizinine kaydedeceğiz
            # orijinal path veya temp path
            image_path = st.session_state.current_image_path or os.path.join(os.getcwd(), "uploaded_image.png")
            enc_path, dec_path, meta_path = make_paths(image_path)
            log("Şifreleme başlıyor...")
            verify_tag, out_enc, img_hash = encrypt_image_file_from_bytes(
                image_bytes,
                entry_pass if not allow_no_pass else "",
                open_time_str,
                entry_secret_text,
                entry_secret_key,
                enc_path,
                meta_path,
                allow_no_pass,
                progress_callback=set_progress
            )
            log(f"Şifreleme tamamlandı: {out_enc}")
            st.success(f"Şifreleme tamamlandı!\n\nŞifreli dosya: {out_enc}\nMeta dosyası: {meta_path}")
            # güncelle: streamlit preview için şifreli dosyanın bytes'ını yükle
            with open(out_enc, "rb") as f:
                st.session_state.current_image_bytes = f.read()
                st.session_state.current_image_path = out_enc
            # indirme butonları
            with open(out_enc, "rb") as f:
                st.download_button("Şifreli Dosyayı İndir", data=f, file_name=os.path.basename(out_enc), mime="image/png")
            with open(meta_path, "r", encoding="utf-8") as f:
                st.download_button("Meta Dosyasını İndir", data=f.read().encode("utf-8"), file_name=os.path.basename(meta_path), mime="application/json")
        except Exception as e:
            log("Şifreleme hatası: " + str(e))
            st.error("Şifreleme Hatası: " + str(e))
            set_progress(0.0)

# Çöz butonu
if btn_decrypt:
    st.session_state.log_lines = []
    set_progress(0.0)
    image_path = st.session_state.current_image_path
    if not image_path:
        st.error("Hata: Lütfen şifresini çözeceğiniz dosyayı seçin.")
        log("Hata: Dosya yolu girin.")
    else:
        # meta dosyasını bul
        base_path = image_path.replace("_encrypted.png", "")
        enc_path, dec_path, meta_path = make_paths(base_path)
        meta = None
        if os.path.exists(meta_path):
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except Exception:
                meta = None
        if not meta:
            log("Hata: Meta dosyası bulunamadı veya bozuk.")
            st.error(f"Meta Dosyası Hatası: Gerekli meta dosyası bulunamadı veya bozuk:\n{meta_path}")
        else:
            try:
                open_time_str = meta.get("open_time")
                allow_no = bool(meta.get("allow_no_password", False))
                stored_tag = meta.get("verify_tag")
                st.session_state.hidden_message = meta.get("hidden_message", "")
                image_hash = meta.get("image_content_hash", "")
                st.session_state.secret_key_hash = meta.get("secret_key_hash", "")

                now = datetime.datetime.now()
                ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M")
                if now < ot_dt:
                    log("Henüz zamanı gelmedi.")
                    st.warning(f"Bekleme Gerekli: Bu dosyanın açılmasına daha var.\n\nAçılma Zamanı: {open_time_str}")
                else:
                    pw_to_use = "" if allow_no else entry_pass
                    if (not allow_no) and (not entry_pass):
                        log("Hata: Şifre gerekli.")
                        st.warning("Bu dosya için şifre gereklidir.")
                    else:
                        log("Çözme işlemi başlıyor...")
                        dec_img, key_hex = decrypt_image_from_file(enc_path, pw_to_use, open_time_str, image_hash, progress_callback=set_progress)
                        calc_tag = hashlib.sha256(key_hex.encode("utf-8") + dec_img.tobytes()).hexdigest()
                        if calc_tag != stored_tag:
                            log("Doğrulama başarısız: yanlış şifre, yanlış görsel veya bozulmuş dosya.")
                            st.error("Çözme Hatası: Yanlış şifre girildi, yanlış görsel için meta dosyası kullanıldı veya dosya bozulmuş. Çözme işlemi iptal edildi.")
                            set_progress(0.0)
                            st.session_state.hidden_message = ""
                            st.session_state.secret_key_hash = ""
                        else:
                            st.session_state.decrypted_image = dec_img
                            # kaydet disk'e
                            dec_img.save(dec_path)
                            log("Çözülmüş orijinal görsel diske kaydedildi: " + dec_path)
                            st.success("Görselin şifresi çözüldü.")
                            # indirme düğmesi
                            with open(dec_path, "rb") as f:
                                st.download_button("Çözülmüş Görseli İndir", data=f, file_name=os.path.basename(dec_path), mime="image/png")
                            if st.session_state.hidden_message.strip():
                                log(f"Not: Gizli bir mesaj bulundu! Görmek için butona tıklayın. (Gizli Şifre gerekli: {'Evet' if st.session_state.secret_key_hash else 'Hayır'})")
            except Exception as e:
                log("Çözme hatası: " + str(e))
                st.error("Çözme Hatası: " + str(e))
                set_progress(0.0)
                st.session_state.hidden_message = ""
                st.session_state.secret_key_hash = ""

# Gizli mesaj göster/gizle butonu işlevi (modal ile şifre sor)
if show_hidden_toggle:
    if not st.session_state.decrypted_image:
        st.warning("Hata: Önizlemede çözülmüş bir görsel yok.")
        log("Hata: Önizlemede çözülmüş bir görsel yok.")
    elif not st.session_state.hidden_message.strip():
        st.info("Gizli mesaj meta verisinde bulunamadı.")
        log("Gizli mesaj meta verisinde bulunamadı.")
    else:
        # Eğer secret_key_hash varsa modal ile sorma; yoksa doğrudan göster
        if st.session_state.secret_key_hash:
            with st.modal("Gizli Mesaj Şifresi", clear_on_submit=False):
                entered = st.text_input("Gizli mesaj filigranını görmek için şifreyi girin:", type="password", key="modal_secret_input")
                ok = st.button("Tamam", key="modal_ok")
                cancel = st.button("İptal", key="modal_cancel")
                if ok:
                    entered_hash = hashlib.sha256(entered.encode('utf-8')).hexdigest()
                    if entered_hash != st.session_state.secret_key_hash:
                        st.error("Gizli mesaj filigranı için girilen şifre yanlış.")
                        log("Hata: Gizli mesaj şifresi yanlış.")
                    else:
                        log("Gizli mesaj şifresi doğru. Filigran gösteriliyor...")
                        # filigranlı görüntüyü oluştur ve preview'yi güncelle
                        st.session_state.watermarked_image = add_text_watermark(st.session_state.decrypted_image, st.session_state.hidden_message)
                        # göster
                        st.image(st.session_state.watermarked_image, use_column_width=True)
                        st.success("Filigran gösterildi.")
                if cancel:
                    log("Gizli mesaj şifresi girilmedi. İşlem iptal edildi.")
        else:
            # doğrudan göster
            st.session_state.watermarked_image = add_text_watermark(st.session_state.decrypted_image, st.session_state.hidden_message)
            st.image(st.session_state.watermarked_image, use_column_width=True)
            log("Gizli mesaj şifresi yok. Filigran gösteriliyor...")

# Preview güncelleme: eğer watermarked veya decrypted varsa göster
if st.session_state.watermarked_image is not None:
    with col2:
        st.image(st.session_state.watermarked_image, use_column_width=True)
elif st.session_state.decrypted_image is not None:
    with col2:
        st.image(st.session_state.decrypted_image, use_column_width=True)

# Log alanını güncelle
log_container.text_area("İşlem Günlüğü", value=get_log_text(), height=220)

# Footer/help
st.markdown("---")
st.caption("Kılavuz: 1) Resim seçin veya Örnek oluştur. 2) Gerekliyse şifre girin. 3) Açılma zamanını girin. 4) Şifrele / Çöz butonlarını kullanın. Çözdükten sonra gizli mesajı görmek için 'Gizli Mesajı Göster/Gizle' butonuna tıklayın.")

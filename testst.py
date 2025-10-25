import streamlit as st
from PIL import Image, ImageDraw, ImageFont 
import hashlib, datetime, random, os, json, io

# ----------------------------- Ayarlar ve Başlık -----------------------------
st.set_page_config(
    page_title="Zamanlı Görsel Şifreleme",
    page_icon="🖼️",
    layout="wide"
)

st.title("🖼️ Zamanlı Görsel Şifreleme (Streamlit)")

# ----------------------------- Session State (Oturum Durumu) -----------------------------
def init_state():
    """Tüm oturum durumlarını başlatır ve varsayılanları atar."""
    # Kararlı başlangıç değeri: Şu andan bir gün sonrası 
    default_open_time = datetime.datetime.now() + datetime.timedelta(days=1)
    
    defaults = {
        'log': "",
        'decrypted_image': None,
        'watermarked_image': None,
        'hidden_message': "",
        'secret_key_hash': "",
        'is_message_visible': False,
        'prompt_secret_key': False,
        'generated_enc_bytes': None,
        'generated_meta_bytes': None,
        # datetime_input için kararlı başlangıç değeri
        'encryption_start_time': default_open_time 
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_state()

# ----------------------------- Yardımcı Fonksiyonlar -----------------------------

def log(text):
    """Streamlit için loglama fonksiyonu. Logları session_state'e ekler."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    st.session_state.log = f"[{ts}] {text}\n" + st.session_state.log

def normalize_time(t):
    # datetime objesini YYYY-MM-DD HH:MM formatında döndürür
    if isinstance(t, datetime.datetime):
        return t.strftime("%Y-%m-%d %H:%M")
    return "" # Güvenli dönüş

def hash_image_content(img: Image.Image) -> str:
    # Resim içeriğinin SHA256 özetini döndürür
    return hashlib.sha256(img.tobytes()).hexdigest()

def generate_key(password, open_time_str, image_hash=""):
    # Şifreleme anahtarını oluşturur
    combo = (password or "") + open_time_str + image_hash
    return hashlib.sha256(combo.encode("utf-8")).hexdigest()

def create_keystream(key_hex, w, h):
    # Anahtardan bir rastgele anahtar akışı (keystream) oluşturur
    random.seed(int(key_hex, 16))
    return [random.randint(0, 255) for _ in range(w * h * 3)]

def add_text_watermark(img: Image.Image, hidden_message: str) -> Image.Image:
    """Şifre çözülmüş görselin üzerine SADECE gizli mesajı ekler."""
    img_copy = img.copy()
    draw = ImageDraw.Draw(img_copy, 'RGBA')
    w, h = img_copy.size
    
    if not hidden_message.strip():
        return img 

    text_lines = [
        "*** GİZLİ MESAJ (FILIGRAN) ***",
        f"{hidden_message}"
    ]
    full_text = "\n".join(text_lines)
    
    # Font yükleme denemesi
    try:
        font_path = "arial.ttf" # Sistemin varsayılan fontunu kullanmayı deneyin
        font = ImageFont.truetype(font_path, 30)
    except IOError:
        try:
             # Eğer arial yoksa varsayılanı kullan
            font = ImageFont.load_default().font_variant(size=30)
        except:
             font = ImageFont.load_default()
        
    text_color = (255, 0, 0, 255)
    
    # Text boyutunu hesapla
    try:
        bbox = draw.textbbox((0, 0), full_text, font=font, anchor="ls")
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
    except AttributeError:
        # Eski PIL versiyonları veya font hatası için
        text_w = 400 
        text_h = 60

    x = w - text_w - 20
    y = h - text_h - 20

    padding = 10
    # Mesaj arka planı
    draw.rectangle([x - padding, y - padding, x + text_w + padding, y + text_h + padding], fill=(0, 0, 0, 150)) 
    # Mesaj metni
    draw.text((x, y), full_text, font=font, fill=text_color)
    
    return img_copy

# ----------------------------- Örnek Resim Oluşturma -----------------------------
def create_sample_image_bytes():
    """Hafızada (bytes) örnek resim oluşturur."""
    img = Image.new("RGB", (600,400), color=(70,130,180))
    for y in range(img.height):
        for x in range(img.width):
            img.putpixel((x,y), (70 + int(x/img.width*80), 130 + int(y/img.height*40), 180))
    
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_bytes = img_byte_arr.getvalue()
    log("Örnek resim hafızada oluşturuldu.")
    return img_bytes

# ----------------------------- Çekirdek (encrypt/decrypt) -----------------------------

def encrypt_image_file(image_bytes, password, open_time_dt, secret_text, secret_key, allow_no_password, progress_bar):
    """Şifreleme işlemini yapar."""
    
    # NONE HATASI İÇİN KATI KONTROL
    if open_time_dt is None:
        log("Hata: Açılma zamanı None olarak geldi. İşlem durduruldu.")
        st.error("Şifreleme sırasında kritik hata: Geçerli bir açılma zamanı alınamadı.")
        return None, None

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as e:
        log(f"Hata: Resim dosyası okunamadı: {e}")
        st.error(f"Hata: Yüklenen resim dosyası açılamadı: {e}")
        return None, None

    w, h = img.size
    px = img.load()
    
    image_hash = hash_image_content(img)
    open_time_str = normalize_time(open_time_dt) # Tarih/saat stringe çevrildi
    
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
        if y % 10 == 0:
            progress_bar.progress((y + 1) / h, text="Şifreleniyor...")
            
    # Şifreli resmi hafızada (bytes) hazırla
    enc_img_byte_arr = io.BytesIO()
    enc_img.save(enc_img_byte_arr, format='PNG')
    enc_img_bytes = enc_img_byte_arr.getvalue()

    # Meta veriler oluşturuluyor
    verify_tag = hashlib.sha256(key_hex.encode("utf-8") + img.tobytes()).hexdigest()
    secret_key_hash = hashlib.sha256(secret_key.encode('utf-8')).hexdigest() if secret_key else ""

    meta = {
        "open_time": open_time_str, # Tarih ve saat bu alanda saklanıyor
        "allow_no_password": bool(allow_no_password), 
        "verify_tag": verify_tag, 
        "hidden_message": secret_text,
        "image_content_hash": image_hash,
        "secret_key_hash": secret_key_hash
    }
    
    meta_json_bytes = json.dumps(meta, ensure_ascii=False, indent=2).encode('utf-8')

    progress_bar.progress(1.0, text="Tamamlandı!")
    return enc_img_bytes, meta_json_bytes

def decrypt_image_in_memory(enc_image_bytes, password, open_time_str, image_hash, progress_bar):
    """Şifreli byte dizisini çözer ve çözülmüş PIL Image objesini döndürür."""
    try:
        img = Image.open(io.BytesIO(enc_image_bytes)).convert("RGB")
    except Exception as e:
        log(f"Hata: Şifreli resim dosyası okunamadı: {e}")
        st.error(f"Hata: Yüklenen şifreli resim dosyası açılamadı: {e}")
        return None, None

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
        if y % 10 == 0:
            progress_bar.progress((y + 1) / h, text="Şifre çözülüyor...")

    progress_bar.progress(1.0, text="Tamamlandı!")
    return dec_img, key_hex

# ----------------------------- ARAYÜZ (UI) -----------------------------

# --- Sidebar (Kenar Çubuğu) ---
with st.sidebar:
    st.image(create_sample_image_bytes(), use_container_width=True, caption="Örnek Resim Görünümü")
    
    st.subheader("Örnek Resim")
    st.info("Test için hızlıca bir resim oluşturun ve şifreleme sekmesinden indirin.")
    
    if st.button("Örnek Resim Oluştur", key="sidebar_sample_btn", use_container_width=True):
        img_bytes = create_sample_image_bytes()
        st.session_state.generated_enc_bytes = img_bytes 
        st.session_state.generated_meta_bytes = None 
        log("Test için örnek resim oluşturuldu. 'Şifrele' sekmesinden indirebilirsiniz.")

    with st.expander("Yardım (Kullanım Kılavuzu)"):
        st.markdown(
            """
            **Şifreleme:**
            1. `🔒 Şifrele` sekmesine gidin.
            2. Bir resim dosyası (`.png`, `.jpg`) yükleyin.
            3. Gerekli ayarları (şifre, zaman, gizli mesaj) yapın. **(Zaman ve Şifre dahil)**
            4. `Şifrele` butonuna basın.
            5. Oluşturulan `.png` ve `.meta` dosyalarını indirin.
            
            **Şifre Çözme:**
            1. `🔓 Çöz` sekmesine gidin.
            2. Şifrelenmiş `.png` dosyasını ve ilgili `.meta` dosyasını yükleyin.
            3. Görsel şifresini (eğer gerekliyse) girin.
            4. `Çöz` butonuna basın.
            5. Resim, **zamanı geldiyse** ve şifre doğruysa sağdaki önizlemede görünecektir.
            6. `Gizli Mesajı Göster` butonu (eğer mesaj varsa) aktifleşir.
            """
        )
    
    st.subheader("İşlem Günlüğü")
    st.text_area("Loglar", value=st.session_state.log, height=300, disabled=True, key="log_area")


# --- Ana Alan (Sekmeler) ---
tab_encrypt, tab_decrypt = st.tabs(["🔒 Şifrele", "🔓 Çöz"])

# --- ŞİFRELEME SEKMESİ ---
with tab_encrypt:
    st.subheader("Yeni Bir Görseli Şifrele")
    
    # KULLANILABİLECEK MİNİMUM ZAMANI HESAPLA (Şu anki zamandan 1 dakika sonrası)
    min_date_relaxed = datetime.datetime.now() + datetime.timedelta(minutes=1)

    with st.form("encrypt_form"):
        uploaded_file = st.file_uploader(
            "1. Şifrelenecek resmi seçin", 
            type=["png", "jpg", "jpeg", "bmp"],
            key="enc_file_uploader" 
        )
        
        st.markdown("---")
        st.markdown("**Şifreleme Ayarları**")
        
        # GÖRSEL ŞİFRESİ (Encryption Password)
        enc_pass = st.text_input("Görsel Şifresi (Çözme için)", type="password", key="enc_pass_input")
        enc_no_pass = st.checkbox("Şifresiz açılmaya izin ver (Sadece zaman kilidi)", key="enc_no_pass_checkbox")
        
        enc_secret_text = st.text_area("Gizli Mesaj (Meta veriye saklanır)", placeholder="Gizli notunuz...", key="enc_secret_text_area")
        enc_secret_key = st.text_input("Gizli Mesaj Şifresi (Filigranı görmek için)", type="password", placeholder="Filigranı açacak şifre", key="enc_secret_key_input")
        
        # AÇILMA ZAMANI (Datetime Input) - KARARLILIK İÇİN GÜNCELLENDİ
        
        enc_time = st.datetime_input(
            "Açılma Zamanı (Bu zamandan önce açılamaz)", 
            value=st.session_state.encryption_start_time,
            min_value=min_date_relaxed, # Minimum değer 1 dakika sonrası olarak ayarlandı
            key="encryption_time_input_fixed", 
            help=f"Resmin şifresi sadece bu tarih ve saatten SONRA çözülebilir. Lütfen saati ve tarihi dikkatlice ayarlayın. Minimum ayar: {normalize_time(min_date_relaxed)}"
        )
        
        # Kullanıcı değeri değiştirdiğinde, kararlı değeri de güncelleyelim.
        if enc_time is not None:
             st.session_state.encryption_start_time = enc_time
        
        submitted = st.form_submit_button("🔒 Şifrele", use_container_width=True, key="enc_submit_button")

    if submitted:
        if uploaded_file is None:
            st.error("Lütfen önce bir resim dosyası yükleyin.")
        elif enc_time is None:
             st.error("Lütfen geçerli bir açılma zamanı seçin.")
        else:
            log("Şifreleme başlatıldı...")
            progress_bar = st.progress(0, text="Başlatılıyor...")
            image_bytes = uploaded_file.getvalue()
            
            pw_to_use = "" if enc_no_pass else enc_pass
            
            enc_bytes, meta_bytes = encrypt_image_file(
                image_bytes, pw_to_use, enc_time, 
                enc_secret_text, enc_secret_key, enc_no_pass,
                progress_bar
            )
            
            if enc_bytes and meta_bytes:
                log("Şifreleme tamamlandı. Dosyalar indirilmeye hazır.")
                st.success("Şifreleme Başarılı! Lütfen her iki dosyayı da indirin.")
                st.session_state.generated_enc_bytes = enc_bytes
                st.session_state.generated_meta_bytes = meta_bytes
                
                base_name = os.path.splitext(uploaded_file.name)[0]
                enc_filename = f"{base_name}_encrypted.png"
                meta_filename = f"{base_name}_encrypted.meta"
                
                st.download_button(
                    label="1. Şifreli Resmi (.png) İndir",
                    data=st.session_state.generated_enc_bytes,
                    file_name=enc_filename,
                    mime="image/png",
                    key="download_enc_button"
                )
                st.download_button(
                    label="2. Meta Dosyasını (.meta) İndir",
                    data=st.session_state.generated_meta_bytes,
                    file_name=meta_filename,
                    mime="application/json",
                    key="download_meta_button"
                )
            else:
                log("Şifreleme başarısız.")
                st.error("Şifreleme sırasında bir hata oluştu. Logları kontrol edin.")
    
    # Örnek resim indirme butonu, sadece meta_bytes yoksa göster
    elif st.session_state.generated_enc_bytes and not st.session_state.generated_meta_bytes:
        st.info("Kenar çubuğunda oluşturulan örnek resmi indirin.")
        st.download_button(
            label="Örnek Resmi İndir",
            data=st.session_state.generated_enc_bytes,
            file_name="sample_for_encrypt.png",
            mime="image/png",
            key="download_sample_button"
        )


# --- ŞİFRE ÇÖZME SEKMESİ ---
with tab_decrypt:
    st.subheader("Şifreli Bir Görseli Çöz")
    
    col1, col2 = st.columns(2)
    
    meta_data_placeholder = col1.empty()

    with col1:
        st.markdown("**1. Dosyaları Yükle**")
        enc_file = st.file_uploader("Şifreli resmi (.png) seçin", type="png", key="dec_enc_file_uploader")
        meta_file = st.file_uploader("Meta dosyasını (.meta) seçin", type="meta", key="dec_meta_file_uploader")
        
        meta_data_available = False
        meta = {}
        if meta_file:
            try:
                # Meta dosyasını okuma ve önizleme
                meta_content = meta_file.getvalue().decode('utf-8')
                meta = json.loads(meta_content)
                meta_data_available = True
                
                # Açılma zamanı kontrolü
                open_time_str = meta.get("open_time", "Bilinmiyor")
                ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M")
                
                now = datetime.datetime.now()
                is_open = "🔓 AÇILABİLİR" if now >= ot_dt else "🔒 KİLİTLİ"
                color = "green" if now >= ot_dt else "red"
                
                # Geçerli saati de göstermek kullanıcıya yardımcı olacaktır
                current_time_str = normalize_time(now)

                meta_data_placeholder.markdown(
                    f"**Açılma Zamanı Bilgisi:**\n\n"
                    f"- Hedeflenen Açılma Zamanı: **<span style='color:{color}'>{open_time_str}</span>**\n"
                    f"- Şu Anki Zaman: **{current_time_str}**\n\n"
                    f"Durum: **{is_open}**", 
                    unsafe_allow_html=True
                )
                
            except Exception as e:
                meta_data_placeholder.error("Meta dosya okuma hatası veya geçersiz format.")
                log(f"Meta dosya önizleme hatası: {e}")

        st.markdown("**2. Şifreyi Gir**")
        # GÖRSEL ŞİFRESİ (Decryption Password)
        dec_pass = st.text_input("Görsel Şifresi (gerekliyse)", type="password", key="decrypt_pass")
        
        if st.button("🔓 Çöz", use_container_width=True, key="decrypt_button"):
            # Önceki sonuçları temizle
            for k in ['decrypted_image', 'watermarked_image', 'is_message_visible', 'prompt_secret_key']:
                st.session_state[k] = None
            
            log("--- Yeni Çözme İşlemi Başlatıldı ---")
            
            if not enc_file or not meta_file:
                st.error("Lütfen hem şifreli .png hem de .meta dosyasını yükleyin.")
            elif not meta_data_available:
                 st.error("Yüklenen meta dosyası geçerli bir JSON formatında değil.")
            else:
                try:
                    open_time_str = meta.get("open_time")
                    allow_no = bool(meta.get("allow_no_password", False))
                    stored_tag = meta.get("verify_tag")
                    image_hash = meta.get("image_content_hash", "")
                    
                    st.session_state.hidden_message = meta.get("hidden_message", "")
                    st.session_state.secret_key_hash = meta.get("secret_key_hash", "")

                    now = datetime.datetime.now()
                    ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M") # Zaman kontrolü için datetime objesine dönüştürüldü
                    
                    if now < ot_dt:
                        log("Hata: Henüz zamanı gelmedi.")
                        st.warning(f"Bu dosyanın açılmasına daha var.\n\nAçılma Zamanı: {open_time_str}")
                    else:
                        pw_to_use = "" # Şifre çözme için kullanılacak şifre
                        
                        # Şifre kontrol mantığı
                        if not allow_no and not dec_pass:
                            log("Hata: Şifre gerekli ancak girilmedi.")
                            st.error("Bu dosya için görsel şifresi gereklidir, ancak şifre girilmedi.")
                            return
                        elif not allow_no:
                             # Şifre gerekiyorsa, girilen şifreyi kullan
                             pw_to_use = dec_pass
                        else:
                            # Şifre gerekmiyorsa pw_to_use zaten ""
                            pass

                        # Çözme işlemini başlatma
                        log("Zaman ve şifre kontrolleri tamam. Çözme işlemi başlıyor...")
                        progress_bar = st.progress(0, text="Başlatılıyor...")
                        enc_image_bytes = enc_file.getvalue()
                        
                        dec_img, key_hex = decrypt_image_in_memory(
                            enc_image_bytes, pw_to_use, open_time_str, image_hash, progress_bar
                        )
                        
                        if dec_img is None:
                            pass # Hata zaten decrypt_image_in_memory içinde loglandı
                        else:
                            calc_tag = hashlib.sha256(key_hex.encode("utf-8") + dec_img.tobytes()).hexdigest()
                            
                            if calc_tag != stored_tag:
                                log("Doğrulama başarısız: Yanlış şifre veya bozuk dosya.")
                                st.error("Çözme Hatası: Yanlış şifre girildi veya dosyalar bozulmuş.")
                                st.session_state.decrypted_image = None
                            else:
                                log("Doğrulama başarılı! Resim çözüldü.")
                                st.success("Görselin şifresi başarıyla çözüldü!")
                                st.session_state.decrypted_image = dec_img 
                                    
                except Exception as e:
                    log(f"Çözme hatası: {e}")
                    st.error(f"Çözme sırasında beklenmedik bir hata oluştu: {e}")
                    st.session_state.decrypted_image = None 

    with col2:
        st.subheader("Önizleme")
        
        image_to_show = None
        caption = "Çözüldükten sonra resim burada görünecek."
        
        if st.session_state.is_message_visible and st.session_state.watermarked_image is not None:
            image_to_show = st.session_state.watermarked_image
            caption = "Çözülmüş Görüntü (Filigranlı)"
        elif st.session_state.decrypted_image is not None:
            image_to_show = st.session_state.decrypted_image
            caption = "Çözülmüş Görüntü (Orijinal)"

        if image_to_show:
            st.image(image_to_show, caption=caption, use_container_width=True)
            
            img_byte_arr = io.BytesIO()
            image_to_show.save(img_byte_arr, format='PNG')
            st.download_button(
                label="Görüntülenen Resmi İndir",
                data=img_byte_arr.getvalue(),
                file_name="decrypted_image.png",
                mime="image/png",
                key="download_displayed_image_button"
            )
        else:
            st.info(caption)
        
        st.markdown("---")
        
        # --- Gizli Mesaj Gösterme Mantığı (Form yerine butonlar kullanıldı) ---
        
        if st.session_state.decrypted_image is not None and st.session_state.hidden_message:
            
            if st.session_state.is_message_visible:
                if st.button("Gizli Mesajı Gizle", use_container_width=True, key="hide_secret_btn"):
                    log("Gizli mesaj gizlendi.")
                    st.session_state.is_message_visible = False
                    st.session_state.prompt_secret_key = False
                    st.rerun() 
            else:
                if st.button("Gizli Mesajı Göster", use_container_width=True, key="show_secret_btn"):
                    if st.session_state.secret_key_hash:
                        log("Gizli mesaj şifresi isteniyor...")
                        st.session_state.prompt_secret_key = True 
                        st.rerun()
                    else:
                        log("Gizli mesaj (şifresiz) gösteriliyor.")
                        st.session_state.watermarked_image = add_text_watermark(
                            st.session_state.decrypted_image, 
                            st.session_state.hidden_message
                        )
                        st.session_state.is_message_visible = True
                        st.rerun()

        # Gizli anahtar sorma arayüzü (Form kullanılmadan)
        if st.session_state.prompt_secret_key:
            st.warning("Filigranı görmek için gizli mesaj şifresini girin:")
            
            entered_key = st.text_input("Gizli Mesaj Şifresi", type="password", key="modal_pass_new")
            
            if st.button("Onayla ve Göster", key="secret_key_submit_new", use_container_width=True):
                if not entered_key:
                    st.error("Lütfen şifreyi giriniz.")
                else:
                    entered_hash = hashlib.sha256(entered_key.encode('utf-8')).hexdigest()
                    if entered_hash == st.session_state.secret_key_hash:
                        log("Gizli mesaj şifresi doğru. Filigran gösteriliyor.")
                        
                        st.session_state.watermarked_image = add_text_watermark(
                            st.session_state.decrypted_image, 
                            st.session_state.hidden_message
                        )
                        st.session_state.is_message_visible = True
                        st.session_state.prompt_secret_key = False
                        st.rerun()
                    else:
                        log("Hata: Gizli mesaj şifresi yanlış.")
                        st.error("Gizli mesaj şifresi yanlış.")
        
        if st.session_state.is_message_visible:
            st.success(f"**GİZLİ MESAJ (Meta Veri):**\n\n{st.session_state.hidden_message}")

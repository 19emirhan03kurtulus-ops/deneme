import streamlit as st
from PIL import Image, ImageDraw, ImageFont 
import hashlib, datetime, random, os, json, io
import zipfile 

# ----------------------------- Ayarlar ve Başlık -----------------------------
# Sayfa yapılandırması: Modern UI'ı taklit etmek için geniş düzen ve koyu tema (varsayılan)
st.set_page_config(
    page_title="Zamanlı Görsel Şifreleme - Modern UI",
    page_icon="🖼️",
    layout="wide"
)

# ----------------------------- Session State (Oturum Durumu) -----------------------------
def init_state():
    """Tüm oturum durumlarını başlatır ve varsayılanları atar."""
    # Varsayılan başlangıç değeri: Şu andan 5 dakika sonrası 
    default_open_time = datetime.datetime.now() + datetime.timedelta(minutes=5)
    
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
        'is_encrypt_mode': True, # Varsayılan olarak Şifrele sekmesi açık
        'encryption_start_time': default_open_time # datetime_input için kararlı başlangıç değeri
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
        # YYYY-MM-DD HH:MM formatı korunuyor
        return t.strftime("%Y-%m-%d %H:%M")
    return "" 

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
    """Şifre çözülmüş görselin üzerine SADECE gizli mesajı ekler (filigran)."""
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
        font_path = "arial.ttf" 
        font = ImageFont.truetype(font_path, 30)
    except IOError:
        try:
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
        # Eski PIL versiyonları veya font hatası için varsayılan değerler
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

def create_zip_archive(enc_bytes, meta_bytes, enc_filename, meta_filename):
    """Şifreli resmi ve meta veriyi içeren bir ZIP arşivi oluşturur."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(enc_filename, enc_bytes)
        zf.writestr(meta_filename, meta_bytes)
    return zip_buffer.getvalue()

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

def encrypt_image_file(image_bytes, password, open_time_dt, secret_text, secret_key, allow_no_password, progress_bar):
    """Şifreleme işlemini yapar."""
    
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
    open_time_str = normalize_time(open_time_dt)
    
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
            
    enc_img_byte_arr = io.BytesIO()
    enc_img.save(enc_img_byte_arr, format='PNG')
    enc_img_bytes = enc_img_byte_arr.getvalue()

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

# ----------------------------- ARAYÜZ Fonksiyonları -----------------------------

def handle_mode_change(mode):
    """Şifrele/Çöz modunu değiştirir ve gerekli durumları sıfırlar."""
    if mode == 'encrypt':
        st.session_state.is_encrypt_mode = True
        log("Mod: Şifrele seçildi.")
    else:
        st.session_state.is_encrypt_mode = False
        log("Mod: Çöz seçildi.")
    
    # Çözme sonuçlarını temizle
    st.session_state.decrypted_image = None
    st.session_state.watermarked_image = None
    st.session_state.is_message_visible = False
    st.session_state.prompt_secret_key = False
    st.rerun()


# --- Sidebar (Kenar Çubuğu) ---
with st.sidebar:
    st.subheader("Zamanlı Şifreleme")
    st.selectbox("Tema Seçimi:", ["Dark", "Light"], index=0, key="theme_select")
    st.caption("Modern arayüz")

    # Örnek Resim Oluşturma Butonu
    if st.button("Örnek Resim Oluştur", key="sidebar_sample_btn", use_container_width=True):
        img_bytes = create_sample_image_bytes()
        # Örnek resmi şifreleme sekmesinde göstermek için session state'e kaydet
        st.session_state.generated_enc_bytes = img_bytes 
        st.session_state.generated_meta_bytes = None 
        st.session_state.is_encrypt_mode = True # Şifreleme sekmesine geç
        log("Test için örnek resim oluşturuldu. Şifreleme sekmesinden indirebilirsiniz.")
        st.rerun()

    # Klasör Aç butonu (Sadece görsel amaçlı)
    st.button("Klasörü Aç", key="sidebar_open_btn", use_container_width=True, disabled=True, help="Bu Streamlit uygulamasında sadece görsel bir düğmedir.")

    st.markdown("---")
    st.markdown("""
    **Kullanım:**
    1) Görsel seç / Örnek Oluştur
    2) Şifre (veya şifresiz zaman) ayarla
    3) Zaman gir
    4) Şifrele / Çöz butonuna bas
    """)

# ----------------------------- Ana Alan (Main Content) -----------------------------

st.title("🎴 Zaman Ayarlı Görsel Şifreleme")
st.button("Yardım", key="help_button", type="secondary", disabled=True) # İstenen arayüzdeki Yardım butonu

# Ana sütunlar: Ayarlar (%40) ve Önizleme (%60)
col_settings, col_preview = st.columns([0.4, 0.6])

# --- AYARLAR SÜTUNU (COL_SETTINGS) ---
with col_settings:
    st.subheader("Dosya & Ayarlar")
    
    # Form: Şifreleme ve Şifre Çözme ayarları (Ortak arayüz elemanları)
    with st.form("main_form"):
        
        # 1. Dosya Seçimi
        if st.session_state.is_encrypt_mode:
            uploaded_file = st.file_uploader(
                "Resim seçin veya örnek oluşturun", 
                type=["png", "jpg", "jpeg", "bmp"],
                key="enc_file_uploader" 
            )
            # Eğer örnek resim oluşturulmuşsa, dosya yükleyicinin üstünde bir bilgi göster
            if st.session_state.generated_enc_bytes and not uploaded_file:
                 st.info("Kenar çubuğundan bir örnek resim yüklendi. 'Şifrele' butonuna basabilirsiniz.")
            
        else: # Çözme Modu
            enc_file = st.file_uploader("Şifreli resmi (.png) seçin", type="png", key="dec_enc_file_uploader")
            meta_file = st.file_uploader("Meta dosyasını (.meta) seçin", type="meta", key="dec_meta_file_uploader")


        st.markdown("---")
        
        # 2. Şifre ve Gizli Mesaj Ayarları
        pass_label = "Görsel Şifresi (Çözme için):"
        enc_pass = st.text_input(pass_label, type="password", key="enc_pass_input_main")
        enc_no_pass = st.checkbox("Şifresiz açılmaya izin ver", key="enc_no_pass_checkbox_main", help="Sadece zaman kilidi ile açılır.")
        
        enc_secret_text = st.text_area("Gizli Mesaj (Meta veriye saklanır):", placeholder="Gizli notunuz...", key="enc_secret_text_area_main")
        enc_secret_key = st.text_input("Gizli Mesaj Şifresi (Filigranı görmek için):", type="password", placeholder="Filigranı açacak şifre", key="enc_secret_key_input_main")
        
        # 3. Zaman Ayarı (SADECE ŞİFRELEME MODUNDA GÖSTER)
        if st.session_state.is_encrypt_mode:
            st.markdown("---")
            st.markdown("**Açılma Zamanı Ayarları**")
            
            # KULLANILABİLECEK MİNİMUM ZAMANI HESAPLA (Şu anki zamandan 1 dakika sonrası)
            dynamic_min_value = datetime.datetime.now() + datetime.timedelta(minutes=1)

            # GÜVENLİK KONTROLÜ (AttriibuteError'u engeller)
            if st.session_state.encryption_start_time < dynamic_min_value:
                st.session_state.encryption_start_time = dynamic_min_value
                log("Güvenlik: Oturum zamanı minimum değerden küçüktü, otomatik olarak güncellendi.")

            # AÇILMA ZAMANI (Datetime Input)
            enc_time = st.datetime_input(
                "Açılma Zamanı (YYYY-AA-GG SS:DD):", 
                value=st.session_state.encryption_start_time, # Güvenlik kontrolünden geçmiş değer kullanılır
                min_value=dynamic_min_value, 
                key="encryption_time_input_fixed", 
                help=f"Resmin şifresi sadece bu tarih ve saatten SONRA çözülebilir. Minimum ayar: {normalize_time(dynamic_min_value)}"
            )
            # Kullanıcı değeri değiştirdiğinde, session state'i de güncelleyelim.
            if enc_time is not None:
                 st.session_state.encryption_start_time = enc_time
        else:
             # Şifre çözme modunda zaman girişini gizle ama yer tutucu tanımla
             enc_time = None
        
        st.markdown("---")
        
        # 4. Şifrele/Çöz Butonları (Aynı form içinde olmalılar)
        col_btn_enc, col_btn_dec, _ = st.columns([1, 1, 3])
        
        if col_btn_enc.form_submit_button(
            "🔒 Şifrele", 
            use_container_width=True, 
            key="enc_submit_button_main",
            type="primary"
        ):
            # Şifrele butonu tetiklendiğinde modu Şifrele yap
            st.session_state.is_encrypt_mode = True
            log("Şifreleme formu gönderildi.")
        
        if col_btn_dec.form_submit_button(
            "🔓 Çöz", 
            use_container_width=True, 
            key="dec_submit_button_main"
        ):
            # Çöz butonu tetiklendiğinde modu Çöz yap
            st.session_state.is_encrypt_mode = False
            log("Şifre Çözme formu gönderildi.")
        
# ----------------------------- ANA İŞLEM MANTIĞI -----------------------------

# Şifrele Butonu İşlemleri
if st.session_state.is_encrypt_mode and st.session_state.enc_submit_button_main:
    
    file_for_enc = uploaded_file or (
        io.BytesIO(st.session_state.generated_enc_bytes) if st.session_state.generated_enc_bytes else None
    )

    if file_for_enc is None:
        st.error("Lütfen önce bir resim dosyası yükleyin veya örnek oluşturun.")
    elif enc_time is None:
         st.error("Lütfen geçerli bir açılma zamanı seçin.")
    else:
        log("Şifreleme başlatıldı...")
        col_settings.progress(0, text="Başlatılıyor...")
        
        image_bytes = file_for_enc.getvalue()
        pw_to_use = "" if enc_no_pass else enc_pass
        
        enc_bytes, meta_bytes = encrypt_image_file(
            image_bytes, pw_to_use, enc_time, 
            enc_secret_text, enc_secret_key, enc_no_pass,
            col_settings.progress(0, text="Şifreleme ilerlemesi...")
        )
        
        if enc_bytes and meta_bytes:
            log("Şifreleme tamamlandı. Dosyalar indirilmeye hazır.")
            col_settings.success("Şifreleme Başarılı! Oluşturulan ZIP dosyasını indirin.")
            
            base_name = os.path.splitext(uploaded_file.name if uploaded_file else "sample")[0]
            enc_filename = f"{base_name}_encrypted.png"
            meta_filename = f"{base_name}_encrypted.meta"
            zip_filename = f"{base_name}_encrypted_files.zip"

            zip_bytes = create_zip_archive(enc_bytes, meta_bytes, enc_filename, meta_filename)

            col_settings.download_button(
                label="ZIP İndir (Şifreli Resim ve Meta)",
                data=zip_bytes,
                file_name=zip_filename,
                mime="application/zip",
                key="download_zip_button",
                use_container_width=True
            )
            
        else:
            log("Şifreleme başarısız.")
            col_settings.error("Şifreleme sırasında bir hata oluştu. Logları kontrol edin.")

# Şifre Çözme Butonu İşlemleri
elif not st.session_state.is_encrypt_mode and st.session_state.dec_submit_button_main:
    
    # Önceki sonuçları temizle
    for k in ['decrypted_image', 'watermarked_image', 'is_message_visible', 'prompt_secret_key']:
        st.session_state[k] = None
        
    log("--- Yeni Çözme İşlemi Başlatıldı ---")

    if not enc_file or not meta_file:
        col_settings.error("Lütfen hem şifreli .png hem de .meta dosyasını yükleyin.")
    else:
        try:
            meta_content = meta_file.getvalue().decode('utf-8')
            meta = json.loads(meta_content)
            
            open_time_str = meta.get("open_time")
            allow_no = bool(meta.get("allow_no_password", False))
            stored_tag = meta.get("verify_tag")
            image_hash = meta.get("image_content_hash", "")
            
            st.session_state.hidden_message = meta.get("hidden_message", "")
            st.session_state.secret_key_hash = meta.get("secret_key_hash", "")

            now = datetime.datetime.now()
            ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M")
            
            if now < ot_dt:
                log("Hata: Henüz zamanı gelmedi.")
                col_settings.warning(f"Bu dosyanın açılmasına daha var. Açılma Zamanı: {open_time_str}")
            else:
                pw_to_use = "" 
                
                if not allow_no and not enc_pass: # enc_pass, main form'daki text_input'un değeri
                    log("Hata: Şifre gerekli ancak girilmedi.")
                    col_settings.error("Bu dosya için görsel şifresi gereklidir, ancak şifre girilmedi.")
                    return
                elif not allow_no:
                     pw_to_use = enc_pass

                log("Zaman ve şifre kontrolleri tamam. Çözme işlemi başlıyor...")
                
                enc_image_bytes = enc_file.getvalue()
                
                dec_img, key_hex = decrypt_image_in_memory(
                    enc_image_bytes, pw_to_use, open_time_str, image_hash, 
                    col_settings.progress(0, text="Şifre çözme ilerlemesi...")
                )
                
                if dec_img is None:
                    pass 
                else:
                    calc_tag = hashlib.sha256(key_hex.encode("utf-8") + dec_img.tobytes()).hexdigest()
                    
                    if calc_tag != stored_tag:
                        log("Doğrulama başarısız: Yanlış şifre veya bozuk dosya.")
                        col_settings.error("Çözme Hatası: Yanlış şifre girildi veya dosyalar bozulmuş.")
                        st.session_state.decrypted_image = None
                    else:
                        log("Doğrulama başarılı! Resim çözüldü.")
                        col_settings.success("Görselin şifresi başarıyla çözüldü!")
                        st.session_state.decrypted_image = dec_img 
                        
        except json.JSONDecodeError:
             col_settings.error("Meta dosyası geçerli bir JSON formatında değil.")
        except Exception as e:
            log(f"Çözme hatası: {e}")
            col_settings.error(f"Çözme sırasında beklenmedik bir hata oluştu: {e}")


# --- ÖNİZLEME SÜTUNU (COL_PREVIEW) ---
with col_preview:
    st.subheader("Önizleme")
    
    image_to_show = None
    caption = "(Resim seçilmedi)"
    
    if st.session_state.is_message_visible and st.session_state.watermarked_image is not None:
        image_to_show = st.session_state.watermarked_image
        caption = "Çözülmüş Görüntü (Filigranlı)"
    elif st.session_state.decrypted_image is not None:
        image_to_show = st.session_state.decrypted_image
        caption = "Çözülmüş Görüntü (Orijinal)"
    elif st.session_state.is_encrypt_mode and st.session_state.generated_enc_bytes:
        # Şifreleme modunda ve örnek resim varsa göster
        try:
             # Örnek veya yüklenen dosyanın orijinalini göstermek için
            if uploaded_file:
                 image_to_show = Image.open(uploaded_file)
                 caption = "Yüklenen Orijinal Resim"
            else:
                 image_to_show = Image.open(io.BytesIO(st.session_state.generated_enc_bytes))
                 caption = "Oluşturulan Örnek Resim"
        except:
             pass # Eğer dosya bozuksa gösterme

    
    # Önizleme alanı (Geniş bir alana yayılır)
    preview_placeholder = st.empty()

    if image_to_show:
        preview_placeholder.image(image_to_show, caption=caption, use_container_width=True)
        # İndirme butonu, sadece resim çözülmüşse veya şifrelenmişse/örnekse gösterilir
        if st.session_state.decrypted_image or st.session_state.enc_submit_button_main:
             img_byte_arr = io.BytesIO()
             image_to_show.save(img_byte_arr, format='PNG')
             col_settings.download_button(
                 label="Görüntülenen Resmi İndir",
                 data=img_byte_arr.getvalue(),
                 file_name="decrypted_or_original_image.png",
                 mime="image/png",
                 key="download_displayed_image_button_preview"
             )

    else:
        # İstenen tasarımda Placeholder metni
        preview_placeholder.markdown(f"<div style='text-align: center; color: #888; padding: 150px 0;'>{caption}</div>", unsafe_allow_html=True)


    st.markdown("---") # İşlem günlüğünün üstündeki çizgi

    # --- İşlem Günlüğü ---
    st.subheader("İşlem Günlüğü")
    st.text_area("Loglar", value=st.session_state.log, height=150, disabled=True, key="log_area")
    
    # Gizli Mesaj Göster/Gizle Butonu (Sağ altta)
    if st.session_state.decrypted_image is not None and st.session_state.hidden_message:
        
        # Gizli anahtar sorma arayüzü
        if st.session_state.prompt_secret_key:
            st.warning("Filigranı görmek için gizli mesaj şifresini girin:")
            
            entered_key = st.text_input("Gizli Mesaj Şifresi", type="password", key="modal_pass_new_preview")
            
            if st.button("Onayla ve Göster", key="secret_key_submit_new_preview"):
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

        # Gizli Mesajı Göster/Gizle butonu
        if st.session_state.is_message_visible:
            if st.button("Gizli Mesajı Gizle", key="hide_secret_btn_preview", use_container_width=True):
                log("Gizli mesaj gizlendi.")
                st.session_state.is_message_visible = False
                st.session_state.prompt_secret_key = False
                st.rerun() 
        else:
            if st.button("Gizli Mesajı Göster", key="show_secret_btn_preview", use_container_width=True):
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
    else:
        st.button("Gizli Mesajı Göster/Gizle", key="dummy_secret_btn", use_container_width=True, disabled=True)

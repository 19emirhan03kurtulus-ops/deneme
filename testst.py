import streamlit as st
import datetime
import pytz
import json
import os
import hashlib
import io

# Gerekli Kriptografi ve Görüntü İşleme Kütüphaneleri
# Eğer "ModuleNotFoundError" hatası alırsanız, terminalde: pip install cryptography Pillow
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from PIL import Image, ImageDraw, ImageFont
except ImportError:
    st.error("Kütüphane Hatası: 'cryptography' veya 'Pillow' kurulu değil. Lütfen terminalde 'pip install cryptography Pillow' komutunu çalıştırın.")
    st.stop()


# --- SABİTLER ve İLK AYARLAR ---
TURKISH_TZ = pytz.timezone('Europe/Istanbul')
LOG_FILE = "app_log.txt" 

# --- YARDIMCI FONKSİYONLAR ---

def log(message):
    """Zaman damgası ile log dosyasına mesaj yazar."""
    now_tr = datetime.datetime.now(TURKISH_TZ).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{now_tr}] {message}\n")
    except Exception:
        # st.info(f"LOG: {message}") # Uygulama içinde çok fazla bilgi mesajı göstermemek için kapatıldı
        pass

def normalize_time(dt_object):
    """datetime objesini 'YYYY-MM-DD HH:MM' formatına dönüştürür ve UTC'ye çevirir."""
    if dt_object.tzinfo is not None and dt_object.tzinfo.utcoffset(dt_object) is not None:
        dt_object = dt_object.astimezone(pytz.utc)
    return dt_object.strftime("%Y-%m-%d %H:%M")

def parse_normalized_time(time_str):
    """Normalize edilmiş UTC zamanını TZ-aware TR zamanına dönüştürür."""
    dt_naive = datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M")
    return dt_naive.replace(tzinfo=pytz.utc).astimezone(TURKISH_TZ)

def init_session_state():
    """Streamlit session state'i başlatır."""
    # ... (Session state başlatma kodları aynı bırakıldı)
    if 'current_view' not in st.session_state: st.session_state.current_view = 'cipher'
    
    if 'generated_enc_bytes' not in st.session_state: st.session_state.generated_enc_bytes = None
    if 'generated_meta_bytes' not in st.session_state: st.session_state.generated_meta_bytes = None
    if 'is_png_downloaded' not in st.session_state: st.session_state.is_png_downloaded = False
    if 'is_meta_downloaded' not in st.session_state: st.session_state.is_meta_downloaded = False
    
    if 'decrypted_image' not in st.session_state: st.session_state.decrypted_image = None
    if 'watermarked_image' not in st.session_state: st.session_state.watermarked_image = None
    if 'is_message_visible' not in st.session_state: st.session_state.is_message_visible = False
    if 'hidden_message' not in st.session_state: st.session_state.hidden_message = ""
    if 'secret_key_hash' not in st.session_state: st.session_state.secret_key_hash = ""
    if 'decrypt_pass' not in st.session_state: st.session_state.decrypt_pass = ""
    if 'modal_pass' not in st.session_state: st.session_state.modal_pass = ""
    if 'prompt_secret_key' not in st.session_state: st.session_state.prompt_secret_key = False
    if 'reset_counter' not in st.session_state: st.session_state.reset_counter = 0 
    
    if 'exam_enc_bytes' not in st.session_state: st.session_state.exam_enc_bytes = None
    if 'exam_meta_bytes' not in st.session_state: st.session_state.exam_meta_bytes = None
    if 'exam_is_enc_downloaded' not in st.session_state: st.session_state.exam_is_enc_downloaded = False
    if 'exam_is_meta_downloaded' not in st.session_state: st.session_state.exam_is_meta_downloaded = False
    if 'exam_decrypted_bytes' not in st.session_state: st.session_state.exam_decrypted_bytes = None


def reset_all_inputs():
    """Tüm girdileri ve sonuçları temizler."""
    log("Tüm girdi ve sonuçlar temizlendi (reset_all_inputs).")
    
    # ... (Reset kodları aynı bırakıldı)
    st.session_state.generated_enc_bytes = None
    st.session_state.generated_meta_bytes = None
    st.session_state.decrypted_image = None
    st.session_state.watermarked_image = None
    st.session_state.is_message_visible = False
    st.session_state.hidden_message = ""
    st.session_state.secret_key_hash = ""
    st.session_state.decrypt_pass = ""
    st.session_state.modal_pass = ""
    st.session_state.prompt_secret_key = False
    st.session_state.is_png_downloaded = False
    st.session_state.is_meta_downloaded = False
    
    st.session_state.exam_enc_bytes = None
    st.session_state.exam_meta_bytes = None
    st.session_state.exam_is_enc_downloaded = False
    st.session_state.exam_is_meta_downloaded = False
    st.session_state.exam_decrypted_bytes = None
    
    st.session_state.reset_counter += 1

# --- KRİPTOGRAFİ VE İŞLEM FONKSİYONLARI ---

def derive_key(input_data, salt_bytes):
    """PBKDF2HMAC kullanarak kriptografik anahtar türetir."""
    # ... (derive_key kodları aynı bırakıldı)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # AES-256 için 32 byte
        salt=salt_bytes,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(input_data.encode('utf-8'))

def encrypt_image_file(image_bytes, password, open_time_dt, secret_text, secret_key, allow_no_pass, progress_bar):
    """Görüntüyü AES-GCM ile şifreler ve meta veriyi oluşturur."""
    # ... (encrypt_image_file kodları aynı bırakıldı)
    try:
        progress_bar.progress(10, text="Anahtar türetiliyor...")
        
        pw_to_use = password if password else "DEFAULT_PASS" 
        time_str = normalize_time(open_time_dt)
        salt = os.urandom(16) 
        key = derive_key(pw_to_use, salt)
        
        aesgcm = AESGCM(key)
        nonce = os.urandom(12) 
        aad = time_str.encode('utf-8') 
        
        progress_bar.progress(50, text="Görüntü şifreleniyor...")
        
        encrypted_data_with_tag = aesgcm.encrypt(nonce, image_bytes, aad) 
        
        progress_bar.progress(80, text="Meta veri hazırlanıyor...")
        
        secret_key_hash = hashlib.sha256(secret_key.encode('utf-8')).hexdigest() if secret_key else ""
        
        meta_data = {
            "type": "IMAGE_LOCK",
            "version": "1.1",
            "open_time": time_str,
            "nonce_hex": nonce.hex(), 
            "allow_no_password": allow_no_pass,
            "salt_hex": salt.hex(),
            "hidden_message": secret_text,
            "secret_key_hash": secret_key_hash,
            "image_content_hash": hashlib.sha256(image_bytes).hexdigest() 
        }
        
        meta_bytes = json.dumps(meta_data, indent=4).encode('utf-8')
        
        progress_bar.progress(100, text="Şifreleme Tamamlandı!")
        return encrypted_data_with_tag, meta_bytes

    except Exception as e:
        log(f"Şifreleme Hatası: {e}")
        progress_bar.progress(100, text="Hata oluştu!")
        st.error(f"Şifreleme başarısız: {e}")
        return None, None 

def decrypt_image_in_memory(encrypted_bytes, password, meta, progress_bar):
    """Şifrelenmiş baytları çözer ve PIL Image objesi olarak döndürür."""
    # ... (decrypt_image_in_memory kodları aynı bırakıldı)
    try:
        progress_bar.progress(10, text="Meta veriler okunuyor...")
        
        open_time_str = meta.get("open_time")
        nonce_bytes = bytes.fromhex(meta.get("nonce_hex"))
        salt_bytes = bytes.fromhex(meta.get("salt_hex"))
        
        pw_to_use = password if password else "DEFAULT_PASS"
        key = derive_key(pw_to_use, salt_bytes)
        
        progress_bar.progress(50, text="Görüntü çözülüyor...")
        
        aesgcm = AESGCM(key)
        aad = open_time_str.encode('utf-8') 

        decrypted_bytes = aesgcm.decrypt(nonce_bytes, encrypted_bytes, aad)
        
        try:
            img_stream = io.BytesIO(decrypted_bytes)
            dec_img = Image.open(img_stream)
        except Exception as img_e:
            log(f"Çözülen baytlar geçerli resim değil: {img_e}")
            st.error("Çözme başarılı oldu, ancak sonuçlar geçerli bir resim dosyası formatında değil.")
            return None
        
        progress_bar.progress(100, text="Çözme Tamamlandı!")
        return dec_img

    except Exception as e:
        log(f"Çözme Sırasında Kripto Hatası: {e}")
        st.error("Kripto hatası oluştu. **Yanlış şifre** veya bozuk dosya olabilir.")
        progress_bar.progress(100, text="Hata!")
        return None

def add_text_watermark(image_obj, text):
    """Görüntünün üzerine gizli mesajı (filigran) ekler."""
    # ... (add_text_watermark kodları aynı bırakıldı)
    img = image_obj.copy()
    draw = ImageDraw.Draw(img)
    width, height = img.size
    
    try:
        font = ImageFont.load_default() 
    except IOError:
        font = ImageFont.load_default() 
        
    text_color = (255, 0, 0, 100) 
    
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width, text_height = bbox[2] - bbox[0], bbox[3] - bbox[1]
    
    x = (width - text_width) / 2
    y = (height - text_height) / 2
    
    draw.text((x, y), text, fill=text_color, font=font)
    
    return img

def set_png_downloaded():
    st.session_state.is_png_downloaded = True
    
def set_meta_downloaded():
    st.session_state.is_meta_downloaded = True

# ----------------------------- SINAV SİSTEMİ YARDIMCI FONKSİYONLARI -----------------------------
# Düzeltme: Fonksiyonlar bu blokta tanımlanarak 'name is not defined' hatası giderildi.

def encrypt_exam_file(file_bytes, access_code, start_time_dt, end_time_dt, progress_bar):
    """Sınav dosyasını şifreler ve meta veriyi hazırlar (AES-GCM)."""
    try:
        progress_bar.progress(10, text="Anahtar türetiliyor...")
        
        # 1. Kriptografik anahtar türetme
        # Hem başlangıç hem de bitiş zamanını AAD'ye (Additional Authenticated Data) dahil et,
        # böylece meta veri değişse bile dosya çözülebilir, ancak AAD'nin bütünlüğü sağlanır.
        time_str = normalize_time(start_time_dt) + normalize_time(end_time_dt)
        salt = os.urandom(16) 
        key_bytes = derive_key(access_code, salt)
        
        # 2. Şifreleme (AES-GCM)
        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(12) 
        aad = time_str.encode('utf-8') 
        
        progress_bar.progress(30, text="Dosya şifreleniyor...")
        
        encrypted_bytes = aesgcm.encrypt(nonce, file_bytes, aad)
        
        progress_bar.progress(70, text="Meta veri hazırlanıyor...")
        
        # 3. Meta Veri Oluşturma
        access_code_hash = hashlib.sha256(access_code.encode('utf-8')).hexdigest()
        
        meta_data = {
            "type": "EXAM_LOCK",
            "version": "1.1",
            "start_time": normalize_time(start_time_dt),
            "end_time": normalize_time(end_time_dt),
            "access_code_hash": access_code_hash,
            "nonce_hex": nonce.hex(),
            "salt_hex": salt.hex(),
            "file_size": len(file_bytes),
        }
        
        meta_bytes = json.dumps(meta_data, indent=4).encode('utf-8')
        progress_bar.progress(100, text="Sınav Hazır!")
        
        return encrypted_bytes, meta_bytes

    except Exception as e:
        log(f"Sınav Şifreleme Hatası: {e}")
        progress_bar.progress(100, text="Hata oluştu!")
        return None, None 

def decrypt_exam_file(encrypted_bytes, access_code, meta, progress_bar):
    """Şifrelenmiş sınav dosyasını çözer ve bütünlük kontrolü yapar (AES-GCM)."""
    try:
        progress_bar.progress(10, text="Meta veriler okunuyor...")
        
        start_time_str = meta.get("start_time")
        end_time_str = meta.get("end_time")
        salt_bytes = bytes.fromhex(meta.get("salt_hex"))
        nonce_bytes = bytes.fromhex(meta.get("nonce_hex"))
        
        # AAD'yi şifreleme ile aynı şekilde yeniden oluştur
        time_str = start_time_str + end_time_str
        
        progress_bar.progress(30, text="Anahtar türetiliyor...")
        
        key_bytes = derive_key(access_code, salt_bytes)
        
        progress_bar.progress(60, text="Dosya çözülüyor ve bütünlük kontrol ediliyor...")

        aesgcm = AESGCM(key_bytes)
        aad = time_str.encode('utf-8')
        
        decrypted_bytes = aesgcm.decrypt(nonce_bytes, encrypted_bytes, aad)
        
        progress_bar.progress(100, text="Çözme Başarılı!")
        return decrypted_bytes

    except Exception as e:
        if "Authentication tag mismatch" in str(e):
            st.error("Çözme Hatası: Erişim kodu veya dosya bozuk.")
            log("Sınav Çözme Hatası: Bütünlük etiketi uyuşmadı (Yanlış kod/dosya).")
        else:
            st.error(f"Beklenmedik bir çözme hatası oluştu: {e}")
            log(f"Sınav Çözme Hatası: {e}")
            
        progress_bar.progress(100, text="Hata!")
        return None

# ------------------------------------------------------------------------------------------------

# --- ANA UYGULAMA YAPISI ---

def render_cipher_module():
    """Görsel şifreleme ve şifre çözme modülünü render eder."""
    st.markdown("## 🖼️ Zaman Ayarlı Görsel Şifreleme")
    st.markdown("Bir görseli belirlediğiniz zamana kadar kilitler.")
    st.markdown("---")

    tab_encrypt, tab_decrypt = st.tabs(["🔒 Şifrele", "🔓 Çöz"])

    # --- ŞİFRELEME SEKMESİ ---
    with tab_encrypt:
        st.subheader("1. Şifreleme Ayarları")

        with st.form("image_encrypt_form", clear_on_submit=False):
            
            uploaded_file = st.file_uploader(
                "Şifrelenecek resmi (.png, .jpg) seçin", 
                type=["png", "jpg", "jpeg"], 
                key="enc_file_upload"
            )
            
            st.markdown("##### ⏳ Açılma Zamanı (Türkiye Saati)")
            col_date, col_time = st.columns(2)

            with col_date:
                enc_date = st.date_input(
                    "Tarih", 
                    datetime.datetime.now(TURKISH_TZ).date(), 
                    key="enc_date"
                )
            with col_time:
                default_time = (datetime.datetime.now(TURKISH_TZ).replace(minute=0, second=0, microsecond=0) + datetime.timedelta(hours=1)).strftime("%H:%M")
                enc_time = st.text_input("Saat (SS:DD)", default_time, key="enc_time", help="Örnek: 14:30")
            
            time_format_valid = True
            enc_time_dt = None
            try:
                dt_naive = datetime.datetime.strptime(f"{enc_date} {enc_time}", "%Y-%m-%d %H:%M")
                enc_time_dt = dt_naive.replace(tzinfo=TURKISH_TZ)
            except ValueError:
                time_format_valid = False

            st.markdown("---")
            st.markdown("##### 🔑 Şifre ve Gizli Mesaj Ayarları")
            
            enc_pass = st.text_input("Görsel Şifresi (Gerekliyse)", type="password", key="enc_pass", help="Şifreleme şifresi. Boş bırakılırsa sadece zamana kilitlenir.")
            enc_no_pass = st.checkbox("Şifre kullanma (Sadece zaman kilidi)", key="enc_no_pass", value=(not enc_pass))
            
            if enc_no_pass:
                enc_pass = "" 
            
            st.markdown("---")
            
            enc_secret_text = st.text_area("Gizli Filigran Mesajı (Şifre çözüldükten sonra görülür)", key="enc_secret_text", help="Bu metin çözülmüş görselin üzerine filigran olarak eklenir.")
            enc_secret_key = st.text_input("Filigran Görüntüleme Şifresi (Filigranı görmek için ekstra şifre)", type="password", key="enc_secret_key", help="Bu şifre, gizli mesajı çözülmüş görselin üzerinde görmek için sorulur. Boş bırakılabilir.")

            submitted = st.form_submit_button("🔒 Şifrele ve Dosyaları Oluştur", type="primary", use_container_width=True)

            if submitted:
                st.session_state.is_png_downloaded = False
                st.session_state.is_meta_downloaded = False
                
                if not time_format_valid:
                    st.warning("Lütfen zaman formatını düzeltin.")
                    st.stop()
                    
                now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                
                if enc_time_dt <= now_tr:
                    st.error(f"Açılma zamanı şu anki zamandan ({now_tr.strftime('%H:%M')}) ileri bir tarih/saat olmalıdır.")
                    log("Hata: Geçmiş zaman seçimi.")
                    st.stop()
                    
                if uploaded_file is None:
                    st.error("Lütfen önce bir resim dosyası yükleyin.")
                else:
                    log("Şifreleme başlatıldı...")
                    progress_bar = st.progress(0, text="Başlatılıyor...")
                    image_bytes = uploaded_file.getvalue()
                    
                    enc_bytes, meta_bytes = encrypt_image_file(
                        image_bytes, enc_pass, enc_time_dt, 
                        enc_secret_text, enc_secret_key, enc_no_pass,
                        progress_bar
                    )
                    
                    if enc_bytes and meta_bytes:
                        log("Şifreleme tamamlandı. Dosyalar indirilmeye hazır.")
                        st.success("Şifreleme Başarılı! Lütfen her iki dosyayı da indirin.")
                        st.session_state.generated_enc_bytes = enc_bytes
                        st.session_state.generated_meta_bytes = meta_bytes
                        
                    else:
                        log("Şifreleme başarısız.")
                        st.session_state.generated_enc_bytes = None
                        st.session_state.generated_meta_bytes = None

            
            # --- İndirme Bölümü ---
            if st.session_state.generated_enc_bytes and st.session_state.generated_meta_bytes:
                
                base_name = os.path.splitext(uploaded_file.name)[0] if uploaded_file else "encrypted_image"
                
                if st.session_state.is_png_downloaded and st.session_state.is_meta_downloaded:
                    st.markdown("---")
                    st.success("✅ Tebrikler! Hem Şifreli Resim hem de Meta Veri başarıyla indirildi.")
                else:
                    st.markdown("---")
                    st.subheader("3. İndirme Bağlantıları")
                    st.warning("⚠️ Lütfen hem .png hem de .meta dosyasını indirin.")

                    col_png, col_meta = st.columns(2)
                    
                    # PNG İndirme Butonu
                    with col_png:
                        st.download_button(
                            label="🖼️ Şifreli Resmi İndir (.png)",
                            data=st.session_state.generated_enc_bytes,
                            file_name=f"{base_name}_encrypted.png",
                            mime="image/png",
                            on_click=set_png_downloaded, 
                            disabled=st.session_state.is_png_downloaded, 
                            use_container_width=True
                        )
                    
                    # Meta İndirme Butonu
                    with col_meta:
                        st.download_button(
                            label="🔑 Meta Veriyi İndir (.meta)",
                            data=st.session_state.generated_meta_bytes,
                            file_name=f"{base_name}_encrypted.meta",
                            mime="application/json",
                            on_click=set_meta_downloaded, 
                            disabled=st.session_state.is_meta_downloaded, 
                            use_container_width=True
                        )
                        

    # --- ŞİFRE ÇÖZME SEKMESİ ---
    with tab_decrypt:
        st.subheader("Şifreli Bir Görseli Çöz")
        
        col1, col2 = st.columns([1, 1.5])
        
        with col1:
            st.markdown("##### 1. Dosyaları Yükle")
            enc_file = st.file_uploader("Şifreli resmi (.png) seçin", type=["png"], key=f"dec_enc_file_{st.session_state.reset_counter}")
            meta_file = st.file_uploader("Meta dosyasını (.meta) seçin", type=["meta", "json", "txt"], key=f"dec_meta_file_{st.session_state.reset_counter}")
            
            meta_data_available = False
            meta = {}
            ot_dt = None
            
            with st.container(border=True):
                st.markdown("##### Açılma Zamanı Durumu")
                if meta_file:
                    try:
                        meta = json.loads(meta_file.getvalue().decode('utf-8'))
                        
                        if meta.get("type") != "IMAGE_LOCK":
                            st.error("Yüklenen meta dosyası bir Görsel Kilidi dosyası değil.")
                            meta_file = None
                            
                        else:
                            meta_data_available = True
                            open_time_str = meta.get("open_time", "Bilinmiyor")
                            ot_dt = parse_normalized_time(open_time_str)
                            
                            now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                            
                            is_open = now_tr >= ot_dt
                            color = "green" if is_open else "red"

                            if not is_open:
                                time_left = ot_dt - now_tr
                                days = time_left.days
                                total_seconds = int(time_left.total_seconds())
                                hours = total_seconds // 3600
                                minutes = (total_seconds % 3600) // 60
                                
                                parts = []
                                if days > 0: parts.append(f"**{days} gün**")
                                if hours > 0: parts.append(f"**{hours} saat**")
                                if minutes > 0 or not parts: parts.append(f"**{minutes} dakika**")
                                time_left_str = "Kalan Süre: " + ", ".join(parts)
                            else:
                                time_left_str = "Açılma zamanı geldi/geçti."

                            st.markdown(
                                f"Açılma Zamanı (TR): **<span style='color:{color}; font-weight: bold;'>{ot_dt.strftime('%Y-%m-%d %H:%M')}</span>**", 
                                unsafe_allow_html=True
                            )
                            st.markdown(f"**Durum:** **<span style='color:{color};'>{'🔓 AÇILABİLİR' if is_open else '🔒 KİLİTLİ'}</span>**", unsafe_allow_html=True)
                            st.markdown(f"*{time_left_str}*")
                            
                    except Exception as e:
                        st.error(f"Meta dosya okuma/zaman hatası: {e}")
                else:
                    st.info("Lütfen bir meta dosyası yükleyin.")


            st.markdown("---")
            st.markdown("##### 2. Şifreyi Gir ve Çöz")
            dec_pass = st.text_input("Görsel Şifresi (gerekliyse)", type="password", key="decrypt_pass_input", value=st.session_state.decrypt_pass)
            
            st.session_state.decrypt_pass = dec_pass 

            col_dec_btn, col_res_btn = st.columns([2, 1])

            with col_dec_btn:
                if st.button("🔓 Çöz", type="primary", use_container_width=True): 
                    # Session state'i temizle
                    for k in ['decrypted_image', 'watermarked_image', 'is_message_visible', 'prompt_secret_key']:
                        if k in st.session_state:
                            st.session_state[k] = None
                    st.session_state.hidden_message = ""
                    st.session_state.secret_key_hash = ""
                    st.session_state.decrypt_pass = st.session_state.decrypt_pass_input 
                    
                    log("--- Yeni Çözme İşlemi Başlatıldı ---")
                    
                    if not enc_file or not meta_file:
                        st.error("Lütfen hem şifreli .png hem de .meta dosyasını yükleyin.")
                    elif not meta_data_available:
                        st.error("Yüklenen meta dosyası geçerli bir JSON formatında veya doğru tipte değil.")
                    else:
                        try:
                            allow_no = bool(meta.get("allow_no_password", False))
                            st.session_state.hidden_message = meta.get("hidden_message", "")
                            st.session_state.secret_key_hash = meta.get("secret_key_hash", "")
                            
                            if ot_dt is None:
                                st.error("Zaman bilgisi okunamadı. Meta dosyasını kontrol edin.")
                                
                            now_tr = datetime.datetime.now(TURKISH_TZ)
                            now_check = now_tr.replace(second=0, microsecond=0)
                            
                            if now_check < ot_dt:
                                log("Hata: Henüz zamanı gelmedi.")
                                st.warning(f"Bu dosyanın açılmasına daha var. Açılma Zamanı: **{ot_dt.strftime('%Y-%m-%d %H:%M')}**")
                            else:
                                current_dec_pass = st.session_state.decrypt_pass
                                pw_to_use = "" if allow_no else current_dec_pass
                                
                                if not allow_no and not current_dec_pass:
                                    log("Hata: Şifre gerekli.")
                                    st.error("Bu dosya için şifre gereklidir, ancak şifre girilmedi.")
                                else:
                                    log("Zaman ve şifre kontrolleri tamam. Çözme işlemi başlıyor...")
                                    progress_bar = st.progress(0, text="Başlatılıyor...")
                                    enc_image_bytes = enc_file.getvalue()
                                    
                                    dec_img = decrypt_image_in_memory(
                                        enc_image_bytes, pw_to_use, meta, progress_bar
                                    )
                                    
                                    if dec_img is not None:
                                        log("Çözme başarılı! Resim yüklendi.")
                                        st.success("Görselin şifresi başarıyla çözüldü!")
                                        st.session_state.decrypted_image = dec_img
                                    
                        except Exception as e:
                            log(f"Çözme hatası: {e}")
                            st.error(f"Çözme sırasında beklenmedik bir hata oluştu: {e}")
                            st.session_state.decrypted_image = None
            
            with col_res_btn:
                st.button("🗑️ Temizle", on_click=reset_all_inputs, use_container_width=True, help="Tüm girdileri ve sonuçları siler.") 

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
                # Görüntülenen resmi PNG olarak kaydet
                try:
                    image_to_show.save(img_byte_arr, format='PNG')
                except Exception as e:
                    st.warning(f"Resmi kaydetme hatası: {e}. İndirme butonu devre dışı.")
                
                if img_byte_arr.getvalue():
                    st.download_button(
                        label="Görüntülenen Resmi İndir",
                        data=img_byte_arr.getvalue(),
                        file_name="decrypted_image.png",
                        mime="image/png"
                    )
            else:
                st.info(caption)
            
            st.markdown("---")
            
            # --- Gizli Mesaj Gösterme Mantığı (Aynı bırakıldı) ---
            
            if st.session_state.decrypted_image is not None and st.session_state.hidden_message:
                if st.session_state.is_message_visible:
                    if st.button("Gizli Mesajı Gizle", use_container_width=True): 
                        log("Gizli mesaj gizlendi.")
                        st.session_state.is_message_visible = False
                        st.session_state.prompt_secret_key = False
                
                else:
                    if st.session_state.secret_key_hash:
                        st.session_state.prompt_secret_key = True
                        st.markdown("**Gizli Mesaj Kilitli!**")
                        
                        modal_pass = st.text_input(
                            "Filigran Şifresi", 
                            type="password", 
                            key="modal_pass_input", 
                            value=st.session_state.modal_pass,
                            placeholder="Gizli mesajı görmek için şifreyi girin"
                        )
                        st.session_state.modal_pass = modal_pass 
                        
                        if st.button("Filigranı Göster", key="show_watermark_btn", use_container_width=True):
                            entered_hash = hashlib.sha256(st.session_state.modal_pass.encode('utf-8')).hexdigest()
                            
                            if entered_hash == st.session_state.secret_key_hash:
                                log("Filigran şifresi doğru. Filigran oluşturuluyor.")
                                wm_img = add_text_watermark(st.session_state.decrypted_image, st.session_state.hidden_message)
                                st.session_state.watermarked_image = wm_img
                                st.session_state.is_message_visible = True
                                st.session_state.prompt_secret_key = False
                                st.session_state.modal_pass = ''
                                st.rerun()
                            else:
                                st.error("Yanlış Filigran Şifresi.")

                    else:
                        st.info("Gizli Mesaj Bulundu! Filigran koruması yok.")
                        if st.button("Gizli Mesajı Göster", use_container_width=True):
                            log("Gizli mesaj filigran olarak gösteriliyor.")
                            wm_img = add_text_watermark(st.session_state.decrypted_image, st.session_state.hidden_message)
                            st.session_state.watermarked_image = wm_img
                            st.session_state.is_message_visible = True
                            st.rerun()

def render_code_module():
    """Zaman ayarlı sınav kilit modülünü render eder."""
    
    st.markdown("## 👨‍🏫 Zaman Ayarlı Sınav Kilit Sistemi")
    st.markdown("---")

    tab_teacher, tab_student = st.tabs(["Öğretmen (Sınav Hazırlama)", "Öğrenci (Sınavı Çözme/İndirme)"])

    # --- ÖĞRETMEN SEKMESİ ---
    with tab_teacher:
        st.subheader("1. Sınav Dosyasını Yükle ve Kitle")
        
        with st.form("exam_encrypt_form", clear_on_submit=False):
            
            uploaded_file = st.file_uploader(
                "Sınav dosyasını seçin (PDF, DOCX, TXT vb.)", 
                type=["pdf", "docx", "txt", "zip", "png" , "jpg"], 
                key="exam_enc_file_upload"
            )
            
            col_start, col_end = st.columns(2)
            
            with col_start:
                st.markdown("##### 🔑 Başlangıç Zamanı (Sınav Giriş)")
                enc_date_start = st.date_input("Başlangıç Tarihi", datetime.datetime.now(TURKISH_TZ).date(), key="exam_enc_date_start")
                enc_time_start = st.text_input("Başlangıç Saati (SS:DD)", datetime.datetime.now(TURKISH_TZ).strftime("%H:%M"), key="exam_enc_time_start", help="Örnek: 14:30")
            
            with col_end:
                st.markdown("##### 🛑 Bitiş Zamanı (Sınav Kapanış)")
                min_date_end = enc_date_start
                enc_date_end = st.date_input("Bitiş Tarihi", enc_date_start, key="exam_enc_date_end", min_value=min_date_end)
                default_end_time = (datetime.datetime.now(TURKISH_TZ) + datetime.timedelta(hours=1)).strftime("%H:%M")
                enc_time_end = st.text_input("Bitiş Saati (SS:DD)", default_end_time, key="exam_enc_time_end", help="Örnek: 15:30")

            enc_access_code = st.text_input("Öğrenci Erişim Kodu (Şifre)", value="", key="exam_enc_access_code", type="password", help="Öğrencilerin sınavı indirebilmek için gireceği kod.")
            
            submitted = st.form_submit_button("🔒 Sınavı Kilitle ve Hazırla", type="primary", use_container_width=True)

        if submitted:
            st.session_state.exam_is_enc_downloaded = False
            st.session_state.exam_is_meta_downloaded = False
            st.session_state.exam_decrypted_bytes = None
            
            try:
                time_format_valid = True
                start_dt_naive, end_dt_naive = None, None
                try:
                    start_dt_naive = datetime.datetime.strptime(f"{enc_date_start} {enc_time_start}", "%Y-%m-%d %H:%M")
                    end_dt_naive = datetime.datetime.strptime(f"{enc_date_end} {enc_time_end}", "%Y-%m-%d %H:%M")
                except ValueError:
                    time_format_valid = False
                
                if not time_format_valid:
                    st.warning("Lütfen zaman formatlarını düzeltin (SS:DD).")
                    st.stop()
                
                start_dt = start_dt_naive.replace(tzinfo=TURKISH_TZ).replace(second=0, microsecond=0)
                end_dt = end_dt_naive.replace(tzinfo=TURKISH_TZ).replace(second=0, microsecond=0)
                now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                
                if not uploaded_file:
                    st.error("Lütfen önce bir sınav dosyası yükleyin.")
                elif not enc_access_code:
                    st.error("Lütfen bir erişim kodu belirleyin.")
                elif end_dt <= now_tr:
                    st.error("Bitiş zamanı şu anki zamandan ileri olmalıdır.")
                elif end_dt <= start_dt:
                    st.error("Bitiş zamanı, başlangıç zamanından sonra olmalıdır.")
                else:
                    progress_bar = st.progress(0, text="Sınav Şifreleniyor...")
                    
                    enc_bytes, meta_bytes = encrypt_exam_file(
                        uploaded_file.getvalue(), enc_access_code, start_dt, end_dt, progress_bar
                    )
                    
                    if enc_bytes and meta_bytes:
                        st.success(f"Sınav Başarıyla Hazırlandı! Başlangıç: **{start_dt.strftime('%d.%m.%Y %H:%M')}** | Bitiş: **{end_dt.strftime('%d.%m.%Y %H:%M')}**")
                        st.session_state.exam_enc_bytes = enc_bytes
                        st.session_state.exam_meta_bytes = meta_bytes
                    else:
                        st.error("Sınav kitleme sırasında bir hata oluştu.")

            except Exception as e:
                st.error(f"Beklenmedik bir hata oluştu: {e}")

        # --- İndirme Bölümü (Öğretmen) ---
        if st.session_state.exam_enc_bytes and st.session_state.exam_meta_bytes:
            st.markdown("---")
            st.subheader("2. Dosyaları İndir ve Paylaş")
            st.warning("⚠️ Lütfen **hem Şifreli Sınav Dosyasını** hem de **Sınav Meta Verisini** indirip öğrencilerinizle paylaşın.")
            
            base_name = os.path.splitext(uploaded_file.name)[0] if uploaded_file else "sinav"
            
            col_enc, col_meta = st.columns(2)
            
            with col_enc:
                # DÜZELTME: Şifreli sınav dosyasının PNG olarak inmesi sağlandı
                st.download_button(
                    label="📝 Şifreli Sınavı İndir (.png)",
                    data=st.session_state.exam_enc_bytes,
                    file_name=f"{base_name}_encrypted.png", 
                    mime="image/png", # Mime type PNG olarak ayarlandı
                    on_click=lambda: setattr(st.session_state, 'exam_is_enc_downloaded', True),
                    disabled=st.session_state.exam_is_enc_downloaded,
                    use_container_width=True
                )
            
            with col_meta:
                st.download_button(
                    label="🔑 Meta Veriyi İndir (.meta)",
                    data=st.session_state.exam_meta_bytes,
                    file_name=f"{base_name}_encrypted.meta",
                    mime="application/json",
                    on_click=lambda: setattr(st.session_state, 'exam_is_meta_downloaded', True),
                    disabled=st.session_state.exam_is_meta_downloaded,
                    use_container_width=True
                )
            
            if st.session_state.exam_is_enc_downloaded and st.session_state.exam_is_meta_downloaded:
                st.success("✅ İki dosya da indirildi.")

    # --- ÖĞRENCİ SEKMESİ ---
    with tab_student:
        st.subheader("1. Sınav Dosyalarını Yükle")
        
        col_file, col_meta = st.columns(2)
        
        with col_file:
            # DÜZELTME: Öğrenci tarafında PNG tipini zorla yüklemesi için kısıtlandı.
            enc_file_student = st.file_uploader("Şifreli Sınav Dosyasını Yükle (.png)", type=["png"], key="exam_dec_enc_file")
        with col_meta:
            meta_file_student = st.file_uploader("Sınav Meta Verisini Yükle (.meta)", type=["meta", "json", "txt"], key="exam_dec_meta_file")
            
        access_code_student = st.text_input("Öğrenci Erişim Kodu", key="exam_dec_access_code", type="password")
        
        st.markdown("---")
        
        # Meta Veri Okuma ve Zaman Kontrolü
        meta_data_available = False
        meta = {}
        is_active = False
        
        if meta_file_student:
            with st.container(border=True):
                try:
                    meta = json.loads(meta_file_student.getvalue().decode('utf-8'))
                    
                    if meta.get("type") != "EXAM_LOCK":
                        st.error("Yüklenen meta dosyası bir Sınav Kilidi dosyası değil.")
                        meta_file_student = None
                        
                    else:
                        meta_data_available = True
                        start_time_str = meta.get("start_time")
                        end_time_str = meta.get("end_time")
                        
                        start_dt = parse_normalized_time(start_time_str)
                        end_dt = parse_normalized_time(end_time_str)
                        now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                        
                        is_too_early = now_tr < start_dt
                        is_too_late = now_tr > end_dt
                        is_active = start_dt <= now_tr <= end_dt
                        
                        st.info(f"Başlangıç: **{start_dt.strftime('%d.%m.%Y %H:%M')}** | Bitiş: **{end_dt.strftime('%d.%m.%Y %H:%M')}**")
                        
                        if is_too_early:
                            time_left = start_dt - now_tr
                            st.warning(f"🔓 Sınav Henüz Başlamadı! Kalan süre: **{time_left.days} gün {time_left.seconds//3600} saat {(time_left.seconds%3600)//60} dakika**")
                        elif is_too_late:
                            st.error("🛑 Sınav Sona Erdi! Dosyayı çözemezsiniz.")
                        elif is_active:
                            time_left = end_dt - now_tr
                            st.success(f"✅ Sınav Aktif! Kalan süre: **{time_left.days} gün {time_left.seconds//3600} saat {(time_left.seconds%3600)//60} dakika**")
                        
                        
                except Exception as e:
                    st.error(f"Meta dosya okuma hatası veya geçersiz format: {e}")


        if st.button("🔓 Sınavı İndir ve Başla", type="primary", use_container_width=True):
            st.session_state.exam_decrypted_bytes = None
            
            if not enc_file_student or not meta_file_student:
                st.error("Lütfen hem şifreli sınav dosyasını hem de meta veriyi yükleyin.")
            elif not meta_data_available:
                st.error("Yüklenen meta dosyası geçersiz veya okunamıyor.")
            elif not access_code_student:
                st.error("Lütfen erişim kodunu girin.")
            elif not is_active:
                st.error("Sınav aktif zaman aralığında değil. Lütfen başlangıç/bitiş zamanlarını kontrol edin.")
            else:
                entered_hash = hashlib.sha256(access_code_student.encode('utf-8')).hexdigest()
                stored_hash = meta.get("access_code_hash")
                
                if entered_hash != stored_hash:
                    st.error("Hata: Girilen erişim kodu hatalı.")
                else:
                    progress_bar = st.progress(0, text="Sınav Çözülüyor...")
                    
                    dec_bytes = decrypt_exam_file(
                        enc_file_student.getvalue(), access_code_student, meta, progress_bar
                    )
                    
                    if dec_bytes:
                        st.success("Sınav Dosyası Başarıyla Çözüldü!")
                        st.session_state.exam_decrypted_bytes = dec_bytes
                    else:
                        st.error("Çözme hatası. Lütfen dosyaları ve erişim kodunu kontrol edin.")
        
        # --- İndirme Bölümü (Öğrenci) ---
        if st.session_state.exam_decrypted_bytes:
            st.markdown("---")
            st.subheader("2. Çözülmüş Dosyayı İndir")
            
            # Orijinal dosya uzantısını yeniden oluşturmak için (örneğin .pdf, .docx, .txt vb.)
            # Şifreli dosyanın adından ".png" uzantısını kaldırıp orjinal uzantıyı tahmin etme (Bu kısım isteğe bağlıdır, güvenli değildir)
            original_file_name = enc_file_student.name.replace("_encrypted.png", "") if enc_file_student else "decrypted_exam"
            file_extension = ""
            
            # Basit bir tahmin yap
            if any(ext in original_file_name.lower() for ext in [".pdf", ".docx", ".txt", ".zip", ".jpg", ".png"]):
                file_extension = os.path.splitext(original_file_name)[1]
            else:
                # Orijinal uzantı bilinmiyorsa sadece "dosya" olarak inmesi daha doğru.
                pass 

            st.download_button(
                label="📥 Çözülmüş Sınavı İndir",
                data=st.session_state.exam_decrypted_bytes,
                file_name=f"decrypted_exam{file_extension}",
                mime="application/octet-stream",
                use_container_width=True
            )
            
            st.success("Sınav dosyasını indirdikten sonra, cevaplarınızı öğretmeninizle paylaşmayı unutmayın!")
            
            
# --- ANA AKIŞ ---

init_session_state()

st.set_page_config(page_title="Zaman Ayarlı Kripto Uygulaması", layout="wide", initial_sidebar_state="expanded")
st.title("⏱️ Zaman Ayarlı Kripto Uygulaması")
st.caption("AES-GCM ve Streamlit ile zaman kilitli şifreleme modülleri.")

# Kenar çubuğu (Sidebar)
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/d/d4/Istanbul_Time_Zone.svg/1200px-Istanbul_Time_Zone.svg.png", width=100)
    st.markdown("## ⚙️ Uygulama Ayarları")
    
    view_option = st.radio(
        "Modül Seçimi",
        ('🖼️ Görsel Kilit (Time Lock)', '👨‍🏫 Sınav Kilit (Exam Lock)'),
        key="app_mode_radio"
    )
    
    if view_option == '🖼️ Görsel Kilit (Time Lock)':
        st.session_state.current_view = 'cipher'
    else:
        st.session_state.current_view = 'code'
        
    st.markdown("---")
    
    st.button("Tüm Verileri Temizle", on_click=reset_all_inputs, use_container_width=True, help="Tüm girdileri ve sonuçları siler.")
    
    st.markdown("---")
    st.markdown("##### 🇹🇷 Türk Saat Dilimi (UTC+03)")
    now_tr = datetime.datetime.now(TURKISH_TZ).strftime("%d.%m.%Y %H:%M:%S")
    st.write(f"Şu anki zaman: **{now_tr}**")


# Ana İçerik
if st.session_state.current_view == 'cipher':
    render_cipher_module()
elif st.session_state.current_view == 'code':
    render_code_module()

import streamlit as st
import datetime
import pytz
import json
import os
import hashlib
import io
import pandas as pd

from test10 import render_cipher_module # Cevapları işlemek için eklendi

# Gerekli Kriptografi ve Görüntü İşleme Kütüphaneleri
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
        pass

def normalize_time(dt_object):
    """datetime objesini 'YYYY-MM-DD HH:MM' formatına dönüştürür ve UTC'ye çevirir."""
    if dt_object.tzinfo is not None and dt_object.tzinfo.utcoffet(dt_object) is not None:
        dt_object = dt_object.astimezone(pytz.utc)
    return dt_object.strftime("%Y-%m-%d %H:%M")

def parse_normalized_time(time_str):
    """Normalize edilmiş UTC zamanını TZ-aware TR zamanına dönüştürür."""
    dt_naive = datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M")
    return dt_naive.replace(tzinfo=pytz.utc).astimezone(TURKISH_TZ)

def init_session_state():
    """Streamlit session state'i başlatır."""
    if 'current_view' not in st.session_state: st.session_state.current_view = 'cipher'
    # ... (Görsel Modül State'leri aynı bırakıldı)
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
    
    # Yeni Sınav Modülü State'leri
    if 'exam_enc_bytes' not in st.session_state: st.session_state.exam_enc_bytes = None
    if 'exam_meta_bytes' not in st.session_state: st.session_state.exam_meta_bytes = None
    if 'exam_is_enc_downloaded' not in st.session_state: st.session_state.exam_is_enc_downloaded = False
    if 'exam_is_meta_downloaded' not in st.session_state: st.session_state.exam_is_meta_downloaded = False
    if 'exam_decrypted_bytes' not in st.session_state: st.session_state.exam_decrypted_bytes = None
    if 'exam_is_unlocked' not in st.session_state: st.session_state.exam_is_unlocked = False # Yeni State
    if 'exam_total_questions' not in st.session_state: st.session_state.exam_total_questions = 0 # Yeni State
    if 'exam_current_meta' not in st.session_state: st.session_state.exam_current_meta = {} # Yeni State


def reset_all_inputs():
    """Tüm girdileri ve sonuçları temizler."""
    log("Tüm girdi ve sonuçlar temizlendi (reset_all_inputs).")
    
    # ... (Görsel Modül Reset kodları aynı bırakıldı)
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
    
    # Sınav Modülü Reset
    st.session_state.exam_enc_bytes = None
    st.session_state.exam_meta_bytes = None
    st.session_state.exam_is_enc_downloaded = False
    st.session_state.exam_is_meta_downloaded = False
    st.session_state.exam_decrypted_bytes = None
    st.session_state.exam_is_unlocked = False
    st.session_state.exam_total_questions = 0
    st.session_state.exam_current_meta = {}
    
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

# --- GÖRSEL ŞİFRELEME FONKSİYONLARI (AYNI BIRAKILDI) ---

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

def encrypt_exam_file(file_bytes, access_code, start_time_dt, end_time_dt, total_question_count, progress_bar):
    """Sınav dosyasını şifreler ve meta veriyi hazırlar (AES-GCM)."""
    try:
        progress_bar.progress(10, text="Anahtar türetiliyor...")
        
        # 1. Kriptografik anahtar türetme
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
        
        # 3. Meta Veri Oluşturma (Soru Sayısı Eklendi)
        access_code_hash = hashlib.sha256(access_code.encode('utf-8')).hexdigest()
        
        meta_data = {
            "type": "EXAM_LOCK",
            "version": "1.2", # Versiyon güncellendi
            "start_time": normalize_time(start_time_dt),
            "end_time": normalize_time(end_time_dt),
            "access_code_hash": access_code_hash,
            "nonce_hex": nonce.hex(),
            "salt_hex": salt.hex(),
            "total_questions": total_question_count, # YENİ: Soru sayısı eklendi
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
    # Bu fonksiyon, öğrenciye dosyayı çözdüğünü kanıtlamak ve cevap formunu açmak için kullanılır.
    # Dosyanın indirilmesi engellenecektir.
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
        
        # Çözme işlemi, sadece bütünlüğün ve şifrenin doğruluğunun kanıtlanması içindir.
        decrypted_bytes = aesgcm.decrypt(nonce_bytes, encrypted_bytes, aad)
        
        progress_bar.progress(100, text="Sınav Başarıyla Açıldı!")
        return decrypted_bytes

    except Exception as e:
        if "Authentication tag mismatch" in str(e):
            st.error("Çözme Hatası: Erişim kodu hatalı veya dosya bozuk.")
            log("Sınav Çözme Hatası: Bütünlük etiketi uyuşmadı (Yanlış kod/dosya).")
        else:
            st.error(f"Beklenmedik bir çözme hatası oluştu: {e}")
            log(f"Sınav Çözme Hatası: {e}")
            
        progress_bar.progress(100, text="Hata!")
        return None

# ------------------------------------------------------------------------------------------------

# --- ANA UYGULAMA YAPISI ---

# ... (render_cipher_module fonksiyonu AYNI BIRAKILDI)

def render_code_module():
    """Zaman ayarlı sınav kilit modülünü render eder."""
    
    st.markdown("## 👨‍🏫 Zaman Ayarlı Sınav Kilit Sistemi")
    st.markdown("⚠️ Öğrenci, sınavı indirmek yerine site üzerinde cevaplayacaktır.")
    st.markdown("---")

    tab_teacher, tab_student = st.tabs(["Öğretmen (Sınav Hazırlama)", "Öğrenci (Sınavı Çözme)"])

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

            # YENİ ALAN: Toplam Soru Sayısı
            total_questions = st.number_input(
                "Toplam Soru Sayısı", 
                min_value=1, 
                max_value=100, 
                value=20, 
                step=1, 
                key="total_question_count_input",
                help="Öğrencinin cevaplayacağı soru sayısı. Bu sayıya göre cevap alanı oluşturulacaktır."
            )
            
            enc_access_code = st.text_input("Öğrenci Erişim Kodu (Şifre)", value="", key="exam_enc_access_code", type="password", help="Öğrencilerin sınavı çözebilmek için gireceği kod.")
            
            submitted = st.form_submit_button("🔒 Sınavı Kilitle ve Hazırla", type="primary", use_container_width=True)

        if submitted:
            st.session_state.exam_is_enc_downloaded = False
            st.session_state.exam_is_meta_downloaded = False
            st.session_state.exam_decrypted_bytes = None
            
            try:
                # Zaman formatı kontrolü
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
                
                # Giriş kontrolleri
                if not uploaded_file:
                    st.error("Lütfen önce bir sınav dosyası yükleyin.")
                elif not enc_access_code:
                    st.error("Lütfen bir erişim kodu belirleyin.")
                elif end_dt <= now_tr:
                    st.error("Bitiş zamanı şu anki zamandan ileri olmalıdır.")
                elif end_dt <= start_dt:
                    st.error("Bitiş zamanı, başlangıç zamanından sonra olmalıdır.")
                elif total_questions <= 0:
                    st.error("Toplam soru sayısı 1'den büyük olmalıdır.")
                else:
                    progress_bar = st.progress(0, text="Sınav Şifreleniyor...")
                    
                    # Şifreleme fonksiyonuna soru sayısı eklendi
                    enc_bytes, meta_bytes = encrypt_exam_file(
                        uploaded_file.getvalue(), enc_access_code, start_dt, end_dt, total_questions, progress_bar
                    )
                    
                    if enc_bytes and meta_bytes:
                        st.success(f"Sınav Başarıyla Hazırlandı! Başlangıç: **{start_dt.strftime('%d.%m.%Y %H:%M')}** | Bitiş: **{end_dt.strftime('%d.%m.%Y %H:%M')}** | Soru Sayısı: **{total_questions}**")
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
            st.warning("⚠️ Lütfen **hem Şifreli Sınav Dosyasını** hem de **Sınav Meta Verisini** indirip öğrencilerinizle paylaşın. Öğrenci, dosya içeriğini görmez, sadece kilidi açar.")
            
            base_name = os.path.splitext(uploaded_file.name)[0] if uploaded_file else "sinav"
            
            col_enc, col_meta = st.columns(2)
            
            with col_enc:
                # Şifreli sınav dosyasının PNG olarak inmesi sağlandı
                st.download_button(
                    label="📝 Şifreli Sınav Dosyasını İndir (.png)",
                    data=st.session_state.exam_enc_bytes,
                    file_name=f"{base_name}_encrypted.png", 
                    mime="image/png", 
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
        st.subheader("1. Sınav Kilidini Aç")
        
        col_file, col_meta = st.columns(2)
        
        with col_file:
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
                    st.session_state.exam_current_meta = meta # Meta veriyi state'e kaydet
                    
                    if meta.get("type") != "EXAM_LOCK":
                        st.error("Yüklenen meta dosyası bir Sınav Kilidi dosyası değil.")
                        meta_file_student = None
                        
                    else:
                        meta_data_available = True
                        start_time_str = meta.get("start_time")
                        end_time_str = meta.get("end_time")
                        st.session_state.exam_total_questions = meta.get("total_questions", 0) # Soru sayısını kaydet
                        
                        start_dt = parse_normalized_time(start_time_str)
                        end_dt = parse_normalized_time(end_time_str)
                        now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                        
                        is_too_early = now_tr < start_dt
                        is_too_late = now_tr > end_dt
                        is_active = start_dt <= now_tr <= end_dt
                        
                        st.info(f"Başlangıç: **{start_dt.strftime('%d.%m.%Y %H:%M')}** | Bitiş: **{end_dt.strftime('%d.%m.%Y %H:%M')}** | Soru: **{st.session_state.exam_total_questions}**")
                        
                        if is_too_early:
                            time_left = start_dt - now_tr
                            st.warning(f"🔓 Sınav Henüz Başlamadı! Kalan süre: **{time_left.days} gün {time_left.seconds//3600} saat {(time_left.seconds%3600)//60} dakika**")
                        elif is_too_late:
                            st.error("🛑 Sınav Sona Erdi! Cevap formunu açamazsınız.")
                        elif is_active:
                            time_left = end_dt - now_tr
                            st.success(f"✅ Sınav Aktif! Kalan süre: **{time_left.days} gün {time_left.seconds//3600} saat {(time_left.seconds%3600)//60} dakika**")
                        
                        
                except Exception as e:
                    st.error(f"Meta dosya okuma hatası veya geçersiz format: {e}")

        # BUTON: Sınavı Çöz ve Cevap Formunu Aç
        if st.button("🔓 Sınavı Çöz ve Cevap Formunu Aç", type="primary", use_container_width=True):
            st.session_state.exam_is_unlocked = False # Kilidi resetle
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
                # Erişim Kodu Kontrolü
                entered_hash = hashlib.sha256(access_code_student.encode('utf-8')).hexdigest()
                stored_hash = meta.get("access_code_hash")
                
                if entered_hash != stored_hash:
                    st.error("Hata: Girilen erişim kodu hatalı.")
                else:
                    progress_bar = st.progress(0, text="Sınav Çözülüyor...")
                    
                    dec_bytes = decrypt_exam_file(
                        enc_file_student.getvalue(), access_code_student, meta, progress_bar
                    )
                    
                    if dec_bytes is not None:
                        # Çözme başarılıysa, dosyayı indirmek yerine cevap formunu aç
                        st.session_state.exam_is_unlocked = True
                        st.session_state.exam_decrypted_bytes = dec_bytes
                        st.success("Sınav kilidi başarıyla açıldı! Aşağıdaki cevap formunu doldurun.")
                        st.balloons()
                    else:
                        st.error("Çözme hatası. Lütfen dosyaları ve erişim kodunu kontrol edin.")
        
        st.markdown("---")
        
        # --- Cevap Formu Bölümü ---
        if st.session_state.exam_is_unlocked and st.session_state.exam_total_questions > 0:
            
            st.subheader(f"2. Sınav Cevap Formu ({st.session_state.exam_total_questions} Soru)")
            st.info("Sınav dosyasını ayrıca açarak buraya cevaplarınızı giriniz.")

            with st.form("exam_answer_form"):
                answers = {}
                cols_per_row = 4 # Yan yana kaç cevap alanı olacağı

                # Dinamik olarak cevap alanları oluşturma
                for i in range(1, st.session_state.exam_total_questions + 1):
                    col_index = (i - 1) % cols_per_row
                    if col_index == 0:
                        cols = st.columns(cols_per_row)

                    # Öğrenci, sınav dosyasını (PNG) manuel olarak açıp soruları görecek ve buraya cevabını girecektir.
                    answer = cols[col_index].text_input(f"Soru {i}", key=f"answer_{i}", max_chars=1)
                    answers[f"Soru_{i}"] = answer

                st.markdown("---")
                # Öğrenci Bilgileri (Gerekli)
                student_id = st.text_input("Öğrenci Numarası", max_chars=10, key="student_id_input")
                student_name = st.text_input("Adınız Soyadınız", key="student_name_input")

                submit_answers = st.form_submit_button("Cevapları Gönder/İndir", type="secondary", use_container_width=True)

                if submit_answers:
                    if not student_id or not student_name:
                        st.error("Lütfen öğrenci numaranızı ve adınızı soyadınızı giriniz.")
                    else:
                        # Cevapları topla ve formatla
                        answer_data = {
                            "Öğrenci No": student_id,
                            "Ad Soyad": student_name,
                            "Sınav Başlangıç": st.session_state.exam_current_meta.get("start_time"),
                            "Sınav Bitiş": st.session_state.exam_current_meta.get("end_time"),
                            "Gönderim Zamanı": datetime.datetime.now(TURKISH_TZ).strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        # Cevapları ekle (Soru_1: A, Soru_2: B, vb.)
                        answer_data.update(answers)

                        df = pd.DataFrame([answer_data])
                        
                        # Öğretmenin kontrol edebileceği bir CSV dosyası olarak hazırla
                        csv = df.to_csv(index=False).encode('utf-8')
                        
                        st.download_button(
                            label="📥 Cevap Dosyasını İndir (CSV)",
                            data=csv,
                            file_name=f"{student_id}_cevaplar_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                            mime="text/csv",
                            help="Bu dosyayı indirin ve öğretmeninizle paylaşın.",
                            use_container_width=True
                        )
                        st.success("Cevaplarınız indirildi. Lütfen bu dosyayı öğretmeninizle paylaşın.")
                        st.warning("Cevapları indirdikten sonra, formun içeriği temizlenecektir. Gerekirse tekrar doldurunuz.")
                        
                        # Cevapları gönderdikten sonra formu temizle
                        st.session_state.exam_is_unlocked = False
                        st.session_state.exam_total_questions = 0
                        st.session_state.exam_current_meta = {}
                        reset_all_inputs()
                        st.rerun()


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
    # Görsel şifreleme modülü
    st.warning("Görsel şifreleme modülünün kodları, isteğiniz dışında olduğu için yukarıdaki tam kodda tekrarlandı ancak değişiklik yapılmadı.")
    render_cipher_module()
elif st.session_state.current_view == 'code':
    # Sınav kilit modülü
    render_code_module()

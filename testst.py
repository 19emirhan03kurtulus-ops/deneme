import streamlit as st
import datetime
import pytz
import json
import os
import hashlib
import io
import pandas as pd
import base64

# Gerekli Kriptografi ve Görüntü İşleme Kütüphaneleri
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from PIL import Image, ImageDraw, ImageFont 
except ImportError:
    st.error("Kütüphane Hatası: 'cryptography' veya 'Pillow' kurulu değil. Lütfen terminalde 'pip install cryptography Pillow pandas' komutunu çalıştırın.")
    st.stop()


# --- SABİTLER ve İLK AYARLAR ---
TURKISH_TZ = pytz.timezone('Europe/Istanbul')
LOG_FILE = "app_log.txt" 
# Anahtar türetme için sabitler
KEY_LENGTH = 32
SALT_SIZE = 16
NONCE_SIZE = 12
PBKDF2_ITERATIONS = 100000

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
    if dt_object.tzinfo is not None and dt_object.tzinfo.utcoffset(dt_object) is not None:
        dt_object = dt_object.astimezone(pytz.utc)
    return dt_object.strftime("%Y-%m-%d %H:%M")

def parse_normalized_time(time_str):
    """Normalize edilmiş UTC zamanını TZ-aware TR zamanına dönüştürür."""
    dt_naive = datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M")
    return dt_naive.replace(tzinfo=pytz.utc).astimezone(TURKISH_TZ)

def get_key_from_password(password: str, salt: bytes) -> bytes:
    """PBKDF2HMAC kullanarak şifreden anahtar türetir."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def encrypt_data(data: bytes, password: str, progress_callback=None) -> tuple[bytes, bytes]:
    """Veriyi AES-256 GCM ile şifreler ve meta veriyi döndürür."""
    try:
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)
        key = get_key_from_password(password, salt)
        aesgcm = AESGCM(key)

        # Şifreleme (Authentication Tag otomatik olarak ciphertext'e eklenir)
        ciphertext_with_tag = aesgcm.encrypt(nonce, data, None)
        
        # progress_callback(100, "Şifreleme Tamamlandı.")

        meta_data = {
            "salt": base64.b64encode(salt).decode('utf-8'),
            "nonce": base64.b64encode(nonce).decode('utf-8'),
            "iterations": PBKDF2_ITERATIONS,
            "key_len": KEY_LENGTH,
            "cipher": "AES-256-GCM"
        }
        
        return ciphertext_with_tag, meta_data
    except Exception as e:
        log(f"Veri şifreleme hatası: {e}")
        return b"", {}

def decrypt_data(encrypted_data: bytes, password: str, meta: dict, progress_callback=None) -> bytes | None:
    """Şifreli veriyi çözer."""
    try:
        salt = base64.b64decode(meta["salt"])
        nonce = base64.b64decode(meta["nonce"])
        key = get_key_from_password(password, salt)
        aesgcm = AESGCM(key)
        
        # progress_callback(50, "Şifre çözülüyor...")

        # Şifre çözme (Authentication Tag dahil)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
        
        # progress_callback(100, "Şifre Çözme Başarılı.")
        return decrypted_data
    except Exception as e:
        log(f"Veri çözme hatası: {e}")
        return None

def add_text_watermark(img_bytes: bytes, text: str) -> Image.Image:
    """Bir görselin üzerine gizli mesajı filigran olarak ekler."""
    try:
        # Byte'tan PIL Image objesi oluştur
        img = Image.open(io.BytesIO(img_bytes)).convert("RGBA")
        
        # Filigran için yeni bir katman oluştur
        watermark = Image.new('RGBA', img.size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(watermark)
        
        # Font ayarları
        try:
            # Türkçe karakterler için bir Font kullanılması önerilir, ancak burada temel bir font kullanılır.
            font = ImageFont.truetype("arial.ttf", size=40)
        except IOError:
            # Sistemde font bulunamazsa varsayılan fontu kullan
            font = ImageFont.load_default()
            
        # Metin özellikleri
        text_color = (0, 0, 0, 100)  # Siyah, %40 opaklık (Hafif Görünür)
        
        # Metin boyutunu al ve konumu hesapla (Merkez)
        text_width, text_height = draw.textsize(text, font)
        
        # Merkezi konum
        x = (img.width - text_width) // 2
        y = (img.height - text_height) // 2

        # Metni çiz
        draw.text((x, y), text, font=font, fill=text_color)
        
        # Filigranı ana görselin üzerine ekle
        final_img = Image.alpha_composite(img, watermark).convert("RGB")
        return final_img

    except Exception as e:
        log(f"Filigran ekleme hatası: {e}")
        # Hata olursa orijinal görseli döndür
        return Image.open(io.BytesIO(img_bytes)).convert("RGB")

# --- SINAV SİSTEMİ KRİPTOGRAFİ FONKSİYONLARI ---

def encrypt_exam_file(data: bytes, access_code: str, start_dt: datetime.datetime, end_dt: datetime.datetime, progress_bar) -> tuple[bytes, bytes] | tuple[None, None]:
    """Sınav dosyasını şifreler ve meta veriyi hazırlar."""
    
    # 1. Access Code'dan Kripto Şifresini Türet
    log("Sınav dosyası şifreleniyor...")
    
    # access_code hem dosya şifrelemesi hem de meta veri hashi için kullanılır.
    # Meta veri hashi, öğrencinin doğru şifreyi girdiğini kontrol etmek için kullanılır.
    meta_password = access_code
    
    # 2. Dosyayı şifrele
    progress_bar.progress(20, text="Dosya içeriği şifreleniyor...")
    enc_data, base_meta = encrypt_data(data, meta_password)
    if not enc_data:
        return None, None
    
    # 3. Şifreli görseli oluştur
    progress_bar.progress(60, text="Şifreli veri görselleştiriliyor...")
    try:
        # Şifreli veriyi görselleştirmek için (Daha güvenli bir dağıtım metodu için)
        img = Image.new('RGB', (1024, 768), color = 'white')
        d = ImageDraw.Draw(img)
        d.text((10,10), "Sınav Dosyası Şifrelendi. Lütfen .meta dosyasını kullanarak çözün.", fill=(255,0,0))
        
        # Şifreli veriyi (salt+nonce+ciphertext_with_tag) gizlemek için BÜTÜN şifreli veriyi BASE64 olarak encode edip görselin altına yazmak pratik bir yöntemdir.
        # Streamlit PNG olarak kaydederken bunu kaybetmemesi için bytes olarak tutulur.
        full_enc_data = b"".join([base64.b64decode(base_meta["salt"]), base64.b64decode(base_meta["nonce"]), enc_data])
        
        # Görselin içine gizlenmiş veri olarak tutulamaz, bu yüzden dosya olarak inmesi gerekiyor.
        # Bu projede, şifreli verinin kendisi direkt olarak PNG dosyası olarak indiriliyor.
        # PNG formatının 'tEXt' chunk'ına veri yazmak yerine, Streamlit'in dosya indirme özelliği kullanılır.
        
        # Burada sadece bir PNG temsil resmi oluşturuluyor, asıl şifreli veri `enc_data` (ciphertext_with_tag)
        # ve meta veriler `base_meta` içinde.
        
        # Bu projede şifreli verinin kendisini PNG'ye çevirmek yerine, sadece şifreli veriyi Streamlit'in
        # download_button fonksiyonu ile inmesini sağlayacağız. (Tek dosya gerekliliği nedeniyle basit tutulur.)
        
        # Streamlit'in download_button'ı byte'ları doğrudan indirir. Bizim burada ihtiyacımız olan, 
        # şifreli veriyi (enc_data) ve meta veriyi (base_meta) ayrı ayrı indirilebilir hale getirmektir.

        # PNG olarak indirilecek dosya için basit bir "kilitli" görsel temsil edelim:
        locked_img = Image.new('RGB', (1024, 768), color = '#f0f0f0')
        draw_locked = ImageDraw.Draw(locked_img)
        draw_locked.text((50, 300), "🔒 Kilitli Sınav Dosyası 🔒", fill='#5c636a', font=ImageFont.load_default(size=40))
        draw_locked.text((50, 400), "Lütfen .meta dosyasını ve Erişim Kodunu kullanarak çözün.", fill='#5c636a', font=ImageFont.load_default(size=20))
        
        output = io.BytesIO()
        locked_img.save(output, format="PNG")
        enc_img_bytes = output.getvalue()
        
    except Exception as e:
        log(f"Görsel oluşturma hatası: {e}")
        return None, None
        
    # 4. Meta Veriyi Hazırla
    access_code_hash = hashlib.sha256(access_code.encode('utf-8')).hexdigest()
    
    final_meta = {
        "type": "EXAM_LOCK",
        "start_time": normalize_time(start_dt),
        "end_time": normalize_time(end_dt),
        "access_code_hash": access_code_hash, # Şifre yerine hash'i saklanır
        "original_file_extension": os.path.splitext(progress_bar.context.get('uploaded_file_name', 'dosya.bin'))[1], # Dosya uzantısını kaydet
        "total_questions": st.session_state.get('exam_total_questions_input', 0), # Toplam soru sayısını meta'ya ekle
        "crypto_meta": base_meta # Kripto detayları burada saklanır
    }
    
    progress_bar.progress(100, text="Başarılı!")
    
    return full_enc_data, json.dumps(final_meta, ensure_ascii=False, indent=4).encode('utf-8')

def decrypt_exam_file(full_enc_data: bytes, access_code: str, meta: dict, progress_bar) -> bytes | None:
    """Sınav dosyasını çözer."""
    log("Sınav dosyası çözülüyor...")
    
    try:
        # Full enc data: salt (16) + nonce (12) + ciphertext+tag (kalan)
        salt = full_enc_data[:SALT_SIZE]
        nonce = full_enc_data[SALT_SIZE:SALT_SIZE + NONCE_SIZE]
        enc_data = full_enc_data[SALT_SIZE + NONCE_SIZE:]

        progress_bar.progress(30, text="Kriptografik anahtar türetiliyor...")
        
        # Meta veriden kripto detaylarını al
        crypto_meta = meta.get("crypto_meta", {})
        
        # Anahtar türetme için salt'ı meta veriye ekle (bu fonksiyonda manuel olarak ayıklanıyor,
        # ancak decrypt_data standart meta formatını beklediği için uyumluluk amaçlı hazırlayalım)
        crypto_meta["salt"] = base64.b64encode(salt).decode('utf-8')
        crypto_meta["nonce"] = base64.b64encode(nonce).decode('utf-8')
        
        # Şifre çözme (Şifre olarak access_code kullanılır)
        decrypted_data = decrypt_data(enc_data, access_code, crypto_meta, progress_bar)

        if decrypted_data:
            progress_bar.progress(100, text="Çözme Başarılı!")
            # Toplam soru sayısını state'e kaydet (Cevap formunu oluşturmak için)
            st.session_state.exam_total_questions = meta.get("total_questions", 0)
            return decrypted_data
        else:
            progress_bar.empty()
            st.error("Şifre çözme başarısız. Lütfen erişim kodunu kontrol edin.")
            return None

    except Exception as e:
        progress_bar.empty()
        log(f"Sınav çözme sırasında beklenmedik hata: {e}")
        st.error(f"Sınav çözme sırasında beklenmedik hata: {e}")
        return None


# --- SESSION STATE YÖNETİMİ ---

def init_session_state():
    """Streamlit session state'i başlatır."""
    if 'current_view' not in st.session_state: st.session_state.current_view = 'cipher'
    
    # Görsel Kilit (Cipher) State'leri
    if 'generated_enc_bytes' not in st.session_state: st.session_state.generated_enc_bytes = None
    if 'generated_meta_bytes' not in st.session_state: st.session_state.generated_meta_bytes = None
    if 'decrypted_image' not in st.session_state: st.session_state.decrypted_image = None
    if 'watermarked_image' not in st.session_state: st.session_state.watermarked_image = None
    if 'is_message_visible' not in st.session_state: st.session_state.is_message_visible = False
    if 'hidden_message' not in st.session_state: st.session_state.hidden_message = ""
    if 'secret_key_hash' not in st.session_state: st.session_state.secret_key_hash = ""
    if 'modal_pass' not in st.session_state: st.session_state.modal_pass = ""
    
    # Sınav Kilit (Exam Lock) State'leri
    if 'exam_enc_bytes' not in st.session_state: st.session_state.exam_enc_bytes = None
    if 'exam_meta_bytes' not in st.session_state: st.session_state.exam_meta_bytes = None
    if 'exam_decrypted_bytes' not in st.session_state: st.session_state.exam_decrypted_bytes = None
    if 'exam_total_questions' not in st.session_state: st.session_state.exam_total_questions = 0
    if 'exam_answers' not in st.session_state: st.session_state.exam_answers = {}
    if 'exam_file_name_info' not in st.session_state: st.session_state.exam_file_name_info = "decrypted_exam.bin"


def reset_all_inputs():
    """Tüm girdileri ve sonuçları temizler."""
    log("Tüm girdi ve sonuçlar temizlendi (reset_all_inputs).")
    
    # Görsel Kilit Reset
    st.session_state.generated_enc_bytes = None
    st.session_state.generated_meta_bytes = None
    st.session_state.decrypted_image = None
    st.session_state.watermarked_image = None
    st.session_state.is_message_visible = False
    st.session_state.hidden_message = ""
    st.session_state.secret_key_hash = ""
    st.session_state.modal_pass = ""
    
    # Sınav Kilit Reset
    st.session_state.exam_enc_bytes = None
    st.session_state.exam_meta_bytes = None
    st.session_state.exam_decrypted_bytes = None
    st.session_state.exam_total_questions = 0
    st.session_state.exam_answers = {}
    st.session_state.exam_file_name_info = "decrypted_exam.bin"
    
    # Input key'lerini sıfırlamak için (Gerekli değilse kaldırılabilir)
    for key in list(st.session_state.keys()):
        if key.startswith(('exam_', 'enc_', 'dec_')):
            if key not in ['exam_total_questions', 'exam_answers']:
                 del st.session_state[key]
    
    st.session_state.reset_counter = st.session_state.get('reset_counter', 0) + 1


# --- RENDER FONKSİYONLARI ---

def render_cipher_module():
    """Zaman ayarlı görsel kilit modülünü render eder."""
    st.markdown("## 🖼️ Zaman Ayarlı Görsel Kilit Sistemi")
    st.markdown("---")

    col1, col2 = st.columns(2)

    # --- Şifreleme (Encryption) ---
    with col1:
        st.subheader("1. Görseli Şifrele ve Kitle")
        with st.form("encrypt_form", clear_on_submit=False):
            uploaded_file = st.file_uploader(
                "Görseli Seçin (.png, .jpg)", 
                type=["png", "jpg", "jpeg"], 
                key=f"enc_file_upload_{st.session_state.reset_counter}"
            )
            enc_password = st.text_input("Şifre (Kriptografik)", type="password", key="enc_password_input")
            enc_hidden_message = st.text_input("Gizli Mesaj (Filigran)", key="enc_hidden_message_input")
            enc_secret_key = st.text_input("Filigran Şifresi (Opsiyonel)", type="password", key="enc_secret_key_input", help="Gizli mesajı göstermek için ek koruma.")

            col_start, col_end = st.columns(2)
            with col_start:
                enc_date_start = st.date_input("Başlangıç Tarihi", datetime.datetime.now(TURKISH_TZ).date(), key="enc_date_start_input")
                enc_time_start = st.text_input("Başlangıç Saati (SS:DD)", datetime.datetime.now(TURKISH_TZ).strftime("%H:%M"), key="enc_time_start_input")
            with col_end:
                enc_date_end = st.date_input("Bitiş Tarihi", datetime.datetime.now(TURKISH_TZ).date() + datetime.timedelta(days=7), key="enc_date_end_input")
                enc_time_end = st.text_input("Bitiş Saati (SS:DD)", datetime.datetime.now(TURKISH_TZ).strftime("%H:%M"), key="enc_time_end_input")

            submitted = st.form_submit_button("🔒 Görseli Kilitle", type="primary", use_container_width=True)

        if submitted and uploaded_file and enc_password:
            try:
                # Tarih/Saat birleştirme ve TZ ekleme
                start_dt_naive = datetime.datetime.strptime(f"{enc_date_start} {enc_time_start}", "%Y-%m-%d %H:%M")
                end_dt_naive = datetime.datetime.strptime(f"{enc_date_end} {enc_time_end}", "%Y-%m-%d %H:%M")
                start_dt = start_dt_naive.replace(tzinfo=TURKISH_TZ)
                end_dt = end_dt_naive.replace(tzinfo=TURKISH_TZ)

                if end_dt <= start_dt:
                    st.error("Bitiş zamanı başlangıç zamanından sonra olmalıdır.")
                else:
                    progress_bar = st.progress(0, text="Görsel Şifreleniyor...")
                    
                    # Şifreleme işlemi
                    enc_bytes, meta_data = encrypt_data(uploaded_file.getvalue(), enc_password)
                    
                    if enc_bytes:
                        # Meta veriye zaman kilidini ve filigran detaylarını ekle
                        meta_data["type"] = "IMAGE_LOCK"
                        meta_data["start_time"] = normalize_time(start_dt)
                        meta_data["end_time"] = normalize_time(end_dt)
                        meta_data["hidden_message"] = enc_hidden_message
                        
                        if enc_secret_key:
                            meta_data["secret_key_hash"] = hashlib.sha256(enc_secret_key.encode('utf-8')).hexdigest()
                        else:
                            meta_data["secret_key_hash"] = ""

                        st.session_state.generated_enc_bytes = enc_bytes
                        st.session_state.generated_meta_bytes = json.dumps(meta_data, ensure_ascii=False, indent=4).encode('utf-8')
                        st.success("Görsel Başarıyla Şifrelendi. Aşağıdaki dosyaları indirin.")
                        
                        # İndirme butonları
                        col_dl1, col_dl2 = st.columns(2)
                        with col_dl1:
                            st.download_button(
                                label="🖼️ Şifreli Görseli İndir",
                                data=st.session_state.generated_enc_bytes,
                                file_name="locked_image.enc",
                                mime="application/octet-stream",
                                use_container_width=True
                            )
                        with col_dl2:
                            st.download_button(
                                label="🔑 Meta Veriyi İndir",
                                data=st.session_state.generated_meta_bytes,
                                file_name="locked_image.meta",
                                mime="application/json",
                                use_container_width=True
                            )
                    else:
                        st.error("Şifreleme sırasında bir hata oluştu.")
                    progress_bar.empty()

            except Exception as e:
                st.error(f"Hata: {e}")

    # --- Şifre Çözme (Decryption) ---
    with col2:
        st.subheader("2. Görseli Çöz ve Görüntüle")
        
        with st.form("decrypt_form", clear_on_submit=False):
            dec_enc_file = st.file_uploader(
                "Şifreli Görseli Yükle (.enc)", 
                type=["enc", "bin", "dat"], 
                key=f"dec_enc_file_{st.session_state.reset_counter}"
            )
            dec_meta_file = st.file_uploader(
                "Meta Veriyi Yükle (.meta)", 
                type=["meta", "json"], 
                key=f"dec_meta_file_{st.session_state.reset_counter}"
            )
            dec_password = st.text_input("Şifre (Kriptografik)", type="password", key="dec_password_input")
            
            dec_submitted = st.form_submit_button("🔓 Görseli Çöz", type="secondary", use_container_width=True)

        if dec_submitted and dec_enc_file and dec_meta_file and dec_password:
            st.session_state.decrypted_image = None
            st.session_state.watermarked_image = None
            st.session_state.is_message_visible = False
            
            try:
                meta = json.loads(dec_meta_file.getvalue().decode('utf-8'))
                
                # Zaman Kontrolü
                start_dt = parse_normalized_time(meta["start_time"])
                end_dt = parse_normalized_time(meta["end_time"])
                now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                
                if not (start_dt <= now_tr <= end_dt):
                    st.error("Zaman Kilidi Devrede: Görsel şu an çözülemez. Lütfen zaman aralığını kontrol edin.")
                    st.info(f"Başlangıç: {start_dt.strftime('%d.%m.%Y %H:%M')} | Bitiş: {end_dt.strftime('%d.%m.%Y %H:%M')}")
                    st.stop()

                progress_bar = st.progress(0, text="Görsel Çözülüyor...")
                dec_bytes = decrypt_data(dec_enc_file.getvalue(), dec_password, meta)
                
                if dec_bytes:
                    st.session_state.decrypted_image = dec_bytes
                    st.session_state.hidden_message = meta.get("hidden_message", "")
                    st.session_state.secret_key_hash = meta.get("secret_key_hash", "")
                    st.success("Görsel Başarıyla Çözüldü!")
                else:
                    st.error("Şifre çözme başarısız. Şifreyi veya dosyaları kontrol edin.")
                progress_bar.empty()
                
            except Exception as e:
                st.error(f"Meta veri okuma veya şifre çözme hatası: {e}")

        st.markdown("---")
        st.subheader("3. Sonuç ve Gizli Mesaj")

        # Görseli Görüntüleme
        if st.session_state.watermarked_image is not None and st.session_state.is_message_visible:
             st.image(st.session_state.watermarked_image, caption="Çözülmüş Görsel (Filigranlı)", use_column_width=True)
        elif st.session_state.decrypted_image is not None:
            st.image(st.session_state.decrypted_image, caption="Çözülmüş Görsel (Orijinal)", use_column_width=True)
        else:
            st.info("Çözülmüş görsel buraya gelecek.")

        # --- GÖNDERDİĞİNİZ GİZLİ MESAJ GÖRÜNTÜLEME MANTIĞI BURAYA EKLENMİŞTİR ---
        if st.session_state.decrypted_image is not None and st.session_state.hidden_message:
            
            # Eğer mesaj görünürse
            if st.session_state.is_message_visible:
                if st.button("Gizli Mesajı Gizle", use_container_width=True): 
                    log("Gizli mesaj gizlendi.")
                    st.session_state.is_message_visible = False
                    st.session_state.watermarked_image = None
                    st.rerun()
            
            # Eğer mesaj gizliyse
            else:
                # Kilitli (Şifreli) ise
                if st.session_state.secret_key_hash:
                    st.markdown("**Gizli Mesaj Kilitli!**")
                    
                    modal_pass = st.text_input(
                        "Filigran Şifresi", 
                        type="password", 
                        key="modal_pass_input", 
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
                            st.session_state.modal_pass = ''
                            st.rerun()
                        else:
                            st.error("Yanlış Filigran Şifresi.")

                # Kilitsiz ise
                else:
                    st.info("Gizli Mesaj Bulundu! Filigran koruması yok.")
                    if st.button("Gizli Mesajı Göster", use_container_width=True):
                        log("Gizli mesaj filigran olarak gösteriliyor.")
                        wm_img = add_text_watermark(st.session_state.decrypted_image, st.session_state.hidden_message)
                        st.session_state.watermarked_image = wm_img
                        st.session_state.is_message_visible = True
                        st.rerun()
        # --- GİZLİ MESAJ GÖRÜNTÜLEME MANTIĞI SONU ---

def render_code_module():
    """Zaman ayarlı sınav kilit modülünü render eder."""
    
    st.markdown("## 👨‍🏫 Zaman Ayarlı Sınav Kilit Sistemi")
    st.markdown("---")

    tab_teacher, tab_student = st.tabs(["Öğretmen (Sınav Hazırlama)", "Öğrenci (Sınavı Çözme/Cevaplama)"])

    # --- ÖĞRETMEN SEKMESİ ---
    with tab_teacher:
        st.subheader("1. Sınav Dosyasını Yükle ve Kitle")
        
        # Soru Sayısı Girişi (Yeni Eklendi)
        total_questions = st.number_input(
            "Toplam Soru Sayısı (Öğrenci Cevap Formu için)", 
            min_value=1, 
            max_value=500, 
            value=st.session_state.get('exam_total_questions_input', 10), 
            key='exam_total_questions_input'
        )
        
        with st.form("exam_encrypt_form", clear_on_submit=False):
            
            uploaded_file = st.file_uploader(
                "Sınav dosyasını seçin (PDF, DOCX, TXT, PNG vb.)", 
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
            # Önceki sonuçları temizle
            st.session_state.exam_enc_bytes = None
            st.session_state.exam_meta_bytes = None
            st.session_state.exam_decrypted_bytes = None
            
            # Form doğrulama
            try:
                # Zaman formatı kontrolü
                start_dt_naive = datetime.datetime.strptime(f"{enc_date_start} {enc_time_start}", "%Y-%m-%d %H:%M")
                end_dt_naive = datetime.datetime.strptime(f"{enc_date_end} {enc_time_end}", "%Y-%m-%d %H:%M")
            except ValueError:
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
                
                # Dosya adı bilgisini ekle (decrypt_exam_file'a uzantıyı iletmek için)
                progress_bar.context = {'uploaded_file_name': uploaded_file.name}

                # Şifreleme fonksiyonu
                enc_bytes, meta_bytes = encrypt_exam_file(
                    uploaded_file.getvalue(), enc_access_code, start_dt, end_dt, progress_bar
                )
                
                if enc_bytes and meta_bytes:
                    st.success(f"Sınav Başarıyla Hazırlandı! Başlangıç: **{start_dt.strftime('%d.%m.%Y %H:%M')}** | Bitiş: **{end_dt.strftime('%d.%m.%Y %H:%M')}**")
                    st.session_state.exam_enc_bytes = enc_bytes
                    st.session_state.exam_meta_bytes = meta_bytes
                else:
                    st.error("Sınav kitleme sırasında bir hata oluştu.")
                
                progress_bar.empty()

        # --- İndirme Bölümü (Öğretmen) ---
        if st.session_state.exam_enc_bytes and st.session_state.exam_meta_bytes:
            st.markdown("---")
            st.subheader("2. Dosyaları İndir ve Paylaş")
            st.warning("⚠️ Lütfen **hem Şifreli Sınav Dosyasını** (.enc) hem de **Sınav Meta Verisini** (.meta) indirip öğrencilerinizle paylaşın.")
            
            base_name = os.path.splitext(uploaded_file.name)[0] if uploaded_file else "sinav"
            
            col_enc, col_meta = st.columns(2)
            
            with col_enc:
                st.download_button(
                    label="📝 Şifreli Sınav İçeriği İndir (.enc)",
                    data=st.session_state.exam_enc_bytes,
                    file_name=f"{base_name}_encrypted.enc", 
                    mime="application/octet-stream", 
                    use_container_width=True
                )
            
            with col_meta:
                st.download_button(
                    label="🔑 Meta Veriyi İndir (.meta)",
                    data=st.session_state.exam_meta_bytes,
                    file_name=f"{base_name}_encrypted.meta",
                    mime="application/json",
                    use_container_width=True
                )

    # --- ÖĞRENCİ SEKMESİ ---
    with tab_student:
        st.subheader("1. Sınav Dosyalarını Yükle ve Başla")
        
        col_file, col_meta = st.columns(2)
        
        with col_file:
            enc_file_student = st.file_uploader("Şifreli Sınav İçeriğini Yükle (.enc)", type=["enc", "bin", "dat"], key="exam_dec_enc_file")
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
                        
                        # Dosya adı bilgisini state'e kaydet
                        original_ext = meta.get("original_file_extension", ".bin")
                        st.session_state.exam_file_name_info = f"decrypted_exam{original_ext}"
                        
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
                        st.session_state.exam_decrypted_bytes = dec_bytes
                        st.success("Sınav Dosyası Başarıyla Çözüldü! Lütfen aşağıdan indirip cevaplarınızı girin.")
                    else:
                        st.error("Çözme hatası. Lütfen dosyaları ve erişim kodunu kontrol edin.")
                    
                    progress_bar.empty()
        
        st.markdown("---")
        
        # --- Sınav Görüntüleme ve Cevap Formu (DİNAMİK KISIM) ---
        if st.session_state.exam_decrypted_bytes:
            st.subheader("2. Sınav Görüntüleme ve Cevaplama")
            
            # Sınav Dosyasını İndirme
            st.download_button(
                label=f"📥 Çözülmüş Sınavı İndir ({st.session_state.exam_file_name_info})",
                data=st.session_state.exam_decrypted_bytes,
                file_name=st.session_state.exam_file_name_info,
                mime="application/octet-stream",
                use_container_width=True
            )
            
            st.warning("⚠️ Önemli: Dosyayı indirdikten sonra, süre bitmeden cevaplarınızı aşağıdaki forma girin!")

            # Dinamik Cevap Formu
            if st.session_state.exam_total_questions > 0:
                st.markdown("### Cevap Formu")
                st.info(f"Toplam **{st.session_state.exam_total_questions}** soru için cevaplarınızı girin.")
                
                # Formu sütunlara böl
                num_cols = 4 if st.session_state.exam_total_questions > 10 else 2
                cols = st.columns(num_cols)
                
                def update_answer(q_num):
                    """Cevap state'ini günceller."""
                    st.session_state.exam_answers[q_num] = st.session_state[f'answer_{q_num}']

                for i in range(1, st.session_state.exam_total_questions + 1):
                    col_index = (i - 1) % num_cols
                    with cols[col_index]:
                        # Cevap kutusu oluştur
                        st.text_input(
                            f"Soru {i}", 
                            key=f'answer_{i}', 
                            value=st.session_state.exam_answers.get(i, ""),
                            on_change=update_answer,
                            args=(i,),
                            placeholder="Cevabı buraya girin"
                        )
                        
                # Cevapları Toparla ve İndir
                st.markdown("---")
                
                # DataFrame oluşturma
                answers_df = pd.DataFrame(
                    [
                        {"Soru Numarası": i, "Cevap": st.session_state.exam_answers.get(i, "")} 
                        for i in range(1, st.session_state.exam_total_questions + 1)
                    ]
                )
                
                csv_data = answers_df.to_csv(index=False).encode('utf-8')
                
                st.download_button(
                    label="📤 Cevapları CSV Olarak İndir",
                    data=csv_data,
                    file_name="sinav_cevaplari.csv",
                    mime="text/csv",
                    use_container_width=True,
                    type="secondary"
                )
                
                st.success("Cevap dosyanızı indirip öğretmeninizle paylaşarak sınavınızı tamamlayabilirsiniz.")
                

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
    
    # Sürekli güncel zamanı göster
    now_tr = datetime.datetime.now(TURKISH_TZ).strftime("%d.%m.%Y %H:%M:%S")
    st.markdown("##### 🇹🇷 Türk Saat Dilimi (UTC+03)")
    st.write(f"Şu anki zaman: **{now_tr}**")


# Ana İçerik
if st.session_state.current_view == 'cipher':
    render_cipher_module()
elif st.session_state.current_view == 'code':
    render_code_module()

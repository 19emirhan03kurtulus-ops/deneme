import streamlit as st
import datetime
import pytz
import hashlib
import json
import os
import io
from Crypto.Cipher import AES
from Crypto.Util import Padding
from Crypto.Random import get_random_bytes
from PIL import Image, ImageDraw, ImageFont

# --- SABİTLER VE BAŞLANGIÇ AYARLARI ---
# Streamlit uygulamalarında, genellikle gerekli modüllerin (Crypto, PIL vb.) 
# yüklenmesi için özel bir ortam gerekir. Bu kod, yapıyı göstermek için tasarlanmıştır.

# Türk Saat Dilimi (UTC+03)
TURKISH_TZ = pytz.timezone('Europe/Istanbul')

# --- YARDIMCI FONKSİYONLAR ---

def log(message):
    """Konsola log mesajı basar (Streamlit'te direkt görünmez, ancak arkada çalışır)."""
    # st.session_state.log_messages.append(f"[{datetime.datetime.now(TURKISH_TZ).strftime('%H:%M:%S')}] {message}")
    pass # Loglama sadece debug amaçlıdır, performansı etkilememesi için pasif bırakıldı.

def parse_normalized_time(time_str):
    """ISO formatındaki zaman stringini Türk saat dilimine ayarlı datetime objesine çevirir."""
    dt_naive = datetime.datetime.fromisoformat(time_str)
    # Datetime objesi zaten UTC formatında saklanıp ISO'ya çevrildiği varsayılır.
    # Ancak Streamlit'te doğrudan girdi olarak alınan zamanlar TZ-aware olmayabilir.
    # Güvenlik için yeniden TZ-aware yapıp TR'ye dönüştürelim.
    dt_utc = pytz.utc.localize(dt_naive)
    return dt_utc.astimezone(TURKISH_TZ).replace(second=0, microsecond=0)

def init_session_state():
    """Tüm Streamlit oturum durum değişkenlerini başlatır."""
    if 'current_view' not in st.session_state:
        st.session_state.current_view = 'cipher'
    if 'encrypted_bytes' not in st.session_state:
        st.session_state.encrypted_bytes = None
    if 'decrypted_image' not in st.session_state:
        st.session_state.decrypted_image = None
    if 'watermarked_image' not in st.session_state:
        st.session_state.watermarked_image = None
    if 'hidden_message' not in st.session_state:
        st.session_state.hidden_message = ""
    if 'secret_key_hash' not in st.session_state:
        st.session_state.secret_key_hash = None
    if 'is_message_visible' not in st.session_state:
        st.session_state.is_message_visible = False
    if 'prompt_secret_key' not in st.session_state:
        st.session_state.prompt_secret_key = False
    if 'modal_pass' not in st.session_state:
        st.session_state.modal_pass = ''
        
    # Sınav Kilit Sistemi için
    if 'exam_enc_bytes' not in st.session_state:
        st.session_state.exam_enc_bytes = None
    if 'exam_meta_bytes' not in st.session_state:
        st.session_state.exam_meta_bytes = None
    if 'exam_is_enc_downloaded' not in st.session_state:
        st.session_state.exam_is_enc_downloaded = False
    if 'exam_is_meta_downloaded' not in st.session_state:
        st.session_state.exam_is_meta_downloaded = False
    if 'exam_decrypted_bytes' not in st.session_state:
        st.session_state.exam_decrypted_bytes = None
    
    log("Oturum durumu başlatıldı.")

def reset_all_inputs():
    """Tüm oturum durumunu sıfırlar."""
    keys_to_reset = [
        'encrypted_bytes', 'decrypted_image', 'watermarked_image', 'hidden_message', 
        'secret_key_hash', 'is_message_visible', 'prompt_secret_key', 'modal_pass',
        'exam_enc_bytes', 'exam_meta_bytes', 'exam_is_enc_downloaded', 
        'exam_is_meta_downloaded', 'exam_decrypted_bytes'
    ]
    for key in keys_to_reset:
        st.session_state[key] = None
    st.session_state.is_message_visible = False
    st.session_state.prompt_secret_key = False
    st.session_state.modal_pass = ''
    log("Tüm veriler temizlendi.")

# --- KRİPTO VE FİGRAN FONKSİYONLARI ---

def get_key_from_pass(password: str) -> bytes:
    """Şifreden 32 baytlık AES anahtarı üretir (SHA-256)."""
    return hashlib.sha256(password.encode('utf-8')).digest()

def encrypt_data(data: bytes, key_bytes: bytes) -> bytes:
    """Veriyi AES-256 GCM ile şifreler. IV ve Tag'i şifreli verinin başına ekler."""
    try:
        cipher = AES.new(key_bytes, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        # Şifreli veri formatı: IV (16 bayt) + Tag (16 bayt) + Ciphertext
        return cipher.nonce + tag + ciphertext
    except Exception as e:
        log(f"Şifreleme hatası: {e}")
        return b''

def decrypt_data(encrypted_data: bytes, key_bytes: bytes) -> bytes:
    """AES-256 GCM ile şifreli veriyi çözer."""
    try:
        # Şifreli veri formatı: IV (16 bayt) + Tag (16 bayt) + Ciphertext
        nonce = encrypted_data[:16]
        tag = encrypted_data[16:32]
        ciphertext = encrypted_data[32:]
        
        cipher = AES.new(key_bytes, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except ValueError:
        log("Şifre çözme veya doğrulama (GCM Tag) başarısız.")
        return b''
    except Exception as e:
        log(f"Şifre çözme sırasında hata: {e}")
        return b''

def add_text_watermark(image, text):
    """PIL Image objesine şeffaf bir metin filigranı ekler."""
    try:
        # Yeni bir şeffaflık katmanı oluştur
        watermark = Image.new('RGBA', image.size, (255, 255, 255, 0))
        draw = ImageDraw.Draw(watermark)
        
        # Font seçimi ve boyut ayarlama
        try:
            # Sistemde bulunması daha olası bir font kullanıyoruz
            font = ImageFont.truetype("arial.ttf", 40)
        except IOError:
            font = ImageFont.load_default()
            
        # Metni çapraz olarak tekrarla
        diagonal_length = int((image.width**2 + image.height**2)**0.5)
        step = 250 # Tekrarlar arası mesafe
        
        for i in range(-diagonal_length, diagonal_length, step):
            for j in range(0, diagonal_length, step):
                draw.text((i + j, i), text, font=font, fill=(0, 0, 0, 30), angle=45) # Açık gri ve yarı saydam
        
        # Filigranı ana görselle birleştir
        return Image.alpha_composite(image.convert('RGBA'), watermark).convert('RGB')
    except Exception as e:
        log(f"Filigran oluşturma hatası: {e}")
        return image


# --- GÖRSEL KİLİT MODÜLÜ KRİPTO FONKSİYONLARI ---

def encrypt_image_data(image_bytes, password, start_dt, end_dt, hidden_message=None, secret_key=None):
    """Görsel verisini şifreler ve meta veriyi hazırlar."""
    
    key_bytes = get_key_from_pass(password)
    encrypted_payload = encrypt_data(image_bytes, key_bytes)
    
    if not encrypted_payload:
        return b'', None
    
    meta_data = {
        "type": "IMAGE_TIMELOCK",
        "start_time": start_dt.astimezone(pytz.utc).isoformat(),
        "end_time": end_dt.astimezone(pytz.utc).isoformat(),
        "hash_check": hashlib.sha256(encrypted_payload).hexdigest(), # Veri bütünlüğü kontrolü için
    }
    
    # Gizli mesajı meta veriye ekle
    if hidden_message:
        meta_data["hidden_message"] = hidden_message
        if secret_key:
            meta_data["secret_key_hash"] = hashlib.sha256(secret_key.encode('utf-8')).hexdigest()
        else:
            meta_data["secret_key_hash"] = None
    
    # Şifreli payload'ı meta veri ile birleştirme (basit bir steganografi simülasyonu)
    # Gerçek uygulamada bu, bir PNG içine gizlenir. Burada sadece JSON meta veriyi payload'ın sonuna ekliyoruz.
    # Ancak Streamlit'te iki ayrı dosya indirip yüklemek daha temiz bir kullanıcı deneyimi sağlar.
    # Bu yüzden sadece şifreli bytes'ı döndürelim ve meta veriyi ayrı bir dosya olarak indirtelim.
    
    meta_bytes = json.dumps(meta_data, indent=2).encode('utf-8')
    
    return encrypted_payload, meta_bytes


def decrypt_image_data(encrypted_data_bytes, password, meta_data_bytes):
    """Görsel verisini çözer, zaman kontrolü yapar ve meta veriyi çıkarır."""
    
    key_bytes = get_key_from_pass(password)
    
    try:
        meta = json.loads(meta_data_bytes.decode('utf-8'))
    except:
        log("Meta verisi okunamadı/geçersiz.")
        return None, "Meta verisi okunamadı veya geçersiz format."
    
    if meta.get("type") != "IMAGE_TIMELOCK":
        return None, "Bu dosya bir Görsel Zaman Kilidi dosyası değil."
    
    # 1. HASH KONTROLÜ
    if hashlib.sha256(encrypted_data_bytes).hexdigest() != meta.get("hash_check"):
        return None, "Şifreli veri bozuk veya üzerinde oynanmış."
        
    # 2. ZAMAN KONTROLÜ
    end_time_str = meta.get("end_time")
    try:
        end_dt = parse_normalized_time(end_time_str)
    except:
        return None, "Meta verideki bitiş zamanı okunamadı."
    
    now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
    
    if now_tr < end_dt:
        time_left = end_dt - now_tr
        return None, f"🔓 Kilitli! Çözmek için kalan süre: **{time_left.days} gün {time_left.seconds//3600} saat {(time_left.seconds%3600)//60} dakika**."
    
    # 3. ŞİFRE ÇÖZME
    decrypted_bytes = decrypt_data(encrypted_data_bytes, key_bytes)
    
    if not decrypted_bytes:
        return None, "Hata: Yanlış Şifre veya veri bütünlüğü bozuk."
        
    # Başarılı: Görseli yükle ve gizli mesajı döndür
    try:
        img = Image.open(io.BytesIO(decrypted_bytes))
        st.session_state.hidden_message = meta.get("hidden_message", "")
        st.session_state.secret_key_hash = meta.get("secret_key_hash", None)
        return img, "✅ Görselin Kilidi Başarıyla Açıldı!"
    except Exception as e:
        log(f"Çözülen veri bir görsel değil: {e}")
        return None, "Hata: Çözülen veri geçerli bir görsel dosyası değil."


# --- SINAV KİLİT MODÜLÜ KRİPTO FONKSİYONLARI ---

def encrypt_exam_file(file_bytes, access_code, start_dt, end_dt, progress_bar):
    """Sınav dosyasını şifreler ve meta veriyi hazırlar."""
    progress_bar.progress(10, text="Anahtar Üretiliyor...")
    
    key_bytes = get_key_from_pass(access_code)
    
    # Dosyanın kendisini şifrele
    progress_bar.progress(30, text="Dosya Şifreleniyor...")
    encrypted_payload = encrypt_data(file_bytes, key_bytes)
    
    if not encrypted_payload:
        progress_bar.progress(100, text="Hata!")
        return None, None
        
    progress_bar.progress(70, text="Meta Veri Hazırlanıyor...")
    
    meta_data = {
        "type": "EXAM_LOCK",
        "start_time": start_dt.astimezone(pytz.utc).isoformat(),
        "end_time": end_dt.astimezone(pytz.utc).isoformat(),
        "access_code_hash": hashlib.sha256(access_code.encode('utf-8')).hexdigest(),
        "hash_check": hashlib.sha256(encrypted_payload).hexdigest(),
    }
    
    meta_bytes = json.dumps(meta_data, indent=2).encode('utf-8')
    
    # ÖĞRETMEN TARAFINDA: Şifreli payload'ı bir PNG olarak paketleme (Simülasyon)
    # Bu, öğrencilerin dosyayı bir resim sanmasını amaçlayan bir steganografi simülasyonudur.
    # Gerçek uygulamada, payload bir PNG'nin IEND bloğu arkasına gizlenir.
    # Burada basitçe encrypted_payload'u bir bayt dizisi olarak döndürüyoruz.
    # Streamlit'in download_button'ı bu bayt dizisini PNG olarak indirecektir.
    
    # Basit bir PNG başlığı ekleyerek daha inandırıcı bir 'PNG' oluşturabiliriz.
    # Ancak bu, dosya boyutunu artırır. Güvenli ve basit olması için şifreli veriyi doğrudan PNG olarak indirteceğiz.

    progress_bar.progress(100, text="Hazır!")
    return encrypted_payload, meta_bytes


def decrypt_exam_file(encrypted_data_bytes, access_code, meta_data, progress_bar):
    """Sınav dosyasını çözer (zaman ve kod kontrolü yapılır)."""
    progress_bar.progress(10, text="Meta Veri Doğrulanıyor...")
    
    if meta_data.get("type") != "EXAM_LOCK":
        progress_bar.progress(100, text="Hata!")
        return None
        
    # 1. HASH KONTROLÜ
    if hashlib.sha256(encrypted_data_bytes).hexdigest() != meta_data.get("hash_check"):
        progress_bar.progress(100, text="Hata!")
        return None
        
    # ZAMAN KONTROLÜ burada yapılır, ancak 'render_code_module' içinde zaten yapıldığı için 
    # burada sadece şifre çözmeye odaklanıyoruz.
    
    progress_bar.progress(30, text="Anahtar Üretiliyor...")
    key_bytes = get_key_from_pass(access_code)
    
    progress_bar.progress(70, text="Dosya Çözülüyor...")
    decrypted_bytes = decrypt_data(encrypted_data_bytes, key_bytes)
    
    progress_bar.progress(100, text="Tamamlandı!")
    return decrypted_bytes

# --- MODÜL RENDER FONKSİYONLARI ---

def render_cipher_module():
    """Zaman Ayarlı Görsel Kilit modülünü render eder."""
    
    st.markdown("## 🖼️ Zaman Ayarlı Görsel Kilit Sistemi")
    st.markdown("---")
    
    tab_enc, tab_dec = st.tabs(["Şifrele", "Çöz"])

    with tab_enc:
        st.subheader("1. Görseli Yükle ve Kitle")
        with st.form("image_encrypt_form", clear_on_submit=False):
            uploaded_file = st.file_uploader(
                "Şifrelenecek Görseli Seçin (.png, .jpg)", 
                type=["png", "jpg", "jpeg"], 
                key="img_enc_file_upload"
            )
            
            password = st.text_input("Şifre (Çözmek İçin Gerekli)", type="password", key="img_enc_pass")
            
            st.markdown("##### ⏳ Kilit Bitiş Zamanı (Bu zamandan sonra çözülebilir)")
            col_date, col_time = st.columns(2)
            now_tr = datetime.datetime.now(TURKISH_TZ).date()
            
            with col_date:
                enc_date_end = st.date_input("Bitiş Tarihi", now_tr, key="img_enc_date_end")
            with col_time:
                default_end_time = (datetime.datetime.now(TURKISH_TZ) + datetime.timedelta(hours=1)).strftime("%H:%M")
                enc_time_end = st.text_input("Bitiş Saati (SS:DD)", default_end_time, key="img_enc_time_end")
                
            st.markdown("---")
            st.subheader("2. Gizli Mesaj Ekle (Filigran)")
            hidden_message = st.text_area("Görsel Çözülünce Ortaya Çıkacak Mesaj", key="img_hidden_msg")
            secret_key = st.text_input("Filigran Şifresi (Opsiyonel)", type="password", help="Bu şifre olmadan gizli mesaj filigran olarak görünmez.", key="img_secret_key")
            
            submitted = st.form_submit_button("🔒 Görseli Şifrele ve Kitle", type="primary", use_container_width=True)
            
        if submitted:
            st.session_state.encrypted_bytes = None
            st.session_state.decrypted_image = None
            st.session_state.watermarked_image = None
            
            try:
                # Tarih ve saat birleştirme
                start_dt = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                end_dt_naive = datetime.datetime.strptime(f"{enc_date_end} {enc_time_end}", "%Y-%m-%d %H:%M")
                end_dt = end_dt_naive.replace(tzinfo=TURKISH_TZ).replace(second=0, microsecond=0)
                
                if not uploaded_file:
                    st.error("Lütfen önce bir görsel yükleyin.")
                elif not password:
                    st.error("Lütfen bir şifre belirleyin.")
                elif end_dt <= datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0):
                    st.error("Kilit bitiş zamanı şu anki zamandan ileri olmalıdır.")
                else:
                    progress_bar = st.progress(0, text="Görsel Şifreleniyor...")
                    
                    # Görseli bayt olarak oku
                    image_bytes = uploaded_file.getvalue()
                    
                    encrypted_bytes, meta_bytes = encrypt_image_data(
                        image_bytes, password, start_dt, end_dt, hidden_message, secret_key
                    )
                    
                    if encrypted_bytes and meta_bytes:
                        st.session_state.encrypted_bytes = encrypted_bytes
                        st.session_state.encrypted_meta = meta_bytes
                        
                        progress_bar.progress(100, text="Şifreleme Başarılı!")
                        st.success(f"Görsel Kilidi Kuruldu. Bitiş: **{end_dt.strftime('%d.%m.%Y %H:%M')}**")
                    else:
                        progress_bar.progress(100, text="Hata!")
                        st.error("Şifreleme sırasında bir hata oluştu.")
                        
            except ValueError:
                st.error("Lütfen Bitiş Saati formatını (SS:DD) kontrol edin.")
            except Exception as e:
                st.error(f"Beklenmedik bir hata oluştu: {e}")
                
        if st.session_state.encrypted_bytes:
            st.markdown("---")
            st.subheader("3. Şifreli Dosyaları İndir")
            st.warning("⚠️ Lütfen **hem Şifreli Görsel Dosyasını** hem de **Meta Veri Dosyasını** indirin ve paylaşın.")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.download_button(
                    label="🔒 Şifreli Görseli İndir (.enc)",
                    data=st.session_state.encrypted_bytes,
                    file_name=f"locked_image_{hashlib.sha1(st.session_state.encrypted_bytes).hexdigest()[:8]}.enc",
                    mime="application/octet-stream",
                    use_container_width=True
                )
            
            with col2:
                st.download_button(
                    label="🔑 Meta Veriyi İndir (.meta)",
                    data=st.session_state.encrypted_meta,
                    file_name="image_lock.meta",
                    mime="application/json",
                    use_container_width=True
                )


    with tab_dec:
        st.subheader("1. Şifreli Dosyaları Yükle")
        col_file, col_meta = st.columns(2)
        
        with col_file:
            enc_file_student = st.file_uploader("Şifreli Görseli Yükle (.enc)", type=["enc"], key="img_dec_enc_file")
        with col_meta:
            meta_file_student = st.file_uploader("Meta Veriyi Yükle (.meta)", type=["meta", "json", "txt"], key="img_dec_meta_file")
            
        password_student = st.text_input("Şifre", key="img_dec_pass", type="password")
        
        st.markdown("---")
        
        if st.button("🔓 Kilidi Aç", type="primary", use_container_width=True):
            st.session_state.decrypted_image = None
            st.session_state.watermarked_image = None
            st.session_state.is_message_visible = False
            st.session_state.secret_key_hash = None
            
            if not enc_file_student or not meta_file_student:
                st.error("Lütfen hem şifreli görseli hem de meta veriyi yükleyin.")
            elif not password_student:
                st.error("Lütfen şifreyi girin.")
            else:
                progress_bar = st.progress(0, text="Kilit Açılıyor...")
                
                decrypted_img, caption = decrypt_image_data(
                    enc_file_student.getvalue(), password_student, meta_file_student.getvalue()
                )
                
                progress_bar.progress(100, text="Kontrol Tamamlandı.")
                
                if decrypted_img:
                    st.session_state.decrypted_image = decrypted_img
                    st.session_state.watermarked_image = None # Başlangıçta filigranı gösterme
                
                st.info(caption)
                

    st.markdown("---")
    st.subheader("2. Görüntüleme ve Gizli Mesaj")
    
    # --- Görüntüleme ve İndirme Mantığı (Kullanıcının Verdiği Snippet'ten adapte edildi) ---
    img_display = None
    
    if st.session_state.watermarked_image is not None and st.session_state.is_message_visible:
        img_display = st.session_state.watermarked_image
        caption = "Çözülmüş Görsel (Filigran Görüntüleniyor)"
    elif st.session_state.decrypted_image is not None:
        img_display = st.session_state.decrypted_image
        caption = "Çözülmüş Görsel"
    else:
        caption = "Lütfen önce görselin kilidini açın."
    
    # Görseli göster ve indir düğmesini hazırla
    if img_display is not None:
        st.image(img_display, caption=caption, use_column_width=True)
        
        # Görseli bayt dizisine dönüştür
        img_byte_arr = io.BytesIO()
        img_display.save(img_byte_arr, format='PNG')
        
        if img_byte_arr.getvalue():
            st.download_button(
                label="Görüntülenen Resmi İndir",
                data=img_byte_arr.getvalue(),
                file_name="decrypted_image.png",
                mime="image/png",
                use_container_width=True
            )
    else:
        st.info(caption)
        
    st.markdown("---")
    
    # --- Gizli Mesaj Gösterme Mantığı (Kullanıcının Verdiği Snippet'ten) ---
    
    if st.session_state.decrypted_image is not None and st.session_state.hidden_message:
        if st.session_state.is_message_visible:
            if st.button("Gizli Mesajı Gizle", use_container_width=True): 
                log("Gizli mesaj gizlendi.")
                st.session_state.is_message_visible = False
                st.session_state.prompt_secret_key = False
                st.rerun() # Gerekli değil ama Streamlit'in durumu güncellemesi için kullanılabilir
        
        else:
            if st.session_state.secret_key_hash:
                st.session_state.prompt_secret_key = True
                st.markdown("**Gizli Mesaj Kilitli!**")
                
                modal_pass = st.text_input(
                    "Filigran Şifresi", 
                    type="password", 
                    key="modal_pass_input", 
                    value=st.session_state.modal_pass if st.session_state.modal_pass is not None else '',
                    placeholder="Gizli mesajı görmek için şifreyi girin"
                )
                st.session_state.modal_pass = modal_pass 
                
                if st.button("Filigranı Göster", key="show_watermark_btn", use_container_width=True):
                    if st.session_state.modal_pass:
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
                        st.error("Lütfen şifreyi girin.")

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
                    # Disabled parametresi kaldırıldı, aksi takdirde kullanıcı tekrar indirmek isteyebilir.
                    use_container_width=True
                )
            
            with col_meta:
                st.download_button(
                    label="🔑 Meta Veriyi İndir (.meta)",
                    data=st.session_state.exam_meta_bytes,
                    file_name=f"{base_name}_encrypted.meta",
                    mime="application/json",
                    on_click=lambda: setattr(st.session_state, 'exam_is_meta_downloaded', True),
                    # Disabled parametresi kaldırıldı.
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
                        # meta_file_student = None # Streamlit'te file_uploader'ı bu şekilde sıfırlamak bir sonraki run'da hata verir, sadece hata gösterilir.
                    
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

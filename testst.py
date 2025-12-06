import streamlit as st
import datetime
import pytz
import json
import os
import hashlib
import io
import base64
import time 

# E-posta göndermek için gerekli kütüphane
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

# Gerekli Kriptografi Kütüphanesi
try:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    st.error("Kütüphane Hatası: 'cryptography' kurulu değil. Lütfen terminalde 'pip install cryptography pytz' komutunu çalıştırın.")
    st.stop()


# --- SABİTLER ve İLK AYARLAR ---
TURKISH_TZ = pytz.timezone('Europe/Istanbul')
LOG_FILE = "app_log.txt" 

# ⚠️ UYARI: Bu kısım, e-posta gönderme işlemini yapacak olan SUNUCU (gönderici) hesabının bilgileridir.
# Lütfen buradaki yer tutucu (placeholder) değerleri kendi gerçek SMTP bilgilerinizle değiştirin!
# GMAIL kullanıyorsanız, SENDER_PASSWORD yerine UYGULAMA ŞİFRESİ kullanmalısınız.
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "your_sending_email@gmail.com"  # Cevapları gönderecek olan sunucunun e-postası
SENDER_PASSWORD = "your_app_password"         # Cevapları gönderecek olan sunucunun uygulama şifresi


# --- YARDIMCI FONKSİYONLAR (Değişmedi) ---

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

def init_session_state():
    """Streamlit session state'i başlatır."""
    if 'current_view' not in st.session_state: st.session_state.current_view = 'code' 
    
    if 'exam_enc_bytes' not in st.session_state: st.session_state.exam_enc_bytes = None
    if 'exam_meta_bytes' not in st.session_state: st.session_state.exam_meta_bytes = None
    if 'exam_is_enc_downloaded' not in st.session_state: st.session_state.exam_is_enc_downloaded = False
    if 'exam_is_meta_downloaded' not in st.session_state: st.session_state.exam_is_meta_downloaded = False
    if 'exam_decrypted_bytes' not in st.session_state: st.session_state.exam_decrypted_bytes = None
    if 'original_file_extension' not in st.session_state: st.session_state.original_file_extension = ""
    if 'student_answers_text' not in st.session_state: st.session_state.student_answers_text = "" # Tek kutu için yeni değişken
    if 'exam_ended_tr' not in st.session_state: st.session_state.exam_ended_tr = None
    if 'answers_sent' not in st.session_state: st.session_state.answers_sent = False


def reset_all_inputs():
    """Tüm girdileri ve sonuçları temizler."""
    log("Tüm girdi ve sonuçlar temizlendi (reset_all_inputs).")
    
    st.session_state.exam_enc_bytes = None
    st.session_state.exam_meta_bytes = None
    st.session_state.exam_is_enc_downloaded = False
    st.session_state.exam_is_meta_downloaded = False
    st.session_state.exam_decrypted_bytes = None
    st.session_state.original_file_extension = ""
    st.session_state.student_answers_text = ""
    st.session_state.exam_ended_tr = None
    st.session_state.answers_sent = False
    

def derive_key(input_data, salt_bytes):
    """PBKDF2HMAC kullanarak kriptografik anahtar türetir."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # AES-256 için 32 byte
        salt=salt_bytes,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(input_data.encode('utf-8'))

# ----------------------------- KRİPTOGRAFİ VE İŞLEM FONKSİYONLARI (Değişmedi) -----------------------------

def encrypt_exam_file(file_bytes, access_code, start_time_dt, end_time_dt, question_count, file_name, teacher_email, progress_bar):
    """Sınav dosyasını şifreler ve meta veriyi hazırlar (AES-GCM)."""
    try:
        progress_bar.progress(10, text="Anahtar türetiliyor...")
        
        _, file_extension = os.path.splitext(file_name)
        time_str = normalize_time(start_time_dt) + normalize_time(end_time_dt)
        salt = os.urandom(16) 
        key_bytes = derive_key(access_code, salt)
        
        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(12) 
        aad = time_str.encode('utf-8') 
        
        progress_bar.progress(30, text="Dosya şifreleniyor...")
        encrypted_bytes = aesgcm.encrypt(nonce, file_bytes, aad)
        
        progress_bar.progress(70, text="Meta veri hazırlanıyor...")
        
        access_code_hash = hashlib.sha256(access_code.encode('utf-8')).hexdigest()
        
        meta_data = {
            "type": "EXAM_LOCK",
            "version": "1.5", 
            "start_time": normalize_time(start_time_dt),
            "end_time": normalize_time(end_time_dt),
            "access_code_hash": access_code_hash,
            "nonce_hex": nonce.hex(),
            "salt_hex": salt.hex(),
            "file_size": len(file_bytes),
            "question_count": question_count,
            "original_extension": file_extension,
            "teacher_email": teacher_email 
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
# ----------------------------- E-POSTA GÖNDERİM FONKSİYONU (Değişmedi) -----------------------------

def send_email_to_teacher(teacher_email, student_info, answers_text):
    """Cevapları öğretmenin e-posta adresine gönderir."""
    
    if SENDER_EMAIL == "your_sending_email@gmail.com" or SENDER_PASSWORD == "your_app_password":
        log("E-posta ayarları yapılmamış. Gönderim iptal edildi.")
        return False, "E-posta ayarları (SMTP sunucu ve şifre) yapılmamış. Lütfen kodun başını kontrol edin."

    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = teacher_email
    msg['Subject'] = f"SINAV CEVAPLARI: {student_info}"

    # E-posta gövdesi
    # Cevaplar, JSON yerine doğrudan gövdeye veya ayrı bir TXT dosyası olarak eklenecek.
    body = f"""
    Sayın Öğretmen,

    Aşağıda belirtilen öğrencinin sınav cevapları bulunmaktadır.
    
    Öğrenci Bilgisi: {student_info}
    Gönderim Zamanı: {datetime.datetime.now(TURKISH_TZ).strftime('%d.%m.%Y %H:%M:%S')}
    
    --- CEVAPLAR ---
    {answers_text}
    """
    msg.attach(MIMEText(body, 'plain'))

    # Cevapları bir TXT dosyası olarak ekle (daha temiz bir okuma için)
    try:
        attachment = MIMEApplication(answers_text.encode('utf-8'), _subtype="txt")
        attachment.add_header('Content-Disposition', 'attachment', filename=f"{student_info.replace(' ', '_')}_cevap.txt")
        msg.attach(attachment)
    except Exception as e:
        log(f"TXT ekleme hatası: {e}")
        # Bu aşamada gönderimi kesmiyoruz, sadece ekleme hatasını logluyoruz.

    # E-posta gönderme
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()  
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        text = msg.as_string()
        server.sendmail(SENDER_EMAIL, teacher_email, text)
        server.quit()
        log(f"Cevaplar başarıyla {teacher_email} adresine gönderildi.")
        return True, "Cevaplar başarıyla öğretmeninize iletildi."
    except Exception as e:
        log(f"E-posta gönderme hatası: {e}")
        return False, f"E-posta gönderme hatası: {e}"

# ------------------------------------------------------------------------------------------------

def render_decrypted_content(dec_bytes, file_extension, question_count, teacher_email):
    """Çözülmüş içeriği ekranda indirme yapmadan göstermeye ve tek cevap alanını eklemeye çalışır."""
    
    # 1. SINAV KAĞIDI GÖRÜNTÜLEME
    with st.container(border=True):
        st.subheader("📝 Sınav Kağıdı (Yalnızca Görüntüleme)")
        
        # Görüntüleme mantığı (TXT, PNG, PDF) ... (kısaltıldı)
        if file_extension in [".txt"]:
            try:
                content = dec_bytes.decode('utf-8')
                st.text_area("Sınav Metni", content, height=500, disabled=True)
                st.success("Metin dosyası başarıyla görüntülendi.")
            except Exception:
                st.error("Metin içeriği görüntülenirken bir hata oluştu.")
                
        elif file_extension in [".png", ".jpg", ".jpeg"]:
            try:
                image_stream = io.BytesIO(dec_bytes)
                st.image(image_stream, caption="Çözülmüş Görüntü Dosyası", use_container_width=True)
                st.success("Görüntü dosyası başarıyla görüntülendi.")
            except Exception:
                st.error("Görüntü dosyası görüntülenirken bir hata oluştu.")
                
        elif file_extension in [".pdf"]:
            try:
                base64_pdf = base64.b64encode(dec_bytes).decode('utf-8')
                pdf_display = f'<iframe src="data:application/pdf;base64,{base64_pdf}" width="100%" height="700" type="application/pdf"></iframe>'
                st.markdown(pdf_display, unsafe_allow_html=True)
                st.warning("PDF gösterimi tarayıcı ayarlarınıza bağlıdır ve indirmeyi tamamen engellemez.")
            except Exception:
                st.error("PDF gösterilirken bir hata oluştu.")
            
        else:
            st.warning(f"**{file_extension.upper()}** uzantılı dosya tipi doğrudan tarayıcıda görüntülenemiyor.")

    st.markdown("---")
    
    # 2. TEK CEVAPLAMA ALANI OLUŞTURMA (Yeni Yapı)
    st.subheader("✍️ Cevap Giriş Alanı")
    st.info("Lütfen tüm cevaplarınızı bu tek kutuya, **her soruyu yeni bir satırda ve Soru Numarası** belirterek yazınız.")
    st.caption(f"Örnek Format: `1. Cevabım budur.` `2. İkinci sorunun cevabı da burada.`")
    st.caption(f"Sınav **{question_count}** soruludur. Cevaplar **{teacher_email}** adresine gönderilecektir.")
    
    # Öğrenci Bilgisi Girişi
    student_id = st.text_input("Öğrenci Adı/Numarası", key="student_id_input", help="Cevaplarınızın kime ait olduğunu belirtin.")
    
    # Varsayılan metni oluştur (Kullanıcının işini kolaylaştırmak için)
    default_text = ""
    for i in range(1, question_count + 1):
        default_text += f"{i}. Cevabınızı buraya yazınız.\n"
        
    
    with st.form("answer_submission_form", clear_on_submit=False):
        
        # Tek büyük cevap alanı
        st.session_state.student_answers_text = st.text_area(
            "Tüm Cevaplarınız:", 
            value=st.session_state.student_answers_text if st.session_state.student_answers_text else default_text,
            key="all_answers_area", 
            height=400,
            help="Lütfen formattaki soru numaralarını silmeden cevaplarınızı giriniz."
        )

        submit_button = st.form_submit_button("Cevapları Öğretmene Gönder", type="primary", use_container_width=True, disabled=st.session_state.answers_sent)
        
        if submit_button:
            if not student_id:
                 st.error("Lütfen cevapların kime ait olduğunu belirtmek için Adınızı/Numaranızı girin.")
            elif st.session_state.student_answers_text.strip() == "":
                 st.error("Lütfen cevap alanını doldurun.")
            else:
                final_answers_text = st.session_state.student_answers_text
                
                try:
                    meta_file_name_prefix = st.session_state.exam_dec_meta_file.name.split('_')[0]
                except:
                    meta_file_name_prefix = "bilinmeyen_sinav"
                    
                student_info = f"Öğrenci: {student_id}, Sınav Kod: {meta_file_name_prefix}"
                
                # E-posta gönderme fonksiyonunu çağır (TXT metin gönderiyor)
                success, message = send_email_to_teacher(teacher_email, student_info, final_answers_text)
                
                if success:
                    st.success(f"✅ {message}")
                    st.session_state.answers_sent = True 
                else:
                    st.error(f"❌ Gönderim Hatası: {message}")
                    st.warning("E-posta gönderme ayarları doğru yapılmamış olabilir veya internet bağlantısı sorunu yaşanıyor olabilir.")


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
            
            # Başlangıç Saati
            current_time = datetime.datetime.now(TURKISH_TZ).strftime("%H:%M")
            
            with col_start:
                st.markdown("##### 🔑 Başlangıç Zamanı (Sınav Giriş)")
                enc_date_start = st.date_input("Başlangıç Tarihi", datetime.datetime.now(TURKISH_TZ).date(), key="exam_enc_date_start")
                enc_time_start = st.text_input("Başlangıç Saati (SS:DD)", current_time, key="exam_enc_time_start", help="Örnek: 14:30")
            
            # Bitiş Saati (Düzeltilmiş)
            with col_end:
                st.markdown("##### 🛑 Bitiş Zamanı (Sınav Kapanış)")
                min_date_end = enc_date_start
                enc_date_end = st.date_input("Bitiş Tarihi", enc_date_start, key="exam_enc_date_end", min_value=min_date_end)
                # Varsayılan Bitiş Saati, başlangıç saatiyle aynı ayarlandı.
                enc_time_end = st.text_input("Bitiş Saati (SS:DD)", enc_time_start, key="exam_enc_time_end", help="Lütfen sınav süreniz kadar olan bitiş saatini manuel girin. Örnek: 15:30")

            enc_access_code = st.text_input("Öğrenci Erişim Kodu (Şifre)", value="", key="exam_enc_access_code", type="password", help="Öğrencilerin sınavı indirebilmek için gireceği kod.")
            
            enc_question_count = st.number_input(
                "Sınav Soru Sayısı", 
                min_value=1, 
                value=10, 
                step=1,
                key="exam_enc_question_count",
                help="Sınavdaki toplam soru sayısını girin."
            )
            
            # Öğretmen E-posta Adresi 
            TEACHER_EMAIL_DEFAULT = "19enes03.kurtulus@gmail.com"
            enc_teacher_email = st.text_input(
                "Cevapların Gönderileceği Öğretmen E-postası",
                value=TEACHER_EMAIL_DEFAULT,
                key="exam_enc_teacher_email",
                help="Öğrenci cevaplarının otomatik olarak gönderileceği e-posta adresi."
            )
            
            submitted = st.form_submit_button("🔒 Sınavı Kilitle ve Hazırla", type="primary", use_container_width=True)

        if submitted:
            reset_all_inputs() 
            
            try:
                # Zaman formatı kontrolü...
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
                elif not enc_teacher_email or "@" not in enc_teacher_email:
                    st.error("Lütfen cevapların gönderileceği geçerli bir e-posta adresi girin.")
                elif end_dt <= now_tr:
                    st.error("Bitiş zamanı şu anki zamandan ileri olmalıdır.")
                elif end_dt <= start_dt:
                    st.error("Bitiş zamanı, başlangıç zamanından sonra olmalıdır.")
                elif enc_question_count <= 0:
                    st.error("Soru sayısı pozitif bir değer olmalıdır.")
                else:
                    progress_bar = st.progress(0, text="Sınav Şifreleniyor...")
                    
                    enc_bytes, meta_bytes = encrypt_exam_file(
                        uploaded_file.getvalue(), enc_access_code, start_dt, end_dt, enc_question_count, uploaded_file.name, enc_teacher_email, progress_bar
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
                st.download_button(
                    label="📝 Şifreli Sınavı İndir (.png)",
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
        
        # Sınav bitmişse, tüm akışı durdur
        if st.session_state.exam_ended_tr:
            st.error(f"🛑 SINAV SÜRESİ DOLDU! 🛑")
            st.warning(f"Sınav **{st.session_state.exam_ended_tr}** itibarıyla sona ermiştir. Görüntüleme ve cevaplama ekranı kapatılmıştır. Öğretmeninizle iletişime geçin.")
            return
            
        
        st.subheader("1. Sınav Dosyalarını Yükle")
        
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
        question_count_student = 0
        original_extension = ""
        teacher_email_student = ""
        end_dt = None
        
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
                        question_count_student = meta.get("question_count", "Bilinmiyor") 
                        original_extension = meta.get("original_extension", "") 
                        teacher_email_student = meta.get("teacher_email", "BILINMIYOR") 
                        
                        start_dt = parse_normalized_time(start_time_str)
                        end_dt = parse_normalized_time(end_time_str) 
                        now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                        
                        is_too_early = now_tr < start_dt
                        is_too_late = now_tr > end_dt
                        is_active = start_dt <= now_tr <= end_dt
                        
                        st.info(f"Başlangıç: **{start_dt.strftime('%d.%m.%Y %H:%M')}** | Bitiş: **{end_dt.strftime('%d.%m.%Y %H:%M')}**")
                        
                        col_qc, col_ext = st.columns(2)
                        with col_qc:
                            st.markdown(f"**Toplam Soru Sayısı:** **{question_count_student}**")
                        with col_ext:
                            st.markdown(f"**Dosya Tipi:** **{original_extension.upper() if original_extension else 'Bilinmiyor'}**")
                        
                        if is_too_early:
                            time_left = start_dt - now_tr
                            st.warning(f"🔓 Sınav Henüz Başlamadı! Kalan süre: **{time_left.days} gün {time_left.seconds//3600} saat {(time_left.seconds%3600)//60} dakika**")
                        elif is_too_late:
                            if st.session_state.exam_ended_tr is None:
                                st.session_state.exam_ended_tr = end_dt.strftime('%d.%m.%Y %H:%M')
                                st.rerun() 
                            st.error("🛑 Sınav Sona Erdi! Dosyayı çözemezsiniz.")
                        elif is_active:
                            time_left = end_dt - now_tr
                            st.success(f"✅ Sınav Aktif! Kalan süre: **{time_left.days} gün {time_left.seconds//3600} saat {(time_left.seconds%3600)//60} dakika**")
                        
                        
                except Exception as e:
                    st.error(f"Meta dosya okuma hatası veya geçersiz format: {e}")


        if st.button("🔓 Sınavı Görüntüle ve Başla", type="primary", use_container_width=True):
            st.session_state.exam_decrypted_bytes = None
            st.session_state.original_file_extension = original_extension
            st.session_state.student_answers_text = "" # Cevap metnini sıfırla
            st.session_state.answers_sent = False 
            
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
                        st.session_state.original_file_extension = original_extension 
                        
                        try:
                            q_count = int(question_count_student)
                        except:
                            q_count = 10 
                            
                        # Cevap alanını sorulara göre hazırlar (İlk çalıştırmada varsayılan metni oluşturur)
                        st.session_state.student_answers_text = ""
                        for i in range(1, q_count + 1):
                            st.session_state.student_answers_text += f"{i}. Cevabınızı buraya yazınız.\n"
                        
                        st.rerun() 
                    else:
                        st.error("Çözme hatası. Lütfen dosyaları ve erişim kodunu kontrol edin.")
        
        
        # --- GÖRÜNTÜLEME VE CEVAPLAMA BÖLÜMÜ (Öğrenci) ---
        if st.session_state.exam_decrypted_bytes:
            # Sınavın bitip bitmediğini kontrol et (anlık kontrol)
            now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
            if end_dt and now_tr > end_dt:
                if st.session_state.exam_ended_tr is None:
                    st.session_state.exam_ended_tr = end_dt.strftime('%d.%m.%Y %H:%M')
                    st.rerun() 
            
            if st.session_state.exam_ended_tr is None:
                try:
                    q_count = int(question_count_student)
                except:
                    q_count = 10
                    
                render_decrypted_content(
                    st.session_state.exam_decrypted_bytes, 
                    st.session_state.original_file_extension,
                    q_count,
                    teacher_email_student
                )
            
            
# --- ANA AKIŞ ---

init_session_state()

st.set_page_config(page_title="Zaman Ayarlı Sınav Kilit Uygulaması", layout="wide", initial_sidebar_state="expanded")
st.title("👨‍🏫 Zaman Ayarlı Sınav Kilit Sistemi")
st.caption("AES-GCM ve Streamlit ile zaman kilitli sınav şifreleme modülü.")

# Kenar çubuğu (Sidebar)
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/d/d4/Istanbul_Time_Zone.svg/1200px-Istanbul_Time_Zone.svg.png", width=100)
    st.markdown("## ⚙️ Uygulama Ayarları")
    
    st.markdown("---")
    
    st.button("Tüm Verileri Temizle", on_click=reset_all_inputs, use_container_width=True, help="Tüm girdileri ve sonuçları siler.")
    
    st.markdown("---")
    st.markdown("##### 🇹🇷 Türk Saat Dilimi (UTC+03)")
    now_tr = datetime.datetime.now(TURKISH_TZ).strftime("%d.%m.%Y %H:%M:%S")
    st.write(f"Şu anki zaman: **{now_tr}**")


# Ana İçerik
render_code_module()

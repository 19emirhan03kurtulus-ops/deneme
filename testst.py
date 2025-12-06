import streamlit as st
import datetime
import pytz
import json
import os
import hashlib
import io

# Gerekli Kriptografi Kütüphanesi
# Eğer "ModuleNotFoundError" hatası alırsanız, terminalde: pip install cryptography pytz
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

def init_session_state():
    """Streamlit session state'i başlatır."""
    if 'current_view' not in st.session_state: st.session_state.current_view = 'code' 
    
    # Sınav sistemine özgü state'ler
    if 'exam_enc_bytes' not in st.session_state: st.session_state.exam_enc_bytes = None
    if 'exam_meta_bytes' not in st.session_state: st.session_state.exam_meta_bytes = None
    if 'exam_is_enc_downloaded' not in st.session_state: st.session_state.exam_is_enc_downloaded = False
    if 'exam_is_meta_downloaded' not in st.session_state: st.session_state.exam_is_meta_downloaded = False
    if 'exam_decrypted_bytes' not in st.session_state: st.session_state.exam_decrypted_bytes = None


def reset_all_inputs():
    """Tüm girdileri ve sonuçları temizler."""
    log("Tüm girdi ve sonuçlar temizlendi (reset_all_inputs).")
    
    st.session_state.exam_enc_bytes = None
    st.session_state.exam_meta_bytes = None
    st.session_state.exam_is_enc_downloaded = False
    st.session_state.exam_is_meta_downloaded = False
    st.session_state.exam_decrypted_bytes = None
    
# --- KRİPTOGRAFİ VE İŞLEM FONKSİYONLARI ---

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

# ----------------------------- SINAV SİSTEMİ YARDIMCI FONKSİYONLARI -----------------------------

def encrypt_exam_file(file_bytes, access_code, start_time_dt, end_time_dt, question_count, progress_bar):
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
        
        # 3. Meta Veri Oluşturma (question_count eklendi)
        access_code_hash = hashlib.sha256(access_code.encode('utf-8')).hexdigest()
        
        meta_data = {
            "type": "EXAM_LOCK",
            "version": "1.2", # Versiyon güncellendi
            "start_time": normalize_time(start_time_dt),
            "end_time": normalize_time(end_time_dt),
            "access_code_hash": access_code_hash,
            "nonce_hex": nonce.hex(),
            "salt_hex": salt.hex(),
            "file_size": len(file_bytes),
            "question_count": question_count, # Soru sayısı eklendi
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
            
            # YENİ EKLENEN KISIM: Soru Sayısı Girişi
            enc_question_count = st.number_input(
                "Sınav Soru Sayısı", 
                min_value=1, 
                value=10, 
                step=1,
                key="exam_enc_question_count",
                help="Sınavdaki toplam soru sayısını girin. Öğrenci ekranında görünecektir."
            )
            
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
                elif enc_question_count <= 0:
                    st.error("Soru sayısı pozitif bir değer olmalıdır.")
                else:
                    progress_bar = st.progress(0, text="Sınav Şifreleniyor...")
                    
                    enc_bytes, meta_bytes = encrypt_exam_file(
                        uploaded_file.getvalue(), enc_access_code, start_dt, end_dt, enc_question_count, progress_bar
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
                        question_count_student = meta.get("question_count", "Bilinmiyor") # Soru sayısı alındı
                        
                        start_dt = parse_normalized_time(start_time_str)
                        end_dt = parse_normalized_time(end_time_str)
                        now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                        
                        is_too_early = now_tr < start_dt
                        is_too_late = now_tr > end_dt
                        is_active = start_dt <= now_tr <= end_dt
                        
                        st.info(f"Başlangıç: **{start_dt.strftime('%d.%m.%Y %H:%M')}** | Bitiş: **{end_dt.strftime('%d.%m.%Y %H:%M')}**")
                        
                        # Soru Sayısı Gösterimi
                        st.markdown(f"**Toplam Soru Sayısı:** **{question_count_student}**")
                        
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
            
            # Orijinal dosya uzantısını yeniden oluşturmak için tahmin yapılır
            original_file_name = enc_file_student.name.replace("_encrypted.png", "") if enc_file_student else "decrypted_exam"
            file_extension = ""
            
            if any(ext in original_file_name.lower() for ext in [".pdf", ".docx", ".txt", ".zip", ".jpg", ".png"]):
                file_extension = os.path.splitext(original_file_name)[1]
            else:
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

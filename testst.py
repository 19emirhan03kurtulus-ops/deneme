import streamlit as st
import datetime
import pytz
import json
import os
import hashlib
import io
import pandas as pd

# --- GEREKLİ KRİPTOGRAFİ VE DİĞER KÜTÜPHANELER ---
try:
    # 'cryptography' kütüphanesi kontrolü (image_3850a4.png hatası çözümü)
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from PIL import Image 
except ImportError:
    st.error("🚨 KRİTİK KÜTÜPHANE HATASI: 'cryptography' kurulu değil. Lütfen terminalde **'pip install cryptography Pillow pandas'** komutunu çalıştırın ve uygulamayı yeniden başlatın.")
    st.stop()


# --- SABİTLER ve İLK AYARLAR ---
TURKISH_TZ = pytz.timezone('Europe/Istanbul')
LOG_FILE = "app_log.txt" 

# --- YARDIMCI VE ZAMAN FONKSİYONLARI ---

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
    if dt_object.tzinfo is not None and dt_object.utcoffset(dt_object) is not None:
        dt_object = dt_object.astimezone(pytz.utc)
    return dt_object.strftime("%Y-%m-%d %H:%M")

def parse_normalized_time(time_str):
    """Normalize edilmiş UTC zamanını TZ-aware TR zamanına dönüştürür."""
    dt_naive = datetime.datetime.strptime(time_str, "%Y-%m-%d %H:%M")
    return dt_naive.replace(tzinfo=pytz.utc).astimezone(TURKISH_TZ)

def init_session_state():
    """Streamlit session state'i başlatır."""
    if 'exam_enc_bytes' not in st.session_state: st.session_state.exam_enc_bytes = None
    if 'exam_meta_bytes' not in st.session_state: st.session_state.exam_meta_bytes = None
    if 'exam_is_unlocked' not in st.session_state: st.session_state.exam_is_unlocked = False 
    if 'exam_total_questions' not in st.session_state: st.session_state.exam_total_questions = 0 
    if 'exam_current_meta' not in st.session_state: st.session_state.exam_current_meta = {} 
    
    # Formları ve yükleyicileri temizlemek için sayaç (Streamlit'in form yönetiminde kritik)
    if 'reset_counter' not in st.session_state: st.session_state.reset_counter = 0 


def reset_all_inputs():
    """Tüm girdileri ve sonuçları temizler ve uygulamayı yeniden başlatır."""
    log("Tüm girdi ve sonuçlar temizlendi (reset_all_inputs).")
    
    st.session_state.exam_enc_bytes = None
    st.session_state.exam_meta_bytes = None
    st.session_state.exam_is_unlocked = False
    st.session_state.exam_total_questions = 0
    st.session_state.exam_current_meta = {}
    
    st.session_state.reset_counter += 1
    st.rerun()

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

def encrypt_exam_file(file_bytes, access_code, start_time_dt, end_time_dt, total_question_count, progress_bar):
    """Sınav dosyasını şifreler ve meta veriyi hazırlar (AES-GCM)."""
    # name 'encrypt_exam_file' is not defined (image_384146.png, image_37d482.png) hatası çözüldü
    try:
        progress_bar.progress(10, text="Anahtar türetiliyor...")
        
        time_str = normalize_time(start_time_dt) + normalize_time(end_time_dt)
        salt = os.urandom(16) 
        key_bytes = derive_key(access_code, salt)
        
        aesgcm = AESGCM(key_bytes)
        nonce = os.urandom(12) 
        aad = time_str.encode('utf-8') 
        
        progress_bar.progress(30, text="Dosya şifreleniyor...")
        
        # Dosyayı şifrele
        encrypted_bytes = aesgcm.encrypt(nonce, file_bytes, aad)
        
        progress_bar.progress(70, text="Meta veri hazırlanıyor...")
        
        access_code_hash = hashlib.sha256(access_code.encode('utf-8')).hexdigest()
        
        meta_data = {
            "type": "EXAM_LOCK",
            "version": "1.3", 
            "start_time": normalize_time(start_time_dt),
            "end_time": normalize_time(end_time_dt),
            "access_code_hash": access_code_hash,
            "nonce_hex": nonce.hex(),
            "salt_hex": salt.hex(),
            "total_questions": total_question_count, 
            "file_size": len(file_bytes),
        }
        
        meta_bytes = json.dumps(meta_data, indent=4).encode('utf-8')
        progress_bar.progress(100, text="Sınav Hazır!")
        
        return encrypted_bytes, meta_bytes

    except Exception as e:
        # Kitleme sırasında oluşan hatalar için (image_6a983a.png, image_812a43.png, image_80c085.png) net hata mesajı
        log(f"Sınav Şifreleme Hatası: {e}")
        progress_bar.progress(100, text="Hata oluştu!")
        st.error(f"Sınav kitleme sırasında kritik bir hata oluştu: **{type(e).__name__}**. Lütfen dosya formatını, erişim kodunu ve diğer girdileri kontrol edin.")
        return None, None 

def decrypt_exam_file(encrypted_bytes, access_code, meta, progress_bar):
    """Şifrelenmiş sınav dosyasını çözmeye çalışır (bütünlük kontrolü için)."""
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

def render_code_module():
    """Zaman ayarlı sınav kilit modülünü render eder."""
    
    st.markdown("## 👨‍🏫 Zaman Ayarlı Sınav Kilit Sistemi")
    st.markdown("---")

    tab_teacher, tab_student = st.tabs(["Öğretmen (Sınav Hazırlama)", "Öğrenci (Sınavı Çözme)"])

    # --- ÖĞRETMEN SEKMESİ ---
    with tab_teacher:
        st.subheader("1. Sınav Dosyasını Yükle ve Kitle")
        
        with st.form(f"exam_encrypt_form_{st.session_state.reset_counter}", clear_on_submit=False):
            
            # Sınav dosyası yükleyicisi
            uploaded_file = st.file_uploader(
                "Sınav dosyasını seçin (PDF, DOCX, TXT, resim vb.)", 
                type=["png"], 
                key=f"exam_enc_file_upload_{st.session_state.reset_counter}"
            )
            
            col_start, col_end = st.columns(2)
            
            with col_start:
                st.markdown("##### 🔑 Başlangıç Zamanı (Sınav Giriş)")
                current_dt = datetime.datetime.now(TURKISH_TZ)
                enc_date_start = st.date_input("Başlangıç Tarihi", current_dt.date(), key=f"exam_enc_date_start_{st.session_state.reset_counter}")
                enc_time_start = st.text_input("Başlangıç Saati (SS:DD)", current_dt.strftime("%H:%M"), key=f"exam_enc_time_start_{st.session_state.reset_counter}", help="Örnek: 14:30")
            
            with col_end:
                st.markdown("##### 🛑 Bitiş Zamanı (Sınav Kapanış)")
                default_end_dt = current_dt + datetime.timedelta(hours=1)
                enc_date_end = st.date_input("Bitiş Tarihi", default_end_dt.date(), key=f"exam_enc_date_end_{st.session_state.reset_counter}", min_value=enc_date_start)
                enc_time_end = st.text_input("Bitiş Saati (SS:DD)", default_end_dt.strftime("%H:%M"), key=f"exam_enc_time_end_{st.session_state.reset_counter}", help="Örnek: 15:30")

            total_questions = st.number_input(
                "Toplam Soru Sayısı", 
                min_value=1, 
                max_value=100, 
                value=20, 
                step=1, 
                key=f"total_question_count_input_{st.session_state.reset_counter}",
                help="Öğrencinin cevaplayacağı soru sayısı."
            )
            
            enc_access_code = st.text_input("Öğrenci Erişim Kodu (Şifre)", value="", key=f"exam_enc_access_code_{st.session_state.reset_counter}", type="password", help="Öğrencilerin sınavı çözebilmek için gireceği kod.")
            
            submitted = st.form_submit_button("🔒 Sınavı Kilitle ve Hazırla", type="primary", use_container_width=True)

        if submitted:
            st.session_state.exam_enc_bytes = None
            st.session_state.exam_meta_bytes = None
            
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
                
                if not uploaded_file:
                    st.error("Lütfen önce bir sınav dosyası yükleyin.")
                elif not enc_access_code:
                    st.error("Lütfen bir erişim kodu belirleyin.")
                elif end_dt <= start_dt:
                    st.error("Bitiş zamanı, başlangıç zamanından sonra olmalıdır.")
                elif total_questions <= 0:
                    st.error("Toplam soru sayısı 1'den büyük olmalıdır.")
                else:
                    progress_bar = st.progress(0, text="Sınav Şifreleniyor...")
                    
                    enc_bytes, meta_bytes = encrypt_exam_file(
                        uploaded_file.getvalue(), enc_access_code, start_dt, end_dt, total_questions, progress_bar
                    )
                    
                    if enc_bytes and meta_bytes:
                        st.success(f"Sınav Başarıyla Hazırlandı! Başlangıç: **{start_dt.strftime('%d.%m.%Y %H:%M')}** | Bitiş: **{end_dt.strftime('%d.%m.%Y %H:%M')}** | Soru Sayısı: **{total_questions}**")
                        st.session_state.exam_enc_bytes = enc_bytes
                        st.session_state.exam_meta_bytes = meta_bytes

            except Exception as e:
                log(f"Form Dışı Beklenmedik Hata: {e}")
                st.error(f"Beklenmedik bir hata oluştu: {e}")

        # --- İndirme Bölümü (Öğretmen) ---
        if st.session_state.exam_enc_bytes and st.session_state.exam_meta_bytes:
            st.markdown("---")
            st.subheader("2. Dosyaları İndir ve Paylaş")
            st.warning("⚠️ Lütfen **hem Şifreli Sınav Dosyasını** (.png) hem de **Sınav Meta Verisini** (.meta) indirip öğrencilerinizle paylaşın.")
            
            base_name = os.path.splitext(uploaded_file.name)[0] if uploaded_file else "sinav"
            
            col_enc, col_meta = st.columns(2)
            
            with col_enc:
                st.download_button(
                    label="📝 Şifreli Sınav Dosyasını İndir (.png)",
                    data=st.session_state.exam_enc_bytes,
                    file_name=f"{base_name}_encrypted.png", 
                    mime="image/png", 
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
        st.subheader("1. Sınav Kilidini Aç")
        
        col_file, col_meta = st.columns(2)
        
        with col_file:
            # files are not allowed (image_820ee3.png) hatası çözümü: Öğretmen PNG indirdiği için, öğrenci de PNG yüklemelidir.
            enc_file_student = st.file_uploader("Şifreli Sınav Dosyasını Yükle (.png)", type=["png"], key=f"exam_dec_enc_file_{st.session_state.reset_counter}")
        with col_meta:
            meta_file_student = st.file_uploader("Sınav Meta Verisini Yükle (.meta)", type=["meta", "json", "txt"], key=f"exam_dec_meta_file_{st.session_state.reset_counter}")
            
        access_code_student = st.text_input("Öğrenci Erişim Kodu", key=f"exam_dec_access_code_{st.session_state.reset_counter}", type="password")
        
        st.markdown("---")
        
        # Meta Veri Okuma ve Zaman Kontrolü
        meta_data_available = False
        meta = {}
        is_active = False
        
        if meta_file_student:
            with st.container(border=True):
                try:
                    meta = json.loads(meta_file_student.getvalue().decode('utf-8'))
                    st.session_state.exam_current_meta = meta 
                    
                    if meta.get("type") != "EXAM_LOCK":
                        st.error("Yüklenen meta dosyası bir Sınav Kilidi dosyası değil.")
                        meta_file_student = None
                        
                    else:
                        meta_data_available = True
                        start_time_str = meta.get("start_time")
                        end_time_str = meta.get("end_time")
                        st.session_state.exam_total_questions = meta.get("total_questions", 0) 
                        
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
            st.session_state.exam_is_unlocked = False 
            
            if not enc_file_student or not meta_file_student:
                st.error("Lütfen hem şifreli sınav dosyasını (.png) hem de meta veriyi (.meta) yükleyin.")
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
                        st.session_state.exam_is_unlocked = True
                        st.success("Sınav kilidi başarıyla açıldı! Aşağıdaki cevap formunu doldurun.")
                        st.balloons()
        
        st.markdown("---")
        
        # --- Cevap Formu Bölümü ---
        if st.session_state.exam_is_unlocked and st.session_state.exam_total_questions > 0:
            
            st.subheader(f"2. Sınav Cevap Formu ({st.session_state.exam_total_questions} Soru)")
            st.warning("Sınav dosyasını (**PNG dosyasını**) manuel olarak açıp soruları gördükten sonra buraya cevaplarınızı giriniz.")

            with st.form(f"exam_answer_form_{st.session_state.reset_counter}"):
                answers = {}
                cols_per_row = 4 

                # Dinamik olarak cevap alanları oluşturma
                for i in range(1, st.session_state.exam_total_questions + 1):
                    col_index = (i - 1) % cols_per_row
                    if col_index == 0:
                        cols = st.columns(cols_per_row)

                    answer = cols[col_index].text_input(f"Soru {i}", key=f"answer_{i}_{st.session_state.reset_counter}", max_chars=1, help="Sadece A, B, C, D veya E giriniz.")
                    answers[f"Soru_{i}"] = answer

                st.markdown("---")
                student_id = st.text_input("Öğrenci Numarası", max_chars=10, key=f"student_id_input_{st.session_state.reset_counter}")
                student_name = st.text_input("Adınız Soyadınız", key=f"student_name_input_{st.session_state.reset_counter}")

                submit_answers = st.form_submit_button("Cevapları Gönder/İndir", type="secondary", use_container_width=True)

                if submit_answers:
                    if not student_id or not student_name:
                        st.error("Lütfen öğrenci numaranızı ve adınızı soyadınızı giriniz.")
                    else:
                        answer_data = {
                            "Öğrenci No": student_id,
                            "Ad Soyad": student_name,
                            "Sınav Başlangıç": st.session_state.exam_current_meta.get("start_time"),
                            "Sınav Bitiş": st.session_state.exam_current_meta.get("end_time"),
                            "Gönderim Zamanı": datetime.datetime.now(TURKISH_TZ).strftime("%Y-%m-%d %H:%M:%S"),
                        }
                        answer_data.update(answers)

                        df = pd.DataFrame([answer_data])
                        csv = df.to_csv(index=False).encode('utf-8')
                        
                        st.download_button(
                            label="📥 Cevap Dosyasını İndir (CSV)",
                            data=csv,
                            file_name=f"{student_id}_cevaplar_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.csv",
                            mime="text/csv",
                            help="Bu dosyayı indirin ve öğretmeninizle paylaşın.",
                            use_container_width=True
                        )
                        st.success("Cevaplarınız başarıyla indirildi. Lütfen bu dosyayı öğretmeninizle paylaşın.")
                        
                        # Cevapları gönderdikten sonra formu temizle
                        reset_all_inputs()


# --- ANA AKIŞ ---

init_session_state()

st.set_page_config(page_title="Zaman Ayarlı Sınav Kilit Sistemi", layout="wide", initial_sidebar_state="expanded")
st.title("👨‍🏫 Zaman Ayarlı Sınav Kilit Sistemi")
st.caption("Bu sistem, sınav dosyasını şifreler ve sadece belirlenen zaman aralığında doğru kod ile açılmasına izin verir.")

# Kenar çubuğu (Sidebar)
with st.sidebar:
    st.image("https://upload.wikimedia.org/wikipedia/commons/thumb/d/d4/Istanbul_Time_Zone.svg/1200px-Istanbul_Time_Zone.svg.png", width=100)
    st.markdown("## ⚙️ Uygulama Ayarları")
        
    st.markdown("---")
    
    # Tüm verileri temizle butonu (reset_all_inputs çağrıldığında st.rerun ile tüm state temizlenir)
    if st.button("Tüm Verileri Temizle", on_click=reset_all_inputs, use_container_width=True, help="Tüm girdileri, yüklenen dosyaları ve sonuçları siler."):
        st.stop() 

    
    st.markdown("---")
    st.markdown("##### 🇹🇷 Türk Saat Dilimi (UTC+03)")
    now_tr = datetime.datetime.now(TURKISH_TZ).strftime("%d.%m.%Y %H:%M:%S")
    st.write(f"Şu anki zaman: **{now_tr}**")


# Ana İçerik: Sadece Sınav Modülü
render_code_module()



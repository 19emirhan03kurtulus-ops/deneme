import streamlit as st
import datetime
import pytz
import hashlib
import json
import base64
import io
import os
import time

# --- Konfigürasyon ve Sabitler ---
# Türk saat dilimi tanımı
TURKISH_TZ = pytz.timezone('Europe/Istanbul')

# --- Helper Fonksiyonlar ---

# Loglama fonksiyonu (isteğe bağlı olarak kaldırılabilir)
def log(message):
    # print(f"[{datetime.datetime.now(TURKISH_TZ).strftime('%H:%M:%S')}] {message}")
    pass

# Keystream Oluşturucu
def create_keystream(key_hex, width, height):
    """
    Belirli bir anahtar hash'i ve boyutlar için deterministik bir anahtar akışı (keystream) oluşturur.
    """
    key_bytes = bytes.fromhex(key_hex)
    key_len = len(key_bytes)
    
    # Keystream'in toplam boyutu
    ks_len = width * height
    ks = bytearray(ks_len)
    
    # Basit bir deterministik Keystream üretimi
    for i in range(ks_len):
        ks[i] = key_bytes[i % key_len] ^ (i & 0xFF) ^ (key_bytes[(i // key_len) % key_len])
        
    return ks

# CSS stili ekleme fonksiyonu
def add_custom_css():
    """
    Uygulamaya özel CSS stillerini ekler.
    """
    CUSTOM_CSS = """
    <style>
        .stButton>button {
            border-radius: 8px;
            font-weight: bold;
            transition: all 0.3s;
        }
        .stButton>button:hover {
            opacity: 0.9;
            transform: translateY(-2px);
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 16px;
        }
        .stTabs [data-baseweb="tab"] {
            height: 40px;
            white-space: nowrap;
            background-color: #f0f2f6;
            border-radius: 8px 8px 0 0;
            padding: 0px 20px;
            border-bottom: 2px solid transparent;
        }
        .stTabs [aria-selected="true"] {
            background-color: #ffffff;
            border-bottom: 2px solid #005f99;
            color: #005f99;
            font-weight: bold;
        }
        /* Sidebar'da daha iyi görünüm için */
        section[data-testid="stSidebar"] div.stRadio > label:nth-child(2) {
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px dashed #cccccc;
        }
        /* İndirme butonu stilini düzenleme */
        div[data-testid="stDownloadButton"] > button {
            background-color: #388e3c;
            color: white;
        }
        div[data-testid="stDownloadButton"] > button:hover {
            background-color: #2e7d32;
        }
    </style>
    """
    st.markdown(CUSTOM_CSS, unsafe_allow_html=True)

# Geri dönme butonu için
def set_view(view):
    st.session_state.current_view = view

# Görüntü şifreleme fonksiyonu (ORİJİNAL KOD)
def encrypt_image_file(image_bytes, open_time_dt, key, progress_bar):
    log("Görüntü şifreleme başlatıldı.")
    try:
        # Anahtar ve zaman hash'ini oluşturma
        key_source = key.encode("utf-8") + open_time_dt.strftime("%Y%m%d%H%M").encode("utf-8")
        key_hex = hashlib.sha256(key_source).hexdigest()
        
        # Görüntünün boyutlarını belirlemek için basitleştirilmiş bir yaklaşım
        # Gerçek Streamlit uygulamasında görüntü boyutu almak karmaşıktır. Basitçe dosya boyutunu kullanıyoruz.
        file_len = len(image_bytes)
        ks = create_keystream(key_hex, file_len, 1) # Genişlik=Dosya Uzunluğu, Yükseklik=1
        
        # XOR Şifreleme
        encrypted_bytes = bytearray(image_bytes)
        for i in range(file_len):
            encrypted_bytes[i] ^= ks[i]
            if i % (file_len // 10) == 0:
                progress_bar.progress(i / file_len, text="Şifreleniyor...")
        
        # Meta Veri Hazırlama
        meta = {
            "version": 1.0,
            "type": "IMAGE_LOCK",
            "open_time": open_time_dt.strftime("%Y-%m-%d %H:%M"),
            "key_hash": hashlib.sha256(key.encode('utf-8')).hexdigest(),
            "file_hash": hashlib.sha256(image_bytes).hexdigest(),
            "verify_tag": hashlib.sha256(key_hex.encode("utf-8") + bytes(encrypted_bytes)).hexdigest()
        }
        meta_bytes = json.dumps(meta, indent=4).encode('utf-8')
        
        progress_bar.progress(1.0, text="Şifreleme Tamamlandı!")
        return bytes(encrypted_bytes), meta_bytes

    except Exception as e:
        log(f"Görüntü şifreleme hatası: {e}")
        progress_bar.progress(1.0, text="Hata Oluştu!")
        st.error(f"Görüntüyü şifrelerken bir hata oluştu: {e}")
        return None, None

# Görüntü çözme fonksiyonu (ORİJİNAL KOD)
def decrypt_image_in_memory(encrypted_bytes, key, meta, progress_bar):
    log("Görüntü çözme başlatıldı.")
    try:
        # Meta veriden zamanı al
        open_time_str = meta.get("open_time")
        
        # Doğrulama Anahtarını yeniden oluştur
        key_source = key.encode("utf-8") + datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M").strftime("%Y%m%d%H%M").encode("utf-8")
        key_hex = hashlib.sha256(key_source).hexdigest()
        
        # Keystream oluşturma
        file_len = len(encrypted_bytes)
        ks = create_keystream(key_hex, file_len, 1)

        # XOR Çözme
        decrypted_bytes = bytearray(encrypted_bytes)
        for i in range(file_len):
            decrypted_bytes[i] ^= ks[i]
            if i % (file_len // 10) == 0:
                progress_bar.progress(i / file_len, text="Çözülüyor...")

        # Integrity Check (Dosya Hash'i)
        calculated_file_hash = hashlib.sha256(bytes(decrypted_bytes)).hexdigest()
        stored_file_hash = meta.get("file_hash")
        
        if calculated_file_hash != stored_file_hash:
             log("Çözme Hatası: Dosya bütünlüğü bozuk.")
             st.error("Çözme Hatası: Yanlış anahtar girildi veya dosya bozulmuş.")
             return None

        progress_bar.progress(1.0, text="Çözme Tamamlandı!")
        return bytes(decrypted_bytes)

    except Exception as e:
        log(f"Görüntü çözme hatası: {e}")
        st.error(f"Görüntü çözme sırasında beklenmedik bir hata oluştu: {e}")
        return None

# --- YENİ SINAV SİSTEMİ FONKSİYONLARI (EKLEME) ---

# Yeni Sınav Şifreleme Fonksiyonu
def encrypt_exam_file(file_bytes, access_code, start_time_dt, end_time_dt, progress_bar):
    log("Sınav dosyası şifreleme başlatıldı.")
    try:
        # XOR şifreleme anahtarı, erişim kodundan ve başlangıç zamanının hash'inden türetilir.
        key_source = access_code.encode("utf-8") + start_time_dt.strftime("%Y%m%d%H%M").encode("utf-8")
        key_hex = hashlib.sha256(key_source).hexdigest()
        
        log(f"Oluşturulan Anahtar Hash'i: {key_hex[:10]}...")
        
        # Keystream oluşturma (Sadece dosya uzunluğu baz alınır)
        file_len = len(file_bytes)
        ks = create_keystream(key_hex, file_len, 1) # Genişlik=Dosya Uzunluğu, Yükseklik=1
        
        # XOR Şifreleme
        encrypted_bytes = bytearray(file_bytes)
        for i in range(file_len):
            encrypted_bytes[i] ^= ks[i]
            if i % (file_len // 10) == 0:
                progress_bar.progress(i / file_len, text="Şifreleniyor...")
        
        # Meta Veri Hazırlama
        # Sınav için hem başlangıç hem de bitiş zamanı kaydedilir.
        meta = {
            "version": 2.0,
            "type": "EXAM_LOCK",
            "access_code_hash": hashlib.sha256(access_code.encode('utf-8')).hexdigest(),
            "start_time": start_time_dt.strftime("%Y-%m-%d %H:%M"),
            "end_time": end_time_dt.strftime("%Y-%m-%d %H:%M"),
            "file_hash": hashlib.sha256(file_bytes).hexdigest(),
            "verify_tag": hashlib.sha256(key_hex.encode("utf-8") + bytes(encrypted_bytes)).hexdigest()
        }
        meta_bytes = json.dumps(meta, indent=4).encode('utf-8')
        
        progress_bar.progress(1.0, text="Şifreleme Tamamlandı!")
        return bytes(encrypted_bytes), meta_bytes

    except Exception as e:
        log(f"Sınav şifreleme hatası: {e}")
        progress_bar.progress(1.0, text="Hata Oluştu!")
        st.error(f"Sınav dosyasını şifrelerken bir hata oluştu: {e}")
        return None, None

# Yeni Sınav Çözme Fonksiyonu
def decrypt_exam_file(encrypted_bytes, access_code, meta, progress_bar):
    log("Sınav dosyası çözme başlatıldı.")
    try:
        # Meta veriden zamanları al
        start_time_str = meta.get("start_time")
        
        # Doğrulama Anahtarını yeniden oluştur
        key_source = access_code.encode("utf-8") + datetime.datetime.strptime(start_time_str, "%Y-%m-%d %H:%M").strftime("%Y%m%d%H%M").encode("utf-8")
        key_hex = hashlib.sha256(key_source).hexdigest()
        
        log(f"Yeniden Oluşturulan Anahtar Hash'i: {key_hex[:10]}...")

        # Keystream oluşturma
        file_len = len(encrypted_bytes)
        ks = create_keystream(key_hex, file_len, 1)

        # XOR Çözme
        decrypted_bytes = bytearray(encrypted_bytes)
        for i in range(file_len):
            decrypted_bytes[i] ^= ks[i]
            if i % (file_len // 10) == 0:
                progress_bar.progress(i / file_len, text="Çözülüyor...")

        # Integrity Check (Dosya Hash'i)
        calculated_file_hash = hashlib.sha256(bytes(decrypted_bytes)).hexdigest()
        stored_file_hash = meta.get("file_hash")
        
        if calculated_file_hash != stored_file_hash:
             log("Çözme Hatası: Dosya bütünlüğü bozuk.")
             st.error("Çözme Hatası: Yanlış erişim kodu girildi veya dosya bozulmuş.")
             return None

        progress_bar.progress(1.0, text="Çözme Tamamlandı!")
        return bytes(decrypted_bytes)

    except Exception as e:
        log(f"Sınav çözme hatası: {e}")
        st.error(f"Sınav çözme sırasında beklenmedik bir hata oluştu: {e}")
        return None

# --- Ana Uygulama Fonksiyonları ---

# YENİ RENDER_CODE_MODULE FONKSİYONU (ESKİ BOŞ FONKSİYONUN YERİNİ ALDI)
def render_code_module():
    """Yeni Kod Geliştirme Alanını (Zaman Ayarlı Sınav Sistemi) gösterir."""
    
    # Session state başlangıç değerlerini kontrol et
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
    
    st.markdown("## 👨‍🏫 Zaman Ayarlı Sınav Kilit Sistemi")
    st.markdown("---")

    tab_teacher, tab_student = st.tabs(["Öğretmen (Sınav Hazırlama)", "Öğrenci (Sınavı Çözme/İndirme)"])

    # --- ÖĞRETMEN SEKMESİ ---
    with tab_teacher:
        st.subheader("1. Sınav Dosyasını Yükle ve Kitle")
        
        with st.form("exam_encrypt_form", clear_on_submit=False):
            
            uploaded_file = st.file_uploader(
                "Sınav dosyasını seçin (PDF, DOCX, TXT vb.)", 
                type=["pdf", "docx", "txt", "zip"], 
                key="exam_enc_file_upload"
            )
            
            col_start, col_end = st.columns(2)
            
            # Başlangıç Zamanı
            with col_start:
                st.markdown("##### 🔑 Başlangıç Zamanı (Sınav Giriş)")
                enc_date_start = st.date_input("Başlangıç Tarihi", datetime.datetime.now(TURKISH_TZ).date(), key="exam_enc_date_start")
                enc_time_start = st.text_input("Başlangıç Saati (SS:DD)", datetime.datetime.now(TURKISH_TZ).strftime("%H:%M"), key="exam_enc_time_start", help="Örnek: 14:30")
            
            # Bitiş Zamanı
            with col_end:
                st.markdown("##### 🛑 Bitiş Zamanı (Sınav Kapanış)")
                # Başlangıç tarihinden 1 gün sonrası/minimum aynı gün olabilir
                min_date_end = enc_date_start + datetime.timedelta(days=0)
                enc_date_end = st.date_input("Bitiş Tarihi", enc_date_start, key="exam_enc_date_end", min_value=min_date_end)
                enc_time_end = st.text_input("Bitiş Saati (SS:DD)", (datetime.datetime.now(TURKISH_TZ) + datetime.timedelta(hours=1)).strftime("%H:%M"), key="exam_enc_time_end", help="Örnek: 15:30")

            # Erişim Kodu
            enc_access_code = st.text_input("Öğrenci Erişim Kodu (Şifre)", value="", key="exam_enc_access_code", help="Öğrencilerin sınavı indirebilmek için gireceği kod.")
            
            submitted = st.form_submit_button("🔒 Sınavı Kilitle ve Hazırla", type="primary", use_container_width=True)

        if submitted:
            # Durumları sıfırla
            st.session_state.exam_is_enc_downloaded = False
            st.session_state.exam_is_meta_downloaded = False
            st.session_state.exam_decrypted_bytes = None
            
            try:
                # Tarih/Saat birleştirme ve format kontrolü
                time_format_valid = True
                try:
                    start_dt_naive = datetime.datetime.strptime(f"{enc_date_start} {enc_time_start}", "%Y-%m-%d %H:%M")
                    end_dt_naive = datetime.datetime.strptime(f"{enc_date_end} {enc_time_end}", "%Y-%m-%d %H:%M")
                except ValueError:
                    time_format_valid = False
                
                if not time_format_valid:
                    st.warning("Lütfen zaman formatlarını düzeltin (SS:DD).")
                    st.stop()
                
                # TZ-aware objeler
                start_dt = start_dt_naive.replace(tzinfo=TURKISH_TZ).replace(second=0, microsecond=0)
                end_dt = end_dt_naive.replace(tzinfo=TURKISH_TZ).replace(second=0, microsecond=0)
                now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                
                # Kontroller
                if not uploaded_file:
                    st.error("Lütfen önce bir sınav dosyası yükleyin.")
                elif not enc_access_code:
                    st.error("Lütfen bir erişim kodu belirleyin.")
                elif end_dt <= start_dt:
                    st.error("Bitiş zamanı, başlangıç zamanından sonra olmalıdır.")
                else:
                    log("Sınav kitleme başlatıldı...")
                    progress_bar = st.progress(0, text="Sınav Şifreleniyor...")
                    
                    # Şifreleme işlemini başlat
                    enc_bytes, meta_bytes = encrypt_exam_file(
                        uploaded_file.getvalue(), enc_access_code, start_dt, end_dt, progress_bar
                    )
                    
                    if enc_bytes and meta_bytes:
                        log("Sınav kitleme tamamlandı. Dosyalar indirilmeye hazır.")
                        st.success(f"Sınav Başarıyla Hazırlandı! Başlangıç: **{start_dt.strftime('%d.%m.%Y %H:%M')}** | Bitiş: **{end_dt.strftime('%d.%m.%Y %H:%M')}**")
                        st.session_state.exam_enc_bytes = enc_bytes
                        st.session_state.exam_meta_bytes = meta_bytes
                    else:
                        st.error("Sınav kitleme sırasında bir hata oluştu.")
                        st.session_state.exam_enc_bytes = None
                        st.session_state.exam_meta_bytes = None

            except Exception as e:
                log(f"Sınav hazırlama genel hatası: {e}")
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
                    label="📝 Şifreli Sınavı İndir",
                    data=st.session_state.exam_enc_bytes,
                    file_name=f"{base_name}_encrypted",
                    mime="application/octet-stream",
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
                 st.success("✅ İki dosya da indirildi. Öğrencilerinizle paylaşabilirsiniz.")

    # --- ÖĞRENCİ SEKMESİ ---
    with tab_student:
        st.subheader("1. Sınav Dosyalarını Yükle")
        
        col_file, col_meta = st.columns(2)
        
        with col_file:
            enc_file_student = st.file_uploader("Şifreli Sınav Dosyasını Yükle", type=["*"], key="exam_dec_enc_file")
        with col_meta:
            meta_file_student = st.file_uploader("Sınav Meta Verisini Yükle (.meta)", type=["meta", "json", "txt"], key="exam_dec_meta_file")
            
        access_code_student = st.text_input("Öğrenci Erişim Kodu", key="exam_dec_access_code", type="password")
        
        st.markdown("---")
        
        # Meta Veri Okuma ve Zaman Kontrolü
        meta_data_available = False
        meta = {}
        is_active = False # Varsayılan olarak aktif değil
        
        if meta_file_student:
            try:
                raw_meta = meta_file_student.getvalue()
                meta_content = raw_meta.decode('utf-8')
                meta = json.loads(meta_content)
                
                # Check file type
                if meta.get("type") != "EXAM_LOCK":
                    st.error("Yüklenen meta dosyası bir Sınav Kilidi dosyası değil.")
                    meta_file_student = None
                else:
                    meta_data_available = True
                    start_time_str = meta.get("start_time")
                    end_time_str = meta.get("end_time")
                    
                    # TZ-aware zaman objeleri
                    start_dt = datetime.datetime.strptime(start_time_str, "%Y-%m-%d %H:%M").replace(tzinfo=TURKISH_TZ)
                    end_dt = datetime.datetime.strptime(end_time_str, "%Y-%m-%d %H:%M").replace(tzinfo=TURKISH_TZ)
                    now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                    
                    # Durum Kontrolü
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
                        # Geri sayım sayacını göster
                        time_left = end_dt - now_tr
                        st.success(f"✅ Sınav Aktif! Kalan süre: **{time_left.days} gün {time_left.seconds//3600} saat {(time_left.seconds%3600)//60} dakika**")
                    
                    
            except Exception as e:
                st.error("Meta dosya okuma hatası veya geçersiz format.")
                log(f"Öğrenci meta dosya okuma hatası: {e}")


        if st.button("🔓 Sınavı İndir ve Başla", type="primary", use_container_width=True):
            st.session_state.exam_decrypted_bytes = None
            log("Sınav çözme işlemi başlatıldı.")
            
            if not enc_file_student or not meta_file_student:
                st.error("Lütfen hem şifreli sınav dosyasını hem de meta veriyi yükleyin.")
            elif not meta_data_available:
                st.error("Yüklenen meta dosyası geçersiz veya okunamıyor.")
            elif not access_code_student:
                st.error("Lütfen erişim kodunu girin.")
            elif not is_active:
                st.error("Sınav aktif zaman aralığında değil. Lütfen başlangıç/bitiş zamanlarını kontrol edin.")
            else:
                # Erişim Kodu Kontrolü (Hash Kontrolü)
                entered_hash = hashlib.sha256(access_code_student.encode('utf-8')).hexdigest()
                stored_hash = meta.get("access_code_hash")
                
                if entered_hash != stored_hash:
                    st.error("Hata: Girilen erişim kodu hatalı.")
                    log("Hata: Hatalı erişim kodu girildi.")
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
            
            original_file_name = enc_file_student.name if enc_file_student else "sinav"
            file_extension = os.path.splitext(original_file_name)[1] or ".dat" # Varsayılan: .dat
            
            st.download_button(
                label="📥 Çözülmüş Sınavı İndir",
                data=st.session_state.exam_decrypted_bytes,
                file_name=f"decrypted_exam{file_extension}",
                mime="application/octet-stream",
                use_container_width=True
            )


# --- Streamlit Uygulama Akışı (ORİJİNAL AKIŞ) ---

# Başlangıç Ayarları
st.set_page_config(
    page_title="Zaman Kilitli Şifreleme Uygulaması",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS Ekleme
add_custom_css()

# Session State başlatma
if 'current_view' not in st.session_state:
    st.session_state.current_view = 'cipher'
if 'encrypted_bytes' not in st.session_state:
    st.session_state.encrypted_bytes = None
if 'meta_bytes' not in st.session_state:
    st.session_state.meta_bytes = None
if 'decrypted_bytes' not in st.session_state:
    st.session_state.decrypted_bytes = None
if 'is_enc_downloaded' not in st.session_state:
    st.session_state.is_enc_downloaded = False
if 'is_meta_downloaded' not in st.session_state:
    st.session_state.is_meta_downloaded = False


# Kenar Çubuğu (Sidebar)
with st.sidebar:
    st.title("🛡️ Uygulama Seçimi")
    
    view_option = st.radio(
        "Görüntülemek istediğiniz uygulamayı seçin:",
        ["Zamanlı Şifreleme Uygulaması", "Yeni Kod Geliştirme Sayfası"],
        index=0 if st.session_state.current_view == 'cipher' else 1,
    )

    # st.session_state'i güncelleyen on_change handler'ı yok, bu yüzden radio button değeri üzerinden atama yapmalıyız.
    if view_option == "Zamanlı Şifreleme Uygulaması":
        st.session_state.current_view = 'cipher'
    elif view_option == "Yeni Kod Geliştirme Sayfası":
        st.session_state.current_view = 'code'
        
    st.markdown("---")
    st.markdown(f"**Güncel Saat (TR):** {datetime.datetime.now(TURKISH_TZ).strftime('%d.%m.%Y %H:%M:%S')}")


# --- Ana İçerik ---

if st.session_state.current_view == 'cipher':
    # ESKİ GÖRÜNÜM (Zamanlı Şifreleme Uygulaması) - ORİJİNAL KOD
    st.markdown("# 🕒 Zaman Kilitli Görüntü Şifreleme")
    st.markdown("---")
    
    tab_encrypt, tab_decrypt = st.tabs(["Şifreleme (Kitleme)", "Şifre Çözme (Açma)"])

    # --- ŞİFRELEME SEKMESİ ---
    with tab_encrypt:
        st.subheader("1. Görüntüyü ve Zamanı Ayarla")
        
        with st.form("encrypt_form", clear_on_submit=False):
            
            uploaded_file = st.file_uploader(
                "Şifrelenecek görüntüyü seçin (JPG, PNG vb.)", 
                type=["png", "jpg", "jpeg", "webp"], 
                key="enc_file_upload"
            )
            
            col_date, col_time = st.columns(2)
            
            with col_date:
                enc_date = st.date_input("Açılma Tarihi", datetime.datetime.now(TURKISH_TZ).date(), key="enc_date")
            
            with col_time:
                enc_time = st.text_input("Açılma Saati (SS:DD)", (datetime.datetime.now(TURKISH_TZ) + datetime.timedelta(hours=1)).strftime("%H:%M"), key="enc_time", help="Örnek: 14:30")
            
            enc_key = st.text_input("Şifre Çözme Anahtarı", value="", key="enc_key", type="password", help="Görüntüyü açacak olan gizli anahtar.")
            
            submitted = st.form_submit_button("🔒 Görüntüyü Şifrele", type="primary", use_container_width=True)

        if submitted:
            # Durumları sıfırla
            st.session_state.is_enc_downloaded = False
            st.session_state.is_meta_downloaded = False
            st.session_state.decrypted_bytes = None
            
            try:
                # Tarih/Saat birleştirme ve format kontrolü
                time_format_valid = True
                try:
                    ot_dt_naive = datetime.datetime.strptime(f"{enc_date} {enc_time}", "%Y-%m-%d %H:%M")
                except ValueError:
                    time_format_valid = False
                
                if not time_format_valid:
                    st.warning("Lütfen zaman formatını düzeltin (SS:DD).")
                    st.stop()
                
                # TZ-aware objeler
                ot_dt = ot_dt_naive.replace(tzinfo=TURKISH_TZ).replace(second=0, microsecond=0)
                now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                
                # Kontroller
                if not uploaded_file:
                    st.error("Lütfen önce bir görüntü yükleyin.")
                elif not enc_key:
                    st.error("Lütfen bir şifre çözme anahtarı girin.")
                elif ot_dt <= now_tr:
                    st.error(f"Açılma zamanı, şu anki zamandan ({now_tr.strftime('%H:%M')}) ileri bir tarih/saat olmalıdır.")
                else:
                    log("Şifreleme başlatıldı...")
                    progress_bar = st.progress(0, text="Görüntü Şifreleniyor...")
                    
                    # Şifreleme işlemini başlat
                    enc_bytes, meta_bytes = encrypt_image_file(
                        uploaded_file.getvalue(), ot_dt, enc_key, progress_bar
                    )
                    
                    if enc_bytes and meta_bytes:
                        log("Şifreleme tamamlandı. Dosyalar indirilmeye hazır.")
                        st.success(f"Görüntü Başarıyla Şifrelendi! Açılma Zamanı: **{ot_dt.strftime('%d.%m.%Y %H:%M')}**")
                        st.session_state.encrypted_bytes = enc_bytes
                        st.session_state.meta_bytes = meta_bytes
                    else:
                        st.error("Şifreleme sırasında bir hata oluştu.")
                        st.session_state.encrypted_bytes = None
                        st.session_state.meta_bytes = None

            except Exception as e:
                log(f"Genel şifreleme hatası: {e}")
                st.error(f"Beklenmedik bir hata oluştu: {e}")


        # --- İndirme Bölümü (Şifreleme) ---
        if st.session_state.encrypted_bytes and st.session_state.meta_bytes:
            st.markdown("---")
            st.subheader("2. Dosyaları İndir ve Paylaş")
            st.warning("⚠️ Lütfen **hem Şifreli Görüntü Dosyasını** hem de **Meta Veri Dosyasını** indirip paylaşın.")
            
            base_name = os.path.splitext(uploaded_file.name)[0] if uploaded_file else "image"
            
            col_enc, col_meta = st.columns(2)
            
            with col_enc:
                st.download_button(
                    label="🖼️ Şifreli Görüntüyü İndir",
                    data=st.session_state.encrypted_bytes,
                    file_name=f"{base_name}_encrypted",
                    mime="application/octet-stream",
                    on_click=lambda: setattr(st.session_state, 'is_enc_downloaded', True),
                    disabled=st.session_state.is_enc_downloaded,
                    use_container_width=True
                )
            
            with col_meta:
                st.download_button(
                    label="🔑 Meta Veriyi İndir (.meta)",
                    data=st.session_state.meta_bytes,
                    file_name=f"{base_name}_encrypted.meta",
                    mime="application/json",
                    on_click=lambda: setattr(st.session_state, 'is_meta_downloaded', True),
                    disabled=st.session_state.is_meta_downloaded,
                    use_container_width=True
                )
            
            if st.session_state.is_enc_downloaded and st.session_state.is_meta_downloaded:
                 st.success("✅ İki dosya da indirildi. Güvenle paylaşabilirsiniz.")


    # --- ŞİFRE ÇÖZME SEKMESİ ---
    with tab_decrypt:
        st.subheader("1. Dosyaları Yükle ve Anahtarı Gir")
        
        col_file, col_meta = st.columns(2)
        
        with col_file:
            enc_file = st.file_uploader("Şifreli Görüntü Dosyasını Yükle", type=["*"], key="dec_enc_file")
        with col_meta:
            meta_file = st.file_uploader("Meta Veri Dosyasını Yükle (.meta)", type=["meta", "json", "txt"], key="dec_meta_file")
            
        dec_key = st.text_input("Şifre Çözme Anahtarı", key="dec_key", type="password")
        
        st.markdown("---")
        
        # Meta Veri Okuma ve Zaman Kontrolü
        meta_data_available = False
        meta = {}
        
        if meta_file:
            try:
                raw_meta = meta_file.getvalue()
                meta_content = raw_meta.decode('utf-8')
                meta = json.loads(meta_content)
                
                # Check file type
                if meta.get("type") != "IMAGE_LOCK":
                    st.error("Yüklenen meta dosyası bir Görüntü Kilidi dosyası değil.")
                    meta_file = None
                else:
                    meta_data_available = True
                    open_time_str = meta.get("open_time")
                    
                    # TZ-aware zaman objeleri
                    ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M").replace(tzinfo=TURKISH_TZ)
                    now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                    
                    st.info(f"Açılma Zamanı: **{ot_dt.strftime('%d.%m.%Y %H:%M')}**")
                    
                    if now_tr < ot_dt:
                        time_left = ot_dt - now_tr
                        st.warning(f"🔓 Henüz Açılmadı! Kalan süre: **{time_left.days} gün {time_left.seconds//3600} saat {(time_left.seconds%3600)//60} dakika**")
                    else:
                        st.success("✅ Açılma Zamanı Geldi! Şifreyi girip çözebilirsiniz.")
                    
            except Exception as e:
                st.error("Meta dosya okuma hatası veya geçersiz format.")
                log(f"Çözme meta dosya okuma hatası: {e}")


        if st.button("🔓 Şifreyi Çöz ve Görüntüle", type="primary", use_container_width=True):
            st.session_state.decrypted_bytes = None
            log("Çözme işlemi başlatıldı.")
            
            if not enc_file or not meta_file:
                st.error("Lütfen hem şifreli görüntüyü hem de meta veriyi yükleyin.")
            elif not meta_data_available:
                st.error("Yüklenen meta dosyası geçersiz veya okunamıyor.")
            elif not dec_key:
                st.error("Lütfen şifre çözme anahtarını girin.")
            else:
                ot_dt = datetime.datetime.strptime(meta.get("open_time"), "%Y-%m-%d %H:%M").replace(tzinfo=TURKISH_TZ)
                now_tr = datetime.datetime.now(TURKISH_TZ).replace(second=0, microsecond=0)
                
                if now_tr < ot_dt:
                    st.error("Hata: Görüntü kilitli. Açılma zamanı henüz gelmedi.")
                else:
                    # Anahtar Kontrolü (Hash Kontrolü)
                    entered_hash = hashlib.sha256(dec_key.encode('utf-8')).hexdigest()
                    stored_hash = meta.get("key_hash")
                    
                    if entered_hash != stored_hash:
                        st.error("Hata: Girilen şifre çözme anahtarı hatalı.")
                        log("Hata: Hatalı anahtar girildi.")
                    else:
                        progress_bar = st.progress(0, text="Görüntü Çözülüyor...")
                        
                        dec_bytes = decrypt_image_in_memory(
                            enc_file.getvalue(), dec_key, meta, progress_bar
                        )
                        
                        if dec_bytes:
                            st.success("Görüntü Başarıyla Çözüldü!")
                            st.session_state.decrypted_bytes = dec_bytes
                        else:
                            st.error("Çözme hatası. Lütfen dosyaları ve anahtarı kontrol edin.")

        
        # --- Görüntüleme ve İndirme Bölümü (Çözme) ---
        if st.session_state.decrypted_bytes:
            st.markdown("---")
            st.subheader("2. Çözülmüş Görüntü")
            
            # Görüntü verisini base64 olarak encode ederek görüntüle
            b64_img = base64.b64encode(st.session_state.decrypted_bytes).decode('utf-8')
            mime_type = "image/png" # Varsayılan olarak png kabul edelim
            if enc_file:
                if enc_file.type in ["image/jpeg", "image/jpg"]:
                    mime_type = "image/jpeg"
                elif enc_file.type == "image/webp":
                     mime_type = "image/webp"

            st.image(io.BytesIO(st.session_state.decrypted_bytes), caption="Çözülmüş Görüntü", use_column_width=True)

            st.download_button(
                label="📥 Çözülmüş Görüntüyü İndir",
                data=st.session_state.decrypted_bytes,
                file_name=f"decrypted_image.png",
                mime=mime_type,
                use_container_width=True
            )


elif st.session_state.current_view == 'code':
    # YENİ SAYFA GÖRÜNÜMÜ (Zaman Ayarlı Sınav Sistemi) - YENİ KOD
    render_code_module()

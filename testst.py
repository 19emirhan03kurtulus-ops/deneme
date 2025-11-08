import streamlit as st
from PIL import Image, ImageDraw, ImageFont
import hashlib, datetime, random, os, json, io
# Saat dilimi işlemleri için gerekli kütüphaneler
from zoneinfo import ZoneInfo
import time 
import base64

# Callback fonksiyonları, download_button'da indirme durumunu kaydetmek için kullanılır
def set_png_downloaded():
    st.session_state['is_png_downloaded'] = True
    log("Şifreli PNG dosyası indirildi olarak işaretlendi.")

def set_meta_downloaded():
    st.session_state['is_meta_downloaded'] = True
    log("Meta verisi dosyası indirildi olarak işaretlendi.")

# Türkiye/İstanbul saat dilimi tanımı (UTC+3)
TURKISH_TZ = ZoneInfo("Europe/Istanbul")

# ----------------------------- Ayarlar ve Başlık -----------------------------
st.set_page_config(
    page_title="Zamanlı Görsel Şifreleme (🇹🇷)",
    page_icon="🖼️",
    layout="wide"
)

# ----------------------------- MODERN CSS ENJEKSİYONU -----------------------------
# Uygulamanın daha modern ve "havalı" görünmesi için CSS stilleri
CUSTOM_CSS = """
<style>
/* 1. GENEL STİL İYİLEŞTİRMELERİ (Streamlit'in Genel Yapısını Hedefleme) */

/* Ana içerik alanına hafif bir gölge ve yuvarlaklık verelim */
.stApp > header {
    background-color: transparent; /* Üst başlığı şeffaf yap */
}

/* Tüm butonlar için modern bir stil */
.stButton>button {
    border-radius: 0.75rem; /* Daha belirgin yuvarlaklık (lg) */
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.06); /* Yumuşak gölge */
    transition: all 0.3s ease;
    border-width: 0px; /* Varsayılan border'ı kaldır */
}

/* Butonlara hover efekti */
.stButton>button:hover {
    box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1); /* Hover'da daha belirgin gölge */
    transform: translateY(-2px); /* Hafif yukarı kalkma efekti */
}

/* 2. SAĞ PANEL İYİLEŞTİRMELERİ (Kenar Çubuğu Taklidi) */

/* Sağ sütunun arka plan rengini ve stilini güncelleyelim */
.right-panel-background > div {
    background-color: var(--st-sidebar-background-color, #f0f2f6); /* Sidebar rengine yakın ton */
    padding: 1.5rem; /* Daha fazla padding */
    border-radius: 1rem; /* Daha yuvarlak köşeler */
    box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1); /* Derin gölge */
}

/* Log alanının arka planını beyaz, yuvarlak köşeli ve gölgeli yapalım */
#log_area textarea {
    background-color: white;
    color: black;
    border-radius: 0.5rem;
    box-shadow: inset 0 2px 4px 0 rgba(0, 0, 0, 0.06);
    padding: 10px;
}

/* 3. İNDİRME BUTONLARI VE SEKMELER */

/* Download butonlarını da aynı modern stilde tutalım */
.stDownloadButton>button {
    background-color: #4CAF50 !important; /* Yeşil ton */
    color: white !important;
}
.stDownloadButton>button:hover {
    background-color: #45a049 !important;
}

/* Uyarı ve Başarı kutularını (info, success) daha yuvarlak yapalım */
div[data-testid="stAlert"] {
    border-radius: 0.75rem;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
}

/* Sekmelerin (Tabs) altındaki içeriğe de hafif bir padding verelim */
.stTabs [data-testid="stVerticalBlock"] {
    padding-top: 1rem;
}
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


# ----------------------------- Session State (Oturum Durumu) -----------------------------

# Başlangıç değerlerini tanımlayan yardımcı fonksiyon
def get_initial_state():
    return {
        'log': "",
        'decrypted_image': None,
        'watermarked_image': None,
        'hidden_message': "",
        'secret_key_hash': "",
        'is_message_visible': False,
        'prompt_secret_key': False,
        'generated_enc_bytes': None,
        'generated_meta_bytes': None,
        
        # YENİ DURUM DEĞİŞKENLERİ: İndirme durumunu takip etmek için
        'is_png_downloaded': False,
        'is_meta_downloaded': False,
        
        # Temizleme için dinamik keyler için sayaç (KRİTİK)
        'reset_counter': 0, 
        
        # Tüm Text Input/Checkbox default değerleri
        'enc_pass_input': '',
        'enc_no_pass_checkbox': False,
        'enc_secret_text_input': '',
        'enc_secret_key_input': '',
        'enc_time_str': '00:00',
        'decrypt_pass': '', 
        'modal_pass': '',
        
        # YENİ GÖRÜNÜM KONTROLÜ: 'cipher' (şifreleme) veya 'code' (kod sayfası)
        'current_view': 'cipher',
    }

def init_state():
    """Tüm oturum durumlarını başlatır."""
    defaults = get_initial_state()
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

def reset_app():
    """Uygulamanın tüm oturum durumunu sıfırlar. (Genel Reset)"""
    # Mevcut görünüm ayarını koruyarak sıfırlama yap
    current_view = st.session_state.get('current_view', 'cipher')
    
    log("Uygulama sıfırlandı. Tüm görseller ve veriler temizlendi.")
    st.session_state.clear()
    init_state() # Sıfırladıktan sonra yeniden başlat
    st.session_state['current_view'] = current_view # Görünümü geri yükle
    time.sleep(0.1) 
    st.rerun()

def reset_all_inputs():
    """Hem Şifre hem de Çöz sekmesindeki tüm yüklemeleri, girdileri ve çıktıları sıfırlar."""
    log("Tüm Şifreleme ve Çözme girdileri temizlendi. Yüklenen dosyalar sıfırlandı.")
    
    # 1. Çıktı ve Kilitli state'leri temizle
    st.session_state['decrypted_image'] = None
    st.session_state['watermarked_image'] = None
    st.session_state['hidden_message'] = ""
    st.session_state['secret_key_hash'] = ""
    st.session_state['is_message_visible'] = False
    st.session_state['prompt_secret_key'] = False
    st.session_state['generated_enc_bytes'] = None
    st.session_state['generated_meta_bytes'] = None
    
    # 2. İndirme durumlarını sıfırla
    st.session_state['is_png_downloaded'] = False
    st.session_state['is_meta_downloaded'] = False
    
    # 3. Text Input/Checkbox state'lerini temizle
    st.session_state['decrypt_pass'] = ''
    st.session_state['enc_pass_input'] = ''
    st.session_state['enc_secret_text_input'] = ''
    st.session_state['enc_secret_key_input'] = ''
    st.session_state['enc_no_pass_checkbox'] = False
    st.session_state['enc_time_str'] = '00:00'
    st.session_state['modal_pass'] = ''

    # 4. KRİTİK ADIM: Dosya yükleyicilerini ve diğer dinamik bileşenleri sıfırlamak için sayacı artır.
    st.session_state['reset_counter'] += 1
    
    time.sleep(0.1)
    st.rerun()

init_state()

# ----------------------------- Yardımcı Fonksiyonlar -----------------------------

def log(text):
    """Streamlit için loglama fonksiyonu. Logları session_state'e ekler."""
    # TR saatini kullanarak zaman damgası ekle
    ts = datetime.datetime.now(TURKISH_TZ).strftime("%H:%M:%S")
    st.session_state['log'] = f"[{ts}] {text}\n" + st.session_state['log']

def normalize_time(t):
    # Meta veriye yazarken saati ve dakikayı formatlar.
    # Timezone bilgisini kaldırarak sadece zamanı metin olarak kaydederiz.
    return t.strftime("%Y-%m-%d %H:%M") if isinstance(t, datetime.datetime) else str(t)

def hash_image_content(img: Image.Image) -> str:
    """Görüntünün içeriğinden bir hash (özet) üretir."""
    # Resim verisi sıkıştırılmamış halde işlenir.
    return hashlib.sha256(img.tobytes()).hexdigest()

def generate_key(password, open_time_str, image_hash=""):
    """Şifreleme anahtarını (hash) oluşturur."""
    combo = (password or "") + open_time_str + image_hash
    return hashlib.sha256(combo.encode("utf-8")).hexdigest()

def create_keystream(key_hex, w, h):
    """Verilen anahtar (hash) ile rastgele bir anahtar akışı (keystream) oluşturur."""
    # Deterministic (belirlenimci) rastgelelik için key_hex'i seed olarak kullanırız.
    random.seed(int(key_hex, 16))
    # w * h * 3 (her piksel için R, G, B) boyutunda bir akış oluşturulur.
    return [random.randint(0, 255) for _ in range(w * h * 3)]

def add_text_watermark(img: Image.Image, hidden_message: str) -> Image.Image:
    """Şifre çözülmüş görselin üzerine SADECE gizli mesajı ekler. Konumu ve görünümü iyileştirildi."""
    img_copy = img.copy()
    draw = ImageDraw.Draw(img_copy, 'RGBA')
    w, h = img_copy.size
    
    if not hidden_message.strip():
        return img 

    # Sadece gizli mesajı göster
    full_text = f"{hidden_message}"
    
    try:
        # Daha büyük bir font boyutu seçelim
        font = ImageFont.load_default().font_variant(size=30) 
    except IOError:
        font = ImageFont.load_default()
        
    text_color = (255, 255, 255, 255) # Beyaz ve tam opak
    
    # Metin boyutunu hesapla
    try:
        bbox = draw.textbbox((0, 0), full_text, font=font, anchor="ls")
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
    except AttributeError:
        # Fallback for older Pillow versions
        text_w = draw.textlength(full_text, font=font)
        text_h = 30 # Tahmini satır yüksekliği
    
    padding = 20 # Daha fazla boşluk bırak
    
    # Metni sağ alt köşeye, daha fazla içeriden yerleştir
    x = w - text_w - padding 
    y = h - text_h - padding 

    # Metin kutusu arka planı için koyu renk, daha yüksek opaklık
    fill_color = (0, 0, 0, 200) # Siyah ve %80 opak
    draw.rectangle([x - padding, y - padding, x + text_w + padding, y + text_h + padding], fill=fill_color) 
    
    # Metni yerleştir
    draw.text((x, y), full_text, font=font, fill=text_color)
    
    return img_copy

# ----------------------------- Örnek Resim Oluşturma -----------------------------
def create_sample_image_bytes():
    """Diske kaydetmek yerine hafızada (bytes) örnek resim oluşturur."""
    img = Image.new("RGB", (600,400), color=(70,130,180))
    # Görseldeki gradient efekti simüle edelim
    for y in range(img.height):
        for x in range(img.width):
            r = 70 + int(x/img.width*120)  # Kırmızı tonu artır
            g = 130 + int(y/img.height*50) # Yeşil tonu artır
            b = 180 + int(x/img.width*30)  # Mavi tonu da ekle
            img.putpixel((x,y), (r % 256, g % 256, b % 256))
    
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_bytes = img_byte_arr.getvalue()
    log("Örnek resim hafızada oluşturuldu.")
    return img_bytes

# ----------------------------- Çekirdek (encrypt/decrypt) -----------------------------

def encrypt_image_file(image_bytes, password, open_time_dt, secret_text, secret_key, allow_no_password, progress_bar):
    """Şifreleme işlemini yapar."""
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as e:
        log(f"Hata: Resim dosyası okunamadı: {e}")
        st.error(f"Hata: Yüklenen resim dosyası açılamadı: {e}")
        return None, None

    w, h = img.size
    px = img.load()
    
    image_hash = hash_image_content(img)
    # open_time_dt, zaten TZ-aware (İstanbul) olarak oluşturuldu. Meta veriye sadece metin olarak kaydet.
    open_time_str = normalize_time(open_time_dt) 
    
    key_hex = generate_key(password, open_time_str, image_hash)
    ks = create_keystream(key_hex, w, h)

    # Şifreleme (XOR) işlemi
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

    # Doğrulama Etiketi (Verification Tag) oluştur
    verify_tag = hashlib.sha256(key_hex.encode("utf-8") + img.tobytes()).hexdigest()
    secret_key_hash = hashlib.sha256(secret_key.encode('utf-8')).hexdigest() if secret_key else ""

    # Meta verisi oluştur
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
    """Şifreli byte dizisini çözer."""
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

    # Şifre çözme (tekrar XOR) işlemi
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

# ----------------------------- Sayfa Görünümleri -----------------------------

def render_code_module():
    """Yeni Kod Geliştirme Alanını (Simülasyon) gösterir. Kullanıcının isteği üzerine tamamen boş bırakıldı."""
    # Kullanıcının isteği üzerine bu sayfa tamamen boş bırakılmıştır.
    st.title("Yeni Kod Geliştirme Alanı")
    st.info("Bu sayfa, talep üzerine boş bırakılmıştır. Ana uygulamaya soldaki menüden dönebilirsiniz.")


# ----------------------------- ARAYÜZ (UI) -----------------------------

# --- Sidebar (Sol Kenar Çubuğu - Sadece Sayfa Seçimi) ---
with st.sidebar:
    
    # Görseldeki gibi bir görsel placeholder'ı ekleyelim (CSS ile uyumlu)
    st.markdown("""
        <div style="
            border-radius: 1rem; 
            overflow: hidden; 
            margin-bottom: 1.5rem; 
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -2px rgba(0, 0, 0, 0.06);">
            
            <div style="
                height: 150px; 
                background: linear-gradient(135deg, #4f46e5, #a855f7); /* Mor-İndigo gradient */
                display: flex; 
                align-items: center; 
                justify-content: center;
                color: white;
                font-weight: bold;
                font-size: 1.25rem;">
                
            </div>
        </div>
        <p style="text-align: center; color: var(--st-secondary-text-color); margin-top: -1rem; margin-bottom: 2rem;">
            Örnek Resim Görünümü
        </p>
    """, unsafe_allow_html=True)
    
    # GÖRÜNÜM SEÇİCİ
    st.subheader("Sayfa Seçimi")
    view_option = st.radio(
        "Görüntülemek istediğiniz uygulamayı seçin:",
        ["Zamanlı Şifreleme Uygulaması", "Yeni Kod Geliştirme Sayfası"],
        index=0 if st.session_state.current_view == 'cipher' else 1,
        key="view_selector"
    )

    # Seçime göre state'i güncelle
    new_view = 'cipher' if view_option == "Zamanlı Şifreleme Uygulaması" else 'code'
    if new_view != st.session_state.current_view:
        st.session_state.current_view = new_view
        # Görünüm değiştiğinde uygulamayı yeniden çalıştır
        st.rerun()

    st.markdown("---")
    
    st.subheader("İşlem Günlüğü")
    st.text_area("Loglar", value=st.session_state.get('log', ''), height=300, disabled=True, key="log_area")


# ----------------------------- Ana Alan (Conditional Rendering) -----------------------------

if st.session_state.current_view == 'cipher':
    
    # Ana içeriği (Sekmeler) ve Sağ Kontrol Panelini ayır
    # Sağ sütun boyutunu biraz artırdık
    col_main_content, col_right_panel = st.columns([2.5, 1]) 

    # --- SAĞ KONTROL PANELİ (Kullanıcının İsteği Üzerine Sağda - Arka Plan Rengi Eşitlendi) ---
    with col_right_panel:
        
        # Arka plan rengini uygulamak için bir container içine alıyoruz
        with st.container(border=False):
            # CSS enjeksiyonu için özel bir sınıf ekleyelim (Bu sadece Streamlit DOM'unda bir wrapper olarak görev yapar)
            st.markdown('<div class="right-panel-background">', unsafe_allow_html=True)
            
            # 1. GÖRSELİ TAŞIDIK (Streamlit'in kendi bileşenini kullanalım)
            with st.container(border=True):
                st.image(create_sample_image_bytes(), use_container_width=True, caption="Örnek Resim Önizlemesi")
            
            st.subheader("Uygulama Kontrolü")
            
            # 2. Sıfırlama Butonu (Genel Reset)
            # Daha dikkat çekici bir stil
            if st.button("🔄 Uygulamayı Sıfırla (GENEL RESET)", on_click=reset_app, help="Tüm oturum verilerini, görselleri ve logları temizler.", use_container_width=True):
                pass # Buton basıldı, on_click halletti
            
            st.markdown("---")
            
            st.subheader("Örnek Resim Oluşturma")
            st.info("Test için hızlıca bir resim oluşturun ve şifreleme sekmesinden indirin.")
            
            # Buton stilini biraz daha farklı yapalım
            if st.button("🖼️ Örnek Şifresiz Resim Oluştur", use_container_width=True):
                img_bytes = create_sample_image_bytes()
                # Çıktı state'lerini güncelle
                st.session_state.generated_enc_bytes = img_bytes
                st.session_state.generated_meta_bytes = None
                
                # Yeni bir şifreleme çıktısı olduğu için indirme durumunu sıfırla
                st.session_state.is_png_downloaded = False
                st.session_state.is_meta_downloaded = False
                
                log("Test için örnek resim oluşturuldu. 'Şifrele' sekmesinden indirebilirsiniz.")
                st.rerun() 
            
            with st.expander("❓ Yardım (Kullanım Kılavuzu)"):
                st.markdown(
                    """
                    **Saat Dilimi Notu:** Uygulama, açılma zamanını Türkiye saati (UTC+3) baz alarak hesaplar.
                    
                    **Şifreleme:**
                    1. `🔒 Şifrele` sekmesine gidin.
                    2. Bir resim dosyası yükleyin ve ayarları yapın.
                    3. `Şifrele` butonuna basın ve oluşan `.png` ile `.meta` dosyalarını **ayrı butonlarla** indirin.
                    
                    **Şifre Çözme:**
                    1. `🔓 Çöz` sekmesinde iki dosyayı da yükleyin.
                    2. Şifre (gerekliyse) girin ve `Çöz` butonuna basın. Resim, açılma zamanı geldiyse çözülür.
                    3. **Temizle Butonu:** Tüm yüklenen dosya, şifre ve sonuçları **her iki sekmede de** siler.
                    """
                )
            
            st.markdown('</div>', unsafe_allow_html=True)


    # --- ANA İÇERİK (Şifrele/Çöz Sekmeleri) ---
    with col_main_content:
        
        st.title("🖼️ Zamanlı Görsel Şifreleme (🇹🇷)")
        st.markdown(
            """
            Bu uygulama, görsellerinizi belirlediğiniz bir tarih ve saate kadar kilitler. 
            Çözmek için hem şifreli görseli hem de meta veriyi saklamanız gerekir.
            """
        )
        
        # --- Ana Alan (Sekmeler) ---
        tab_encrypt, tab_decrypt = st.tabs(["🔒 Şifrele", "🔓 Çöz"])

        # --- ŞİFRELEME SEKMESİ ---
        with tab_encrypt:
            st.subheader("Yeni Bir Görseli Şifrele")
            
            # Dosya yükleyiciyi sıfırlamak için dinamik key kullanıyoruz
            uploaded_file = st.file_uploader(
                "1. Şifrelenecek resmi seçin", 
                type=["png", "jpg", "jpeg", "bmp"],
                key=f"encrypt_file_uploader_{st.session_state.reset_counter}" 
            )
            
            with st.form("encrypt_form", clear_on_submit=False):
                
                st.markdown("---")
                st.markdown("##### Şifreleme Ayarları")
                
                # Giriş değerlerini session state'ten alarak sıfırlama özelliğini destekliyoruz
                enc_pass = st.text_input("Görsel Şifresi (Çözme için)", type="password", key="enc_pass_input", value=st.session_state.enc_pass_input)
                
                # Checkbox değerini session state'ten al
                enc_no_pass = st.checkbox("Şifresiz açılmaya izin ver (Sadece zaman kilidi)", key="enc_no_pass_checkbox", value=st.session_state.enc_no_pass_checkbox)
                
                enc_secret_text = st.text_area("Gizli Mesaj (Meta veriye saklanır)", placeholder="Gizli notunuz...", key="enc_secret_text_input", value=st.session_state.enc_secret_text_input)
                enc_secret_key = st.text_input("Gizli Mesaj Şifresi (Filigranı görmek için)", type="password", placeholder="Filigranı açacak şifre", key="enc_secret_key_input", value=st.session_state.enc_secret_key_input)
                
                st.markdown("---")
                st.markdown("##### 2. Açılma Zamanı Ayarı (Türkiye Saati ile)")

                col_date, col_time = st.columns(2)
                
                min_date = datetime.datetime.now(TURKISH_TZ).date()
                default_date = min_date + datetime.timedelta(days=1)
                
                with col_date:
                    # Tarih input'u için de dinamik key kullanıyoruz
                    enc_date = st.date_input(
                        "Açılma Tarihi (YYYY-AA-GG)",
                        value=default_date,
                        min_value=min_date,
                        key=f"enc_date_{st.session_state.reset_counter}" 
                    )

                with col_time:
                    enc_time_str = st.text_input(
                        "Açılma Saati (HH:MM formatında)",
                        value=st.session_state.enc_time_str, 
                        placeholder="Örn: 14:30",
                        key="enc_time_str" 
                    )

                # --- Zaman İşleme Başlangıcı ---
                enc_time_dt = None
                time_format_valid = False
                try:
                    hour, minute = map(int, enc_time_str.split(':'))
                    if 0 <= hour <= 23 and 0 <= minute <= 59:
                        enc_time_val = datetime.time(hour, minute, 0)
                        naive_dt = datetime.datetime.combine(enc_date, enc_time_val).replace(second=0, microsecond=0)
                        enc_time_dt = naive_dt.replace(tzinfo=TURKISH_TZ)
                        time_format_valid = True
                    else:
                        log("Hata: Geçersiz saat/dakika aralığı.")
                except Exception:
                    log("Hata: Geçersiz saat formatı.")
                    time_format_valid = False
                    
                if not time_format_valid and st.session_state.enc_time_str != '00:00':
                    st.error("Lütfen saati **HH:MM** formatında doğru girin. (Örn: 14:30)")

                # Daha vurgulu bir submit butonu
                submitted = st.form_submit_button("🔒 Şifrele ve Dosyaları Oluştur", type="primary", use_container_width=True)

            if submitted:
                # Yeni şifreleme işlemi başladığında indirme durumunu sıfırla
                st.session_state.is_png_downloaded = False
                st.session_state.is_meta_downloaded = False
                
                if not time_format_valid:
                    st.warning("Lütfen zaman formatını düzeltin.")
                    st.stop()
                    
                # Şu anki zamanı da Türkiye saati olarak al
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
                    
                    pw_to_use = "" if enc_no_pass else enc_pass
                    
                    # Meta veriye sadece metin olarak kaydedilecek TZ-aware zaman objesi kullanılır.
                    enc_bytes, meta_bytes = encrypt_image_file(
                        image_bytes, pw_to_use, enc_time_dt, 
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
                        st.error("Şifreleme sırasında bir hata oluştu. Logları kontrol edin.")
                        st.session_state.generated_enc_bytes = None
                        st.session_state.generated_meta_bytes = None
                        st.session_state.is_png_downloaded = False
                        st.session_state.is_meta_downloaded = False

            
            # --- İndirme Bölümü (KRİTİK GÖRÜNÜRLÜK KONTROLÜ) ---
            if st.session_state.generated_enc_bytes and st.session_state.generated_meta_bytes:
                
                base_name = "encrypted_image"
                try:
                    # uploaded_file may be None when using example; guard it
                    if uploaded_file is not None:
                        base_name = os.path.splitext(uploaded_file.name)[0]
                except Exception:
                    pass
                
                # İki dosya da indirildiğinde bu bölümü gizle
                if st.session_state.is_png_downloaded and st.session_state.is_meta_downloaded:
                    st.markdown("---")
                    st.success("✅ Tebrikler! Hem Şifreli Resim hem de Meta Veri başarıyla indirildi. Yeni bir şifreleme başlatabilirsiniz.")
                else:
                    st.markdown("---")
                    st.subheader("3. İndirme Bağlantıları (Zorunlu İkili İndirme)")
                    st.warning("⚠️ Lütfen hem .png hem de .meta dosyasını indirin. İkisi de indirilince bu bölüm kaybolacaktır.")

                    col_png, col_meta = st.columns(2)
                    
                    # PNG İndirme Butonu
                    with col_png:
                        st.download_button(
                            label="🖼️ Şifreli Resmi İndir (.png)",
                            data=st.session_state.generated_enc_bytes,
                            file_name=f"{base_name}_encrypted.png",
                            mime="image/png",
                            on_click=set_png_downloaded, # Callback eklendi
                            disabled=st.session_state.is_png_downloaded, # Tıklanınca pasifleşir
                            use_container_width=True
                        )
                    
                    # Meta İndirme Butonu
                    with col_meta:
                        st.download_button(
                            label="🔑 Meta Veriyi İndir (.meta)",
                            data=st.session_state.generated_meta_bytes,
                            file_name=f"{base_name}_encrypted.meta",
                            mime="application/json",
                            on_click=set_meta_downloaded, # Callback eklendi
                            disabled=st.session_state.is_meta_downloaded, # Tıklanınca pasifleşir
                            use_container_width=True
                        )
                        
            
            # Örnek Resim indirme butonu, sadece kenar çubuğundan oluşturulduysa ve meta veri yoksa gösterilir
            elif st.session_state.generated_enc_bytes and not st.session_state.generated_meta_bytes:
                st.info("Kenar çubuğundan oluşturulan örnek resmi indirin. Bu resim şifresizdir.")
                st.download_button(
                    label="Örnek Resmi İndir",
                    data=st.session_state.generated_enc_bytes,
                    file_name="sample_for_encrypt.png",
                    mime="image/png"
                )


        # --- ŞİFRE ÇÖZME SEKMESİ ---
        with tab_decrypt:
            st.subheader("Şifreli Bir Görseli Çöz")
            
            col1, col2 = st.columns([1, 1.5])
            
            with col1:
                st.markdown("##### 1. Dosyaları Yükle")
                # Dosya yükleyicileri sıfırlamak için dinamik key kullanıyoruz
                enc_file = st.file_uploader("Şifreli resmi (.png) seçin", type=["png"], key=f"dec_enc_file_{st.session_state.reset_counter}")
                # DÜZELTME: .meta, .json ve .txt uzantılarına izin veriyoruz (telefonlarda application/json hatasını önlemek için)
                meta_file = st.file_uploader("Meta dosyasını (.meta) seçin", type=["meta", "json", "txt"], key=f"dec_meta_file_{st.session_state.reset_counter}")
                
                meta_data_available = False
                meta = {}
                ot_dt = None
                
                # Meta Veri Önizlemesi (col1'e taşındı)
                with st.container(border=True):
                    st.markdown("##### Açılma Zamanı Durumu")
                    if meta_file:
                        try:
                            # meta_file.getvalue() -> bytes; decode güvenliği için try/except
                            raw = meta_file.getvalue()
                            try:
                                meta_content = raw.decode('utf-8')
                            except Exception:
                                meta_content = raw.decode('latin-1')  # fallback
                            meta = json.loads(meta_content)
                            meta_data_available = True
                            
                            open_time_str = meta.get("open_time", "Bilinmiyor")
                            # Meta veriden okunan zamanı (TZ-naive) al ve TR saat dilimine dönüştür
                            naive_ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M")
                            ot_dt = naive_ot_dt.replace(tzinfo=TURKISH_TZ)
                            
                            # Şu anki zamanı TR saat dilimiyle al
                            now_tr = datetime.datetime.now(TURKISH_TZ)
                            # Açılma kontrolü için saniyeleri sıfırla
                            now_check = now_tr.replace(second=0, microsecond=0)
                            
                            is_open = "🔓 AÇILABİLİR" if now_check >= ot_dt else "🔒 KİLİTLİ"
                            color = "green" if now_check >= ot_dt else "red"

                            # Kalan süreyi hesapla ve göster
                            if now_check < ot_dt:
                                time_left = ot_dt - now_tr
                                
                                # Hesaplama: Gün, saat, dakika ve saniye
                                days = time_left.days
                                total_seconds = int(time_left.total_seconds())
                                hours = total_seconds // 3600
                                minutes = (total_seconds % 3600) // 60
                                
                                parts = []
                                if days > 0: parts.append(f"**{days} gün**")
                                if hours > 0: parts.append(f"**{hours} saat**")
                                if minutes > 0 or not parts: parts.append(f"**{minutes} dakika**")
                                    
                                
                                if not parts:
                                    time_left_str = "Açılma zamanı saniyeler içinde bekleniyor..."
                                else:
                                    time_left_str = "Kalan Süre: " + ", ".join(parts)
                            else:
                                time_left_str = "Açılma zamanı geldi/geçti."

                            st.markdown(
                                f"Açılma Zamanı (TR): **<span style='color:{color}; font-weight: bold;'>{open_time_str}</span>**", 
                                unsafe_allow_html=True
                            )
                            st.markdown(f"**Durum:** **<span style='color:{color};'>{is_open}</span>**", unsafe_allow_html=True)
                            st.markdown(f"*{time_left_str}*")
                            
                        except Exception as e:
                            st.error(f"Meta dosya okuma/zaman hatası: {e}")
                            log(f"Meta dosya önizleme hatası: {e}")
                    else:
                        st.info("Lütfen bir meta dosyası yükleyin.")


                st.markdown("---")
                st.markdown("##### 2. Şifreyi Gir ve Çöz")
                # Giriş değerini session state'ten alarak sıfırlama özelliğini destekliyoruz
                dec_pass = st.text_input("Görsel Şifresi (gerekliyse)", type="password", key="decrypt_pass", value=st.session_state.decrypt_pass)
                
                # Çöz ve Temizle butonlarını yan yana yerleştirelim
                col_dec_btn, col_res_btn = st.columns([2, 1])

                with col_dec_btn:
                    if st.button("🔓 Çöz", type="primary", use_container_width=True): 
                        # Çözme butonuna basıldığında tüm görsel ve mesaj durumlarını sıfırla
                        for k in ['decrypted_image', 'watermarked_image', 'is_message_visible', 'prompt_secret_key']:
                            st.session_state[k] = None
                        st.session_state.hidden_message = ""
                        st.session_state.secret_key_hash = ""
                        
                        log("--- Yeni Çözme İşlemi Başlatıldı ---")
                        
                        if not enc_file or not meta_file:
                            st.error("Lütfen hem şifreli .png hem de .meta dosyasını yükleyin.")
                        elif not meta_data_available:
                                st.error("Yüklenen meta dosyası geçerli bir JSON formatında değil.")
                        else:
                            try:
                                # dec_pass değişkeni zaten st.session_state.decrypt_pass içindeki değeri tutar
                                
                                allow_no = bool(meta.get("allow_no_password", False))
                                stored_tag = meta.get("verify_tag")
                                image_hash = meta.get("image_content_hash", "")
                                
                                st.session_state.hidden_message = meta.get("hidden_message", "")
                                st.session_state.secret_key_hash = meta.get("secret_key_hash", "")

                                # 1. Zaman kontrolü
                                if ot_dt is None:
                                    st.error("Zaman bilgisi okunamadı. Meta dosyasını kontrol edin.")
                                    st.stop()
                                    
                                # Şu anki zamanı TR saat dilimiyle al ve kontrol için saniyeyi sıfırla
                                now_tr = datetime.datetime.now(TURKISH_TZ)
                                now_check = now_tr.replace(second=0, microsecond=0)
                                
                                if now_check < ot_dt:
                                    log("Hata: Henüz zamanı gelmedi.")
                                    st.warning(f"Bu dosyanın açılmasına daha var. Açılma Zamanı: **{normalize_time(ot_dt)}**")
                                else:
                                    # 2. Şifre kontrolü
                                    current_dec_pass = st.session_state.decrypt_pass 
                                    pw_to_use = "" if allow_no else current_dec_pass
                                    
                                    if not allow_no and not current_dec_pass:
                                        log("Hata: Şifre gerekli.")
                                        st.error("Bu dosya için şifre gereklidir, ancak şifre girilmedi.")
                                    else:
                                        log("Zaman ve şifre kontrolleri tamam. Çözme işlemi başlıyor...")
                                        progress_bar = st.progress(0, text="Başlatılıyor...")
                                        enc_image_bytes = enc_file.getvalue()
                                        
                                        # 3. Çözme işlemi
                                        dec_img, key_hex = decrypt_image_in_memory(
                                            enc_image_bytes, pw_to_use, normalize_time(ot_dt), image_hash, progress_bar
                                        )
                                        
                                        if dec_img is None:
                                            pass
                                        else:
                                            # 4. Doğrulama (Verification)
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
                
                with col_res_btn:
                    # Temizle butonu artık tüm girdileri resetliyor.
                    st.button("🗑️ Temizle", on_click=reset_all_inputs, use_container_width=True, help="Şifrele ve Çöz sekmelerindeki tüm yüklenen dosyaları, şifreleri ve sonuçları siler.") 

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
                        mime="image/png"
                    )
                else:
                    st.info(caption)
                
                st.markdown("---")
                
                # --- Gizli Mesaj Gösterme Mantığı ---
                
                if st.session_state.decrypted_image is not None and st.session_state.hidden_message:
                    
                    if st.session_state.is_message_visible:
                        if st.button("Gizli Mesajı Gizle", use_container_width=True): 
                            log("Gizli mesaj gizlendi.")
                            st.session_state.is_message_visible = False
                            st.session_state.prompt_secret_key = False
                    
                    else:
                        # Mesajı göster/şifre sor
                        if st.session_state.secret_key_hash:
                            # Gizli Anahtar Girdisi
                            st.session_state.prompt_secret_key = True
                            st.markdown("**Gizli Mesaj Kilitli!**")
                            
                            # Dinamik olarak oluşturulan 'modal_pass' key'i ile input'u oluştur
                            modal_pass = st.text_input(
                                "Filigran Şifresi", 
                                type="password", 
                                key="modal_pass_input", 
                                value=st.session_state.modal_pass,
                                placeholder="Gizli mesajı görmek için şifreyi girin"
                            )
                            
                            if st.button("Filigranı Göster", key="show_watermark_btn", use_container_width=True):
                                # Şifreyi kontrol et
                                entered_hash = hashlib.sha256(modal_pass.encode('utf-8')).hexdigest()
                                
                                if entered_hash == st.session_state.secret_key_hash:
                                    log("Filigran şifresi doğru. Filigran oluşturuluyor.")
                                    
                                    # Filigranı oluştur ve state'e kaydet
                                    wm_img = add_text_watermark(st.session_state.decrypted_image, st.session_state.hidden_message)
                                    st.session_state.watermarked_image = wm_img
                                    st.session_state.is_message_visible = True
                                    st.session_state.prompt_secret_key = False # Modalı kapat
                                    st.session_state.modal_pass = '' # Şifreyi temizle
                                    st.rerun()
                                else:
                                    st.error("Yanlış Filigran Şifresi.")
                                    log("Hata: Yanlış filigran şifresi girildi.")

                        else:
                            # Gizli Anahtar yoksa mesajı direkt göster (ve filigranı ekle)
                            st.info("Gizli Mesaj Bulundu! Filigran koruması yok.")
                            if st.button("Gizli Mesajı Göster", use_container_width=True):
                                log("Gizli mesaj filigran olarak gösteriliyor.")
                                wm_img = add_text_watermark(st.session_state.decrypted_image, st.session_state.hidden_message)
                                st.session_state.watermarked_image = wm_img
                                st.session_state.is_message_visible = True
                                st.rerun()
    
elif st.session_state.current_view == 'code':
    # YENİ KOD SAYFASI GÖRÜNÜMÜ
    render_code_module()

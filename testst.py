import streamlit as st
from PIL import Image, ImageDraw, ImageFont
import hashlib, datetime, random, os, json, io
# Saat dilimi işlemleri için gerekli kütüphaneler
from zoneinfo import ZoneInfo
import time 

# Türkiye/İstanbul saat dilimi tanımı (UTC+3)
TURKISH_TZ = ZoneInfo("Europe/Istanbul")

# ----------------------------- Ayarlar ve Başlık -----------------------------
st.set_page_config(
    page_title="Zamanlı Görsel Şifreleme (🇹🇷 Saat Ayarlı)",
    page_icon="🖼️",
    layout="wide"
)

st.title("🖼️ Zamanlı Görsel Şifreleme (🇹🇷 TR Saati ile)")

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
        'generated_meta_bytes': None
    }

def init_state():
    """Tüm oturum durumlarını başlatır."""
    defaults = get_initial_state()
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

def reset_app():
    """Uygulamanın tüm oturum durumunu sıfırlar."""
    log("Uygulama sıfırlandı. Tüm görseller ve veriler temizlendi.")
    st.session_state.clear()
    init_state() # Sıfırladıktan sonra yeniden başlat
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
    """Şifre çözülmüş görselin üzerine SADECE gizli mesajı ekler."""
    img_copy = img.copy()
    draw = ImageDraw.Draw(img_copy, 'RGBA')
    w, h = img_copy.size
    
    if not hidden_message.strip():
        return img 

    text_lines = [
        "*** GİZLİ MESAJ ***",
        f"{hidden_message}"
    ]
    full_text = "\n".join(text_lines)
    
    try:
        font = ImageFont.load_default().font_variant(size=24)
    except IOError:
        font = ImageFont.load_default()
        
    text_color = (255, 0, 0, 255) # Kırmızı ve tam opak
    
    try:
        bbox = draw.textbbox((0, 0), full_text, font=font, anchor="ls")
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
    except AttributeError:
        text_w = draw.textlength(full_text, font=font)
        text_h = 24 * len(text_lines)

    padding = 15
    # Metin sağ alt köşeye yerleştirilir.
    x = w - text_w - padding * 2 
    y = h - text_h - padding * 2

    fill_color = (0, 0, 0, 180) # Siyah ve %70 opak
    draw.rectangle([x - padding, y - padding, x + text_w + padding, y + text_h + padding], fill=fill_color) 
    draw.text((x + padding, y + padding), full_text, font=font, fill=text_color)
    
    return img_copy

# ----------------------------- Örnek Resim Oluşturma -----------------------------
def create_sample_image_bytes():
    """Diske kaydetmek yerine hafızada (bytes) örnek resim oluşturur."""
    img = Image.new("RGB", (600,400), color=(70,130,180))
    for y in range(img.height):
        for x in range(img.width):
            r = 70 + int(x/img.width*80)
            g = 130 + int(y/img.height*40)
            b = 180
            img.putpixel((x,y), (r, g, b))
    
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

# ----------------------------- ARAYÜZ (UI) -----------------------------

# --- Sidebar (Kenar Çubuğu) ---
with st.sidebar:
    st.image(create_sample_image_bytes(), use_column_width=True, caption="Örnek Resim Görünümü")
    
    st.subheader("Uygulama Kontrolü")
    
    # 1. Sıfırlama Butonu
    st.button("🔄 Uygulamayı Sıfırla (Reset)", on_click=reset_app, help="Tüm yüklemeleri, logları ve çözülmüş görselleri temizler.")
    
    st.subheader("Örnek Resim")
    st.info("Test için hızlıca bir resim oluşturun ve şifreleme sekmesinden indirin.")
    
    if st.button("Örnek Resim Oluştur"):
        img_bytes = create_sample_image_bytes()
        st.session_state.generated_enc_bytes = img_bytes
        st.session_state.generated_meta_bytes = None
        log("Test için örnek resim oluşturuldu. 'Şifrele' sekmesinden indirebilirsiniz.")

    with st.expander("Yardım (Kullanım Kılavuzu)"):
        st.markdown(
            """
            **Saat Dilimi Notu:** Uygulama, açılma zamanını Türkiye saati (UTC+3) baz alarak hesaplar.
            
            **Şifreleme:**
            1. `🔒 Şifrele` sekmesine gidin.
            2. Bir resim dosyası yükleyin ve ayarları yapın.
            3. `Şifrele` butonuna basın ve `.png` ile `.meta` dosyalarını indirin.
            
            **Şifre Çözme:**
            1. `🔓 Çöz` sekmesinde iki dosyayı da yükleyin.
            2. Şifre (gerekliyse) girin ve `Çöz` butonuna basın. Resim, açılma zamanı geldiyse çözülür.
            """
        )
    
    st.subheader("İşlem Günlüğü")
    st.text_area("Loglar", value=st.session_state.get('log', ''), height=300, disabled=True, key="log_area")


# --- Ana Alan (Sekmeler) ---
tab_encrypt, tab_decrypt = st.tabs(["🔒 Şifrele", "🔓 Çöz"])

# --- ŞİFRELEME SEKMESİ ---
with tab_encrypt:
    st.subheader("Yeni Bir Görseli Şifrele")
    
    with st.form("encrypt_form"):
        uploaded_file = st.file_uploader(
            "1. Şifrelenecek resmi seçin", 
            type=["png", "jpg", "jpeg", "bmp"]
        )
        
        st.markdown("---")
        st.markdown("**Şifreleme Ayarları**")
        
        enc_pass = st.text_input("Görsel Şifresi (Çözme için)", type="password")
        enc_no_pass = st.checkbox("Şifresiz açılmaya izin ver (Sadece zaman kilidi)")
        
        enc_secret_text = st.text_area("Gizli Mesaj (Meta veriye saklanır)", placeholder="Gizli notunuz...")
        enc_secret_key = st.text_input("Gizli Mesaj Şifresi (Filigranı görmek için)", type="password", placeholder="Filigranı açacak şifre")
        
        st.markdown("---")
        st.markdown("**2. Açılma Zamanı Ayarı (Türkiye Saati ile)**")

        col_date, col_time = st.columns(2)
        
        min_date = datetime.datetime.now(TURKISH_TZ).date()
        
        with col_date:
            enc_date = st.date_input(
                "Açılma Tarihi (YYYY-AA-GG)",
                value=min_date + datetime.timedelta(days=1),
                min_value=min_date
            )

        with col_time:
            enc_time_str = st.text_input(
                "Açılma Saati (HH:MM formatında)",
                value="00:00",
                placeholder="Örn: 14:30"
            )

        # --- Zaman İşleme Başlangıcı ---
        enc_time_dt = None
        time_format_valid = False
        try:
            hour, minute = map(int, enc_time_str.split(':'))
            if 0 <= hour <= 23 and 0 <= minute <= 59:
                enc_time_val = datetime.time(hour, minute, 0)
                # Burası KRİTİK: Kullanıcının girdiği tarih/saat bilgisini al ve TZ-aware (İstanbul) yap
                naive_dt = datetime.datetime.combine(enc_date, enc_time_val).replace(second=0, microsecond=0)
                enc_time_dt = naive_dt.replace(tzinfo=TURKISH_TZ)
                
                time_format_valid = True
            else:
                st.error("Saat/Dakika değerleri geçerli aralıkta değil.")
                log("Hata: Geçersiz saat/dakika aralığı.")
        except Exception:
            st.error("Lütfen saati **HH:MM** formatında doğru girin. (Örn: 14:30)")
            log("Hata: Geçersiz saat formatı.")
            time_format_valid = False

        submitted = st.form_submit_button("🔒 Şifrele", use_container_width=True)

    if submitted:
        if not time_format_valid:
            st.warning("Lütfen zaman formatını düzeltin.")
            st.stop()
            
        # KRİTİK: Şu anki zamanı da Türkiye saati olarak al
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
                
                base_name = os.path.splitext(uploaded_file.name)[0]
                enc_filename = f"{base_name}_encrypted.png"
                meta_filename = f"{base_name}_encrypted.meta"
                
                st.download_button(
                    label="1. Şifreli Resmi (.png) İndir",
                    data=st.session_state.generated_enc_bytes,
                    file_name=enc_filename,
                    mime="image/png"
                )
                st.download_button(
                    label="2. Meta Dosyasını (.meta) İndir",
                    data=st.session_state.generated_meta_bytes,
                    file_name=meta_filename,
                    mime="application/json"
                )
            else:
                log("Şifreleme başarısız.")
                st.error("Şifreleme sırasında bir hata oluştu. Logları kontrol edin.")
    
    elif st.session_state.generated_enc_bytes and not st.session_state.generated_meta_bytes:
        st.info("Kenar çubuğunda oluşturulan örnek resmi indirin. Bu resim şifresizdir.")
        st.download_button(
            label="Örnek Resmi İndir",
            data=st.session_state.generated_enc_bytes,
            file_name="sample_for_encrypt.png",
            mime="image/png"
        )


# --- ŞİFRE ÇÖZME SEKMESİ ---
with tab_decrypt:
    st.subheader("Şifreli Bir Görseli Çöz")
    
    col1, col2 = st.columns(2)
    meta_data_placeholder = col1.empty()

    with col1:
        st.markdown("**1. Dosyaları Yükle**")
        enc_file = st.file_uploader("Şifreli resmi (.png) seçin", type="png")
        meta_file = st.file_uploader("Meta dosyasını (.meta) seçin", type="meta")
        
        meta_data_available = False
        meta = {}
        if meta_file:
            try:
                meta_content = meta_file.getvalue().decode('utf-8')
                meta = json.loads(meta_content)
                meta_data_available = True
                
                open_time_str = meta.get("open_time", "Bilinmiyor")
                # Meta veriden okunan zamanı (TZ-naive) al ve TR saat dilimine dönüştür
                naive_ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M")
                ot_dt = naive_ot_dt.replace(tzinfo=TURKISH_TZ)
                
                # KRİTİK: Şu anki zamanı da TR saat dilimiyle al
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
                    seconds = total_seconds % 60
                    
                    parts = []
                    if days > 0: parts.append(f"**{days} gün**")
                    if hours > 0: parts.append(f"**{hours} saat**")
                    if minutes > 0: parts.append(f"**{minutes} dakika**")
                    
                    # Kalan saniyeyi her zaman göster (veya en azından birimlerden biri sıfırsa)
                    if not parts or seconds > 0:
                         parts.append(f"**{seconds} saniye**")
                         
                    
                    if not parts:
                        time_left_str = "Açılma zamanı saniyeler içinde bekleniyor..."
                    else:
                        time_left_str = "Kalan Süre: " + ", ".join(parts)
                else:
                    time_left_str = "Açılma zamanı geldi/geçti."

                meta_data_placeholder.markdown(
                    f"**Açılma Zamanı Bilgisi (Türkiye Saati):**\n\n"
                    f"Bu dosya **<span style='color:{color}'>{open_time_str}</span>** tarihinde açılmak üzere ayarlanmıştır. Şu anki durumu: **{is_open}**\n\n"
                    f"{time_left_str}", 
                    unsafe_allow_html=True
                )
                
            except Exception as e:
                meta_data_placeholder.error(f"Meta dosya okuma/zaman hatası: {e}")
                log(f"Meta dosya önizleme hatası: {e}")

        st.markdown("**2. Şifreyi Gir**")
        dec_pass = st.text_input("Görsel Şifresi (gerekliyse)", type="password", key="decrypt_pass")
        
        if st.button("🔓 Çöz", use_container_width=True):
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
                    open_time_str = meta.get("open_time")
                    allow_no = bool(meta.get("allow_no_password", False))
                    stored_tag = meta.get("verify_tag")
                    image_hash = meta.get("image_content_hash", "")
                    
                    st.session_state.hidden_message = meta.get("hidden_message", "")
                    st.session_state.secret_key_hash = meta.get("secret_key_hash", "")

                    # 1. Zaman kontrolü
                    # Meta veriden okunan zamanı (TZ-naive) al ve TR saat dilimine dönüştür
                    naive_ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M")
                    ot_dt = naive_ot_dt.replace(tzinfo=TURKISH_TZ)

                    # Şu anki zamanı TR saat dilimiyle al ve kontrol için saniyeyi sıfırla
                    now_tr = datetime.datetime.now(TURKISH_TZ)
                    now_check = now_tr.replace(second=0, microsecond=0)
                    
                    if now_check < ot_dt:
                        log("Hata: Henüz zamanı gelmedi.")
                        
                        time_left = ot_dt - now_tr
                        days = time_left.days
                        total_seconds = int(time_left.total_seconds())
                        hours = total_seconds // 3600
                        minutes = (total_seconds % 3600) // 60
                        
                        st.warning(f"Bu dosyanın açılmasına daha var. \n\nAçılma Zamanı: **{open_time_str}**\nKalan Süre: **{days} gün, {hours} saat, {minutes} dakika**")
                    else:
                        # 2. Şifre kontrolü
                        pw_to_use = "" if allow_no else dec_pass
                        if not allow_no and not dec_pass:
                            log("Hata: Şifre gerekli.")
                            st.error("Bu dosya için şifre gereklidir, ancak şifre girilmedi.")
                        else:
                            log("Zaman ve şifre kontrolleri tamam. Çözme işlemi başlıyor...")
                            progress_bar = st.progress(0, text="Başlatılıyor...")
                            enc_image_bytes = enc_file.getvalue()
                            
                            # 3. Çözme işlemi
                            dec_img, key_hex = decrypt_image_in_memory(
                                enc_image_bytes, pw_to_use, open_time_str, image_hash, progress_bar
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
            st.image(image_to_show, caption=caption, use_column_width=True)
            
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
                    st.session_state.watermarked_image = None
                    st.rerun()
            else:
                if st.button("Gizli Mesajı Göster", use_container_width=True):
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

        if st.session_state.prompt_secret_key:
            st.warning("Filigranı görmek için gizli mesaj şifresini girin:")
            
            with st.form("secret_key_form"):
                entered_key = st.text_input("Gizli Mesaj Şifresi", type="password", key="modal_pass")
                submit_key = st.form_submit_button("Onayla")
                
            if submit_key:
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
        
        if st.session_state.is_message_visible and st.session_state.hidden_message:
            st.success(f"**GİZLİ MESAJ (MetaA Veri):**\n\n{st.session_state.hidden_message}")

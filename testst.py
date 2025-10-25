import streamlit as st
from PIL import Image, ImageDraw, ImageFont 
import hashlib, datetime, random, os, json, io
import zipfile 

# ----------------------------- Ayarlar ve Başlık -----------------------------
# Sayfa yapılandırması
st.set_page_config(
    page_title="Zamanlı Görsel Şifreleme - Final Düzeltme",
    page_icon="🖼️",
    layout="wide"
)

# ----------------------------- Session State (Oturum Durumu) -----------------------------
def init_state():
    """Tüm oturum durumlarını başlatır ve varsayılanları atar."""
    
    # Varsayılan başlangıç değeri: Şu andan 5 dakika sonrası
    # Bu, datetime_input'un hiçbir zaman None/eksik değerle başlamamasını sağlar.
    default_open_time = datetime.datetime.now().replace(second=0, microsecond=0) + datetime.timedelta(minutes=5)
    
    defaults = {
        'log': "",
        'decrypted_image': None,
        'watermarked_image': None,
        'hidden_message': "",
        'secret_key_hash': "",
        'is_message_visible': False,
        'prompt_secret_key': False,
        'generated_enc_bytes': None, 
        'mode': 'encrypt', 
        # encryption_start_time artık SADECE bir session state değeri tutar, input'un kendisiyle karışmaz.
        'encryption_start_time': default_open_time 
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_state()

# ----------------------------- Yardımcı Fonksiyonlar -----------------------------

def log(text):
    """Streamlit için loglama fonksiyonu. Logları session_state'e ekler."""
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    st.session_state.log = f"[{ts}] {text}\n" + st.session_state.log

def normalize_time(t):
    # datetime objesini YYYY-MM-DD HH:MM formatında döndürür
    if isinstance(t, datetime.datetime):
        return t.strftime("%Y-%m-%d %H:%M")
    return "" 

def hash_image_content(img: Image.Image) -> str:
    # Resim içeriğinin SHA256 özetini döndürür
    return hashlib.sha256(img.tobytes()).hexdigest()

def generate_key(password, open_time_str, image_hash=""):
    # Şifreleme anahtarını oluşturur
    combo = (password or "") + open_time_str + image_hash
    return hashlib.sha256(combo.encode("utf-8")).hexdigest()

def create_keystream(key_hex, w, h):
    # Anahtardan bir rastgele anahtar akışı (keystream) oluşturur
    random.seed(int(key_hex, 16))
    return [random.randint(0, 255) for _ in range(w * h * 3)]

def add_text_watermark(img: Image.Image, hidden_message: str) -> Image.Image:
    """Şifre çözülmüş görselin üzerine SADECE gizli mesajı ekler (filigran)."""
    img_copy = img.copy()
    draw = ImageDraw.Draw(img_copy, 'RGBA')
    w, h = img_copy.size
    
    if not hidden_message.strip():
        return img 

    text_lines = [
        "*** GİZLİ MESAJ (FILIGRAN) ***",
        f"{hidden_message}"
    ]
    full_text = "\n".join(text_lines)
    
    # Font yükleme denemesi
    try:
        font_path = "arial.ttf" 
        font = ImageFont.truetype(font_path, 30)
    except IOError:
        try:
            # Fallback to default font
            font = ImageFont.load_default().font_variant(size=30)
        except:
            font = ImageFont.load_default()
        
    text_color = (255, 0, 0, 255)
    
    # Text boyutunu hesapla
    try:
        bbox = draw.textbbox((0, 0), full_text, font=font) 
        text_w = bbox[2] - bbox[0]
        text_h = bbox[3] - bbox[1]
    except AttributeError:
        text_w = 400 
        text_h = 60

    x = w - text_w - 20
    y = h - text_h - 20

    padding = 10
    # Mesaj arka planı
    draw.rectangle([x - padding, y - padding, x + text_w + padding, y + text_h + padding], fill=(0, 0, 0, 150)) 
    # Mesaj metni
    draw.text((x, y), full_text, font=font, fill=text_color)
    
    return img_copy

def create_zip_archive(enc_bytes, meta_bytes, enc_filename, meta_filename):
    """Şifreli resmi ve meta veriyi içeren bir ZIP arşivi oluşturur."""
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(enc_filename, enc_bytes)
        zf.writestr(meta_filename, meta_bytes)
    return zip_buffer.getvalue()

def create_sample_image_bytes():
    """Hafızada (bytes) örnek resim oluşturur."""
    img = Image.new("RGB", (600,400), color=(70,130,180))
    for y in range(img.height):
        for x in range(img.width):
            img.putpixel((x,y), (70 + int(x/img.width*80), 130 + int(y/img.height*40), 180))
    
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_bytes = img_byte_arr.getvalue()
    log("Örnek resim hafızada oluşturuldu.")
    return img_bytes

def encrypt_image_file(image_bytes, password, open_time_dt, secret_text, secret_key, allow_no_password, progress_bar):
    """Şifreleme işlemini yapar."""
    
    if open_time_dt is None:
        log("Hata: Açılma zamanı None olarak geldi. İşlem durduruldu.")
        st.error("Şifreleme sırasında kritik hata: Geçerli bir açılma zamanı alınamadı.")
        return None, None

    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception as e:
        log(f"Hata: Resim dosyası okunamadı: {e}")
        st.error(f"Hata: Yüklenen resim dosyası açılamadı: {e}")
        return None, None

    w, h = img.size
    px = img.load()
    
    image_hash = hash_image_content(img)
    open_time_str = normalize_time(open_time_dt)
    
    key_hex = generate_key(password, open_time_str, image_hash)
    ks = create_keystream(key_hex, w, h)

    enc_img = Image.new("RGB", (w, h))
    enc_px = enc_img.load()
    i = 0
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            # XOR işlemi: Şifreleme/Şifre Çözme için aynı işlem
            enc_px[x, y] = (r ^ ks[i], g ^ ks[i+1], b ^ ks[i+2])
            i += 3
        if y % 10 == 0:
            progress_bar.progress((y + 1) / h, text="Şifreleniyor...")
            
    enc_img_byte_arr = io.BytesIO()
    enc_img.save(enc_img_byte_arr, format='PNG')
    enc_img_bytes = enc_img_byte_arr.getvalue()

    # Doğrulama Etiketi (Verify Tag)
    verify_tag = hashlib.sha256(key_hex.encode("utf-8") + img.tobytes()).hexdigest()
    secret_key_hash = hashlib.sha256(secret_key.encode('utf-8')).hexdigest() if secret_key else ""

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
    """Şifreli byte dizisini çözer ve çözülmüş PIL Image objesini döndürür."""
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

    dec_img = Image.new("RGB", (w, h))
    dec_px = dec_img.load()
    i = 0
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            # XOR işlemi (Şifrelemedekiyle aynı)
            dec_px[x, y] = (r ^ ks[i], g ^ ks[i+1], b ^ ks[i+2])
            i += 3
        if y % 10 == 0:
            progress_bar.progress((y + 1) / h, text="Şifre çözülüyor...")

    progress_bar.progress(1.0, text="Tamamlandı!")
    return dec_img, key_hex

# ----------------------------- ARAYÜZ Fonksiyonları -----------------------------

def handle_sample_creation():
    """Örnek resim oluşturma ve moda geçişi yönetir."""
    img_bytes = create_sample_image_bytes()
    st.session_state.generated_enc_bytes = img_bytes 
    st.session_state.mode = 'encrypt' 
    # Diğer durumları temizle
    st.session_state.decrypted_image = None
    st.session_state.watermarked_image = None
    st.session_state.is_message_visible = False
    st.session_state.prompt_secret_key = False
    log("Test için örnek resim oluşturuldu.")
    st.rerun()

def set_mode(new_mode):
    """Şifreleme/Çözme modunu değiştirir ve çözme sonuçlarını temizler."""
    st.session_state.mode = new_mode
    # Çözme sonuçlarını temizle
    st.session_state.decrypted_image = None
    st.session_state.watermarked_image = None
    st.session_state.is_message_visible = False
    st.session_state.prompt_secret_key = False
    # generated_enc_bytes'i sadece şifreleme modunda tutmak daha iyi
    if new_mode == 'decrypt':
         st.session_state.generated_enc_bytes = None 
    
# --- Sidebar (Kenar Çubuğu) ---
with st.sidebar:
    st.subheader("Zamanlı Şifreleme")
    st.caption("Modern arayüz")
    
    st.selectbox("Tema Seçimi:", ["Dark", "Light"], index=0, key="theme_select")
    
    # Örnek Resim Oluşturma Butonu
    st.button("Örnek Resim Oluştur", key="sidebar_sample_btn", use_container_width=True, on_click=handle_sample_creation)

    st.button("Klasörü Aç", key="sidebar_open_btn", use_container_width=True, disabled=True, help="Bu Streamlit uygulamasında sadece görsel bir düğmedir.")

    st.markdown("---")
    st.markdown("""
    **Kullanım:**
    1) Görsel seç / Örnek Oluştur
    2) Şifre (veya şifresiz zaman) ayarla
    3) Zaman gir
    4) Şifrele / Çöz butonuna bas
    """)

# ----------------------------- Ana Alan (Main Content) -----------------------------

st.title("🎴 Zaman Ayarlı Görsel Şifreleme")
col_title_controls, col_title_help = st.columns([0.9, 0.1])
with col_title_help:
    st.button("Yardım", key="help_button", type="secondary", use_container_width=True, disabled=True) 

# Ana sütunlar: Ayarlar (%40) ve Önizleme (%60)
col_settings, col_preview = st.columns([0.4, 0.6])

# --- AYARLAR SÜTUNU (COL_SETTINGS) ---
with col_settings:
    st.subheader("Dosya & Ayarlar")
    
    # ------------------ KRİTİK DÜZELTME: MOD SEÇİM DÜĞMELERİ FORMDAN ÇIKARILDI ------------------
    # Bu düğmeler formu tetiklemez ve formun dışında olmalıdır.
    col_mode_enc, col_mode_dec = st.columns([1, 1])
    
    col_mode_enc.button("🔒 Şifrele", 
                        key="mode_btn_enc", 
                        use_container_width=True, 
                        type="primary" if st.session_state.mode == 'encrypt' else 'secondary',
                        on_click=set_mode, args=('encrypt',)
                        )
    col_mode_dec.button("🔓 Çöz", 
                        key="mode_btn_dec", 
                        use_container_width=True, 
                        type="primary" if st.session_state.mode == 'decrypt' else 'secondary',
                        on_click=set_mode, args=('decrypt',)
                        )
    
    st.markdown("---")
    
    # ----------------------------- ŞİFRELEME ARAYÜZÜ -----------------------------
    if st.session_state.mode == 'encrypt':
        
        # Sadece SUBMIT butonu olan öğeler formun içinde kalmalıdır.
        with st.form("encrypt_form_dedicated", clear_on_submit=False):
            st.markdown("**Resim Seçimi**")
            
            uploaded_file = st.file_uploader(
                "Şifrelenecek resmi seçin (PNG, JPG)", 
                type=["png", "jpg", "jpeg", "bmp"],
                key="enc_file_uploader",
                label_visibility="collapsed" 
            )
            
            if st.session_state.generated_enc_bytes and not uploaded_file:
                 st.info("Kenar çubuğundan bir örnek resim yüklendi.")

            st.markdown("---")
            st.markdown("**Şifreleme Ayarları**")
            
            enc_pass = st.text_input("Görsel Şifresi (Çözme için):", type="password", key="enc_pass_input_enc")
            enc_no_pass = st.checkbox("Şifresiz açılmaya izin ver", key="enc_no_pass_checkbox_enc", help="Sadece zaman kilidi ile açılır.")
            enc_secret_text = st.text_area("Gizli Mesaj (Meta veriye saklanır):", placeholder="Gizli notunuz...", key="enc_secret_text_area_enc")
            enc_secret_key = st.text_input("Gizli Mesaj Şifresi (Filigranı görmek için):", type="password", placeholder="Filigranı açacak şifre", key="enc_secret_key_input_enc")
            
            st.markdown("---")
            st.markdown("**Açılma Zamanı**")
            
            # GÜVENLİK KONTROLÜ: Minimum 1 dakika sonrası olmalı.
            dynamic_min_value = datetime.datetime.now().replace(second=0, microsecond=0) + datetime.timedelta(minutes=1)
            
            # Eğer session state'deki zaman minimumun altındaysa, minimuma ayarla.
            if st.session_state.encryption_start_time < dynamic_min_value:
                 st.session_state.encryption_start_time = dynamic_min_value
                 log("Güvenlik: Oturum zamanı minimum değerden küçüktü, otomatik olarak güncellendi.")
            
            # AÇILMA ZAMANI (Datetime Input)
            # BURADA CRITICAL FIX: enc_time input'un anlık değeri olarak kullanılırken, 
            # st.session_state.encryption_start_time sadece kararlı başlangıç değeri sağlar.
            enc_time = st.datetime_input(
                "Açılma Zamanı (YYYY-AA-GG SS:DD):", 
                value=st.session_state.encryption_start_time, 
                min_value=dynamic_min_value, 
                key="encryption_time_input_fixed", 
                help=f"Resmin şifresi sadece bu tarih ve saatten SONRA çözülebilir. Minimum ayar: {normalize_time(dynamic_min_value)}"
            )
            
            # Input değeri değiştiğinde session state'i de hemen güncelle.
            # Bu, AttributeErrors'ın birincil kaynağını çözer.
            if enc_time is not None:
                 st.session_state.encryption_start_time = enc_time
            
            # Şifrele Butonu (st.form_submit_button)
            submitted = st.form_submit_button("🔒 Şifrele", use_container_width=True, type="primary")

        # Şifreleme İşlemi Mantığı
        if submitted:
            time_to_use = enc_time
            
            file_for_enc = uploaded_file or (
                io.BytesIO(st.session_state.generated_enc_bytes) if st.session_state.generated_enc_bytes else None
            )

            if file_for_enc is None:
                st.error("Lütfen önce bir resim dosyası yükleyin veya örnek oluşturun.")
            elif time_to_use is None:
                 st.error("Lütfen geçerli bir açılma zamanı seçin.")
            else:
                log("Şifreleme başlatıldı...")
                
                image_bytes = file_for_enc.getvalue()
                pw_to_use = "" if enc_no_pass else enc_pass
                
                progress_placeholder = st.empty()
                progress_bar = progress_placeholder.progress(0, text="Başlatılıyor...")

                enc_bytes, meta_bytes = encrypt_image_file(
                    image_bytes, pw_to_use, time_to_use, 
                    enc_secret_text, enc_secret_key, enc_no_pass,
                    progress_bar
                )
                progress_placeholder.empty()
                
                if enc_bytes and meta_bytes:
                    log("Şifreleme tamamlandı. Dosyalar indirilmeye hazır.")
                    st.success("Şifreleme Başarılı! Oluşturulan ZIP dosyasını indirin.")
                    
                    base_name = os.path.splitext(uploaded_file.name if uploaded_file else "sample")[0]
                    enc_filename = f"{base_name}_encrypted.png"
                    meta_filename = f"{base_name}_encrypted.meta"
                    zip_filename = f"{base_name}_encrypted_files.zip"

                    zip_bytes = create_zip_archive(enc_bytes, meta_bytes, enc_filename, meta_filename)

                    st.download_button(
                        label="ZIP İndir (Şifreli Resim ve Meta)",
                        data=zip_bytes,
                        file_name=zip_filename,
                        mime="application/zip",
                        key="download_zip_button",
                        use_container_width=True
                    )
                    
                else:
                    log("Şifreleme başarısız.")
    
    # ----------------------------- ŞİFRE ÇÖZME ARAYÜZÜ -----------------------------
    else: # st.session_state.mode == 'decrypt'
        
        meta_data_placeholder = st.empty()

        # Çözme formu
        with st.form("decrypt_form_dedicated", clear_on_submit=False):
            st.markdown("**Şifreli Dosyaları Yükle**")
            enc_file = st.file_uploader("Şifreli resmi (.png) seçin", type="png", key="dec_enc_file_uploader")
            meta_file = st.file_uploader("Meta dosyasını (.meta) seçin", type="meta", key="dec_meta_file_uploader")
            
            st.markdown("---")
            st.markdown("**Şifreyi Gir**")
            dec_pass = st.text_input("Görsel Şifresi (gerekliyse)", type="password", key="decrypt_pass_dec")
            
            # SADECE FORM SUBMIT BUTONU KALDI
            dec_submitted = st.form_submit_button("🔓 Çöz", use_container_width=True, type="primary")

        # Meta Veri Önizlemesi (Dosya yüklenince hemen gösterilir, formun dışında)
        meta_data_available = False
        meta = {}
        if meta_file:
            try:
                meta_content = meta_file.getvalue().decode('utf-8')
                meta = json.loads(meta_content)
                meta_data_available = True
                
                open_time_str = meta.get("open_time", "Bilinmiyor")
                ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M")
                
                now = datetime.datetime.now()
                is_open = "🔓 AÇILABİLİR" if now >= ot_dt else "🔒 KİLİTLİ"
                color = "green" if now >= ot_dt else "red"
                current_time_str = normalize_time(now)

                meta_data_placeholder.markdown(
                    f"**Açılma Zamanı Bilgisi:**\n\n"
                    f"- Hedeflenen Açılma Zamanı: **<span style='color:{color}'>{open_time_str}</span>**\n"
                    f"- Şu Anki Zaman: **{current_time_str}**\n\n"
                    f"Durum: **{is_open}**", 
                    unsafe_allow_html=True
                )
                
            except Exception as e:
                meta_data_placeholder.error("Meta dosya okuma hatası veya geçersiz format.")
                log(f"Meta dosya önizleme hatası: {e}")
        else:
             meta_data_placeholder.info("Lütfen .meta dosyasını yükleyiniz.")


        # Şifre Çözme İşlemi Mantığı
        if dec_submitted:
            # Önceki sonuçları temizle
            for k in ['decrypted_image', 'watermarked_image', 'is_message_visible', 'prompt_secret_key']:
                st.session_state[k] = None
                
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

                    now = datetime.datetime.now()
                    ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M")
                    
                    if now < ot_dt:
                        log("Hata: Henüz zamanı gelmedi.")
                        st.warning(f"Bu dosyanın açılmasına daha var. Açılma Zamanı: {open_time_str}")
                    else:
                        pw_to_use = "" 
                        
                        should_proceed = True
                        if not allow_no and not dec_pass: 
                            log("Hata: Şifre gerekli ancak girilmedi.")
                            st.error("Bu dosya için görsel şifresi gereklidir, ancak şifre girilmedi.")
                            should_proceed = False
                        elif not allow_no:
                             pw_to_use = dec_pass
                        
                        if should_proceed:
                            log("Zaman ve şifre kontrolleri tamam. Çözme işlemi başlıyor...")
                            progress_placeholder = st.empty()
                            progress_bar = progress_placeholder.progress(0, text="Başlatılıyor...")
                            enc_image_bytes = enc_file.getvalue()
                            
                            dec_img, key_hex = decrypt_image_in_memory(
                                enc_image_bytes, pw_to_use, open_time_str, image_hash, progress_bar
                            )
                            progress_placeholder.empty()
                            
                            if dec_img is None:
                                pass # Hata zaten decrypt_image_in_memory içinde loglandı
                            else:
                                # Doğrulama Etiketi Kontrolü
                                calc_tag = hashlib.sha256(key_hex.encode("utf-8") + dec_img.tobytes()).hexdigest()
                                
                                if calc_tag != stored_tag:
                                    log("Doğrulama başarısız: Yanlış şifre veya bozuk dosya.")
                                    st.error("Çözme Hatası: Yanlış şifre girildi veya dosyalar bozulmuş.")
                                    st.session_state.decrypted_image = None
                                else:
                                    log("Doğrulama başarılı! Resim çözüldü.")
                                    st.success("Görselin şifresi başarıyla çözüldü!")
                                    st.session_state.decrypted_image = dec_img 
                                    st.rerun() # Önizlemeyi güncellemek için rerunu çağırıyoruz
                                        
                except Exception as e:
                    log(f"Çözme hatası: {e}")
                    st.error(f"Çözme sırasında beklenmedik bir hata oluştu: {e}")


# --- ÖNİZLEME SÜTUNU (COL_PREVIEW) ---
with col_preview:
    st.subheader("Önizleme")
    
    image_to_show = None
    caption = "(Resim seçilmedi)"
    
    # 1. Filigranlı resim
    if st.session_state.is_message_visible and st.session_state.watermarked_image is not None:
        image_to_show = st.session_state.watermarked_image
        caption = "Çözülmüş Görüntü (Filigranlı)"
    # 2. Şifresi çözülmüş orijinal resim
    elif st.session_state.decrypted_image is not None:
        image_to_show = st.session_state.decrypted_image
        caption = "Çözülmüş Görüntü (Orijinal)"
    # 3. Şifreleme modundaki önizleme
    elif st.session_state.mode == 'encrypt':
        current_file = st.session_state.get('enc_file_uploader')
        if current_file:
             try:
                image_to_show = Image.open(current_file)
                caption = "Yüklenen Orijinal Resim"
             except:
                 pass
        elif st.session_state.generated_enc_bytes:
             try:
                 image_to_show = Image.open(io.BytesIO(st.session_state.generated_enc_bytes))
                 caption = "Oluşturulan Örnek Resim"
             except:
                 pass

    
    # Önizleme alanı
    if image_to_show:
        st.image(image_to_show, caption=caption, use_container_width=True)
        
        # İndirme butonu
        img_byte_arr = io.BytesIO()
        image_to_show.save(img_byte_arr, format='PNG')
        
        st.markdown("<br>", unsafe_allow_html=True)
        st.download_button(
            label="Görüntülenen Resmi İndir",
            data=img_byte_arr.getvalue(),
            file_name="displayed_image.png",
            mime="image/png",
            key="download_displayed_image_button_preview",
            use_container_width=True
        )

    else:
        st.markdown(f"<div style='text-align: center; color: #888; padding: 150px 0;'>{caption}</div>", unsafe_allow_html=True)
        st.markdown("<br><br><br><br><br>", unsafe_allow_html=True) 


    st.markdown("---") 

    # --- İşlem Günlüğü ve Gizli Mesaj Kontrolü ---
    
    st.subheader("İşlem Günlüğü")
    log_area_placeholder = st.empty()
    log_area_placeholder.text_area("Loglar", value=st.session_state.log, height=150, disabled=True, key="log_area_preview", label_visibility="collapsed")
    
    # Gizli Mesaj Göster/Gizle Butonu (Sağ altta)
    if st.session_state.decrypted_image is not None and st.session_state.hidden_message:
        
        # Gizli anahtar sorma arayüzü
        if st.session_state.prompt_secret_key:
            st.warning("Filigranı görmek için gizli mesaj şifresini girin:")
            
            col_pass_in, col_pass_btn = st.columns([2, 1])
            entered_key = col_pass_in.text_input("Gizli Mesaj Şifresi", type="password", key="modal_pass_new_preview", label_visibility="collapsed")
            
            if col_pass_btn.button("Onayla ve Göster", key="secret_key_submit_new_preview", use_container_width=True):
                if not entered_key:
                    st.error("Lütfen şifreyi giriniz.")
                else:
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

        # Gizli Mesajı Göster/Gizle butonu
        if st.session_state.is_message_visible:
            if st.button("Gizli Mesajı Gizle", key="hide_secret_btn_preview", use_container_width=True, type="secondary"):
                log("Gizli mesaj gizlendi.")
                st.session_state.is_message_visible = False
                st.session_state.prompt_secret_key = False
                st.rerun()
        else:
            if st.button("Gizli Mesajı Göster", key="show_secret_btn_preview", use_container_width=True, type="primary"):
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
    else:
        st.button("Gizli Mesajı Göster", key="dummy_secret_btn", use_container_width=True, disabled=True, help="Şifre çözülmedi veya gizli mesaj yok.")

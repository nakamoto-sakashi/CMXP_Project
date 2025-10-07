# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
# (Wallet GUI - Fully Functional and Stabilized Implementation)

import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel, ttk, filedialog
import json, os, requests, hashlib, threading, base64
import traceback # 상세 오류 추적용
import sys
import pkg_resources # 자가 진단용

# (중요) 자가 진단을 위한 임포트 시도
try:
    # bip_utils의 wordlists 모듈 위치 확인 시도
    import bip_utils.bip.bip39.wordlists as wordlists_module
except ImportError:
    wordlists_module = None
except Exception as e:
    print(f"Warning: Could not import wordlists_module: {e}")
    wordlists_module = None

from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39MnemonicValidator, Bip44, Bip44Coins, Bip44Changes, Bip39Languages
# QR 코드 생성을 위한 라이브러리 임포트
import qrcode
from PIL import Image, ImageTk
    
# core.py 임포트 (동일 디렉토리 필요)
try:
    # core.py의 경로는 실제 환경에 맞게 조정해야 할 수 있습니다.
    from core import Transaction 
except ImportError as e:
    print(f"Warning: core.py not found. Transaction functionality will be disabled. Error: {e}")
    Transaction = None
    
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import ecdsa

# --- Configuration ---
# 노드 주소 설정 (개발 환경 기준, 배포 시 변경 가능)
NODE_URL = "https://cmxp-node.onrender.com" 
DEFAULT_WALLET_EXT = ".dat"

# 스타일 테마
BG_COLOR = "#282c34"; FG_COLOR = "#abb2bf"; ACCENT_COLOR = "#61afef"
SUCCESS_COLOR = "#98c379"; ERROR_COLOR = "#e06c75"; BUTTON_BG = "#3e4451"; ENTRY_BG = "#1e2229"
FONT_FAMILY = "Arial"; FONT_SIZE_LARGE = 18; FONT_SIZE_NORMAL = 12; FONT_SIZE_SMALL = 9
FONT_MONO = "Consolas"

# --- Base64 Encoded Icons (No external files needed) ---
ICON_DATA = {
    "send": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAAbwAAAG8B8aLcQwAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAADdSURBVDiNpdOxSgNREAbge/s2BAWFLQSFrbWNCGKLELoEg/XgYyDo7gV0gT2Ena2thZ2FhXAE23oDm28g3Yij8fE2YAI/fJgZ5j8zcpbl51CWYarBDaM8w8SoFjgGnHf5UeH4T0K4bIMdNmDAWaDUSa8l2NQPfGGFtYD1gX1nQKsDwwLvjV7Z+a1I/dEAS50e2LqABb4aGtFoAAVw9sCnSg8/O8U6tG4E590y2NUNvExg5Y+o4Jd/4yAt4wY4gV0wADfAADTCOw/wDgeY9o1fAXc5H8AFrvE2wZ9m2FVg2AZG6fIEP/g2/wFNqYgNDyPZ3AAAAABJRU5ErkJggg==",
    "copy": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAAbwAAAG8B8aLcQwAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAEGSURBVDjLpZJfSgNREIW/iw+gLg2CICLoBknBzsKKaC9U5Aso+x/Uu2hXV/oDRf4DN+7VymhXrZTQoIMODofH3DvnzJ12cnIyFsdxFoqiOM/zLEsSDAAODwcAT09Pdk5OTmZxcbF9fX2V7e3tMcbYTCaTyWQyqsdxuY3jGO/U+VsUhaIothG1Pj4+slwup2KxWJVKpeF2u43x3iilUqk0m80lAJ/PhxBCaa1/b/9tA1gohBCI7BljsVgsx3E8z3Odcl2XxWIxGo0mUq/XaLTb7ZRSb7fbjDEIIWBJkgghsCxLxnG82u1WjDEZY9fXV5RSxhjjGZZlc3t7Syml0+mU/wMo2gK5nHhZpgAAAABJRU5ErkJggg==",
    "refresh": "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAAbwAAAG8B8aLcQwAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAAAFnSURBVDjLjZJPSwJREIW/N1nGNjOkJcgyCMp4C4m7iG78B7oJ3bZ1J+i/0FdQXdBN6O6CCm4UfAXXpSAh9Lw1P4z3gbkzhvfs+c537pxx/IsgCKIqy5p2nVeAcyyLpmnGcVwB9wF7Q+gKPAJOApvB8BO6rAD+gI1hGAbDMEzoZMLfP0DjMaZpjGn7/Qk8A54DHbB2MMwBf8HwT5rRABfg/QkcxpEG0G0g3gKngCvgH3gBjsNwdL75+AFpGkaIURQlx2EUmQd7pNTM5NlRUYQAHDpYpW9A/gYciMIwChgE06QIjIMyCsy+gD4CzgK7JAzD2GMEnoAdMOsC0xRgkR4XBWgA6wBnwE1gN7gBfh8TcrA9gSbgFHgT+A1W6fWAmv4Gq3y+D+A1cDUq/D3QU2j+q/19B/gB3ADf7p/4BHgCvBw5w2wm4ewP4B/gG5s/y4wUJlOgAAAAAElFTkwiniw=="
}

# --- 자가 진단 함수: EXE 파일에 데이터가 포함되었는지 확인 ---
def check_bip_utils_resources():
    if wordlists_module is None:
        return "FAILED: bip_utils wordlists module could not be imported. (Check PyInstaller hidden imports)"
        
    resource_path = "Unknown"
    try:
        # pkg_resources를 사용하여 파일 경로 찾기 (bip_utils의 방식)
        # 이 방식은 PyInstaller 환경에서도 작동해야 합니다.
        resource_path = pkg_resources.resource_filename(wordlists_module.__name__, "english.txt")
        
        # 경로 존재 여부 확인
        if not os.path.exists(resource_path):
            # PyInstaller 환경(_MEIPASS)에서 대체 경로 확인 (안전장치)
            if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                # 빌드 명령어의 --add-data 대상 경로와 일치해야 함
                meipass_path = os.path.join(sys._MEIPASS, 'bip_utils', 'bip', 'bip39', 'wordlists', 'english.txt')
                if os.path.exists(meipass_path):
                    # pkg_resources가 MEIPASS 경로를 인식하지 못할 수 있지만 파일이 존재하면 OK
                    return "PASSED (via MEIPASS fallback)"
                else:
                    return f"FAILED: Cannot find english.txt.\nChecked:\n1. pkg_resources: {resource_path}\n2. MEIPASS: {meipass_path}\n\n(Check PyInstaller --add-data path)"
            else:
                 return f"FAILED: Cannot find english.txt at: {resource_path} (Check installation)"
        
        # 파일 내용 확인 (첫 단어: abandon)
        with open(resource_path, 'r', encoding='utf-8') as f:
            if f.readline().strip() != "abandon":
                return f"FAILED: english.txt content is incorrect."
        
        return "PASSED"
    except Exception as e:
        return f"FAILED with unexpected error: {type(e).__name__} (Path: {resource_path})\nTraceback:\n{traceback.format_exc()}"

# --- 암호화/복호화 함수 (에러 핸들링 강화) ---
def encrypt_mnemonic(password, mnemonic_str):
    try:
        salt = get_random_bytes(16)
        # AES-256 사용 (dklen=32), PBKDF2 사용
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32) 
        cipher = AES.new(key, AES.MODE_GCM)
        # 안정성을 위해 항상 str()로 변환 후 인코딩
        ciphertext, tag = cipher.encrypt_and_digest(str(mnemonic_str).encode('utf-8'))
        return {'salt': salt.hex(), 'nonce': cipher.nonce.hex(), 'ciphertext': ciphertext.hex(), 'tag': tag.hex()}
    except Exception as e:
        # 암호화 라이브러리 실패 시 명시적 예외 발생
        raise RuntimeError(f"Encryption failed (Crypto library error): {e}")

def decrypt_mnemonic(password, encrypted_data):
    try:
        salt = bytes.fromhex(encrypted_data['salt']); nonce = bytes.fromhex(encrypted_data['nonce'])
        ciphertext = bytes.fromhex(encrypted_data['ciphertext']); tag = bytes.fromhex(encrypted_data['tag'])
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_mnemonic_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_mnemonic_bytes.decode('utf-8')
    except (ValueError, KeyError, TypeError):
        return None # 비밀번호 불일치 또는 데이터 손상
    except Exception as e:
        raise RuntimeError(f"Decryption failed (Crypto library error): {e}")

# --- Wallet 클래스 (에러 핸들링 강화) ---
class Wallet:
    def __init__(self, mnemonic=None):
        try:
            if mnemonic:
                self.mnemonic = str(mnemonic)
            else:
                # 니모닉 생성 (Wordlist 접근 필요)
                self.mnemonic = str(Bip39MnemonicGenerator().FromWordsNumber(12))
                
            self.private_key, self.address = self._derive_keys(self.mnemonic)
        except Exception as e:
            # 키 유도 실패 시 명시적 예외 발생 (bip_utils 또는 coincurve 문제)
            # 이는 주로 wordlist 누락 또는 C++ 라이브러리 누락 시 발생합니다.
            raise RuntimeError(f"Wallet initialization failed (Key derivation error): {e}")

    def _derive_keys(self, mnemonic_str):
        seed_bytes = Bip39SeedGenerator(mnemonic_str).Generate()
        # Bip44Coins.BITCOIN은 예시이며, CMXP 전용 코인 타입을 정의할 수도 있습니다.
        bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        bip44_acc = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        return bip44_acc.PrivateKey(), bip44_acc.PublicKey().RawCompressed().ToHex()

    def sign_transaction(self, recipient, amount):
        if Transaction is None:
            raise ImportError("Transaction module (core.py) not available.")
        try:
            amount_float = float(amount)
            if amount_float <= 0:
                raise ValueError("Amount must be positive.")
        except ValueError as e:
            raise ValueError(f"Invalid amount: {e}")

        tx = Transaction(self.address, recipient, amount_float)
        tx_hash = tx.calculate_hash()
        pk_bytes = self.private_key.Raw().ToBytes()
        try:
            signing_key = ecdsa.SigningKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
            signature = signing_key.sign(tx_hash.encode())
        except Exception as e:
             raise RuntimeError(f"Signing failed (ECDSA/Coincurve error): {e}")

        tx.signature = signature
        return tx.to_dict()

# --- GUI Application ---
class WalletApp:
    def __init__(self, root):
        self.root = root
        self.wallet = None
        self.current_wallet_file = None
        self.qr_image = None
        self.node_url = NODE_URL
        self.icons = {} # 아이콘 PhotoImage 객체 저장
        self.load_icons()
        self.setup_styles()
        self.show_welcome_screen()
        self.root.after(100, self.run_diagnostics)

    def load_icons(self):
        for name, data in ICON_DATA.items():
            try:
                image_data = base64.b64decode(data)
                self.icons[name] = tk.PhotoImage(data=image_data)
            except Exception as e:
                print(f"Warning: Could not load icon '{name}': {e}")
                self.icons[name] = None
                
    def run_diagnostics(self):
        result = check_bip_utils_resources()
        if result != "PASSED" and not result.startswith("PASSED"):
            self.root.lift() # 창을 최상단으로
            messagebox.showerror(
                "Diagnostic Failure (EXE Packaging Issue)",
                f"WARNING: Essential data files (BIP39 Wordlists) are inaccessible.\n\n"
                f"Wallet creation and restoration will likely FAIL.\n\n"
                f"Cause: Files were missed during the PyInstaller build process.\n\n"
                f"Details:\n{result}"
            )

    def setup_styles(self):
        self.root.configure(bg=BG_COLOR); self.root.geometry("800x720")
        self.style = ttk.Style(); self.style.theme_use('clam')
        self.style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL))
        self.style.configure("TButton", background=BUTTON_BG, foreground=FG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"), padding=8)
        self.style.map("TButton", background=[('active', ACCENT_COLOR)])
        # 성공 피드백용 스타일 (Copy 버튼)
        self.style.configure("Success.TButton", foreground=SUCCESS_COLOR)
        self.style.configure("TEntry", fieldbackground=ENTRY_BG, foreground=FG_COLOR, insertcolor=FG_COLOR)
        self.style.configure("TFrame", background=BG_COLOR)
        self.style.configure("Title.TLabel", font=(FONT_FAMILY, FONT_SIZE_LARGE, "bold"), foreground=ACCENT_COLOR)
        self.style.configure("TProgressbar", background=SUCCESS_COLOR, troughcolor=BUTTON_BG)
        # 탭 스타일 설정
        self.style.configure("TNotebook", background=BG_COLOR)
        self.style.configure("TNotebook.Tab", background=BUTTON_BG, foreground=FG_COLOR, padding=[20, 10], font=(FONT_FAMILY, 13, 'bold'))
        self.style.map("TNotebook.Tab",
                       background=[("selected", BG_COLOR)],
                       foreground=[("selected", ACCENT_COLOR)],
                       padding=[("selected", [25, 12])])
        self.update_title()

    def update_title(self):
        title = "CMXP Wallet"
        if self.current_wallet_file:
            filename = os.path.basename(self.current_wallet_file)
            title += f" - [{filename}]"
        self.root.title(title)
        
    def setup_menu(self):
        menubar = tk.Menu(self.root, bg=BG_COLOR, fg=FG_COLOR); self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0, bg=BUTTON_BG, fg=FG_COLOR)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Wallet...", command=self.create_new_wallet_flow)
        file_menu.add_command(label="Open Wallet...", command=self.open_wallet_flow)
        file_menu.add_separator()
        file_menu.add_command(label="Restore Wallet (Mnemonic)...", command=self.restore_wallet_flow)
        if self.wallet:
            file_menu.add_separator()
            file_menu.add_command(label="Close Wallet", command=self.close_wallet)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)

    def clear_screen(self):
        self.root.config(menu="")
        for widget in self.root.winfo_children():
            widget.destroy()
            
    def show_loading(self, message="Loading..."):
        self.clear_screen()
        frame = ttk.Frame(self.root)
        frame.pack(expand=True)
        ttk.Label(frame, text=message, font=(FONT_FAMILY, FONT_SIZE_LARGE)).pack(pady=20)
        progress = ttk.Progressbar(frame, orient="horizontal", length=200, mode="indeterminate")
        progress.pack(pady=10)
        progress.start()

    def show_welcome_screen(self):
        self.clear_screen()
        self.setup_menu()
        self.update_title()
        frame = ttk.Frame(self.root)
        frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        ttk.Label(frame, text="Welcome to CMXP Wallet", style="Title.TLabel").pack(pady=20)
        ttk.Button(frame, text="Open Wallet File (.dat)...", command=self.open_wallet_flow).pack(pady=10, fill='x')
        ttk.Separator(frame, orient='horizontal').pack(pady=15, fill='x')
        ttk.Button(frame, text="Create New Wallet...", command=self.create_new_wallet_flow).pack(pady=10, fill='x')
        ttk.Button(frame, text="Restore Wallet (Mnemonic)...", command=self.restore_wallet_flow).pack(pady=10, fill='x')

    def close_wallet(self):
        self.wallet = None
        self.current_wallet_file = None
        self.show_welcome_screen()

    # --- 지갑 관리 흐름 (Flows) ---
    def open_wallet_flow(self):
        self.root.update_idletasks()
        filepath = filedialog.askopenfilename(
            parent=self.root,
            title="Open Wallet File",
            filetypes=[("CMXP Wallet Files", f"*{DEFAULT_WALLET_EXT}")]
        )
        if not filepath: return

        password = self.ask_for_password(f"Enter password for {os.path.basename(filepath)}:")
        if not password: return

        self.show_loading("Unlocking wallet...")
        threading.Thread(target=self.unlock_wallet_thread, args=(filepath, password), daemon=True).start()

    def create_new_wallet_flow(self):
        self.root.update_idletasks()
        filepath = filedialog.asksaveasfilename(
            parent=self.root,
            title="Create New Wallet File",
            initialfile="wallet" + DEFAULT_WALLET_EXT,
            defaultextension=DEFAULT_WALLET_EXT,
            filetypes=[("CMXP Wallet Files", f"*{DEFAULT_WALLET_EXT}")]
        )
        if not filepath: return

        password = self.ask_for_new_password()
        if not password: return

        self.show_loading("Generating new wallet...")
        threading.Thread(target=self.wallet_operation_thread, args=("create", filepath, password, None), daemon=True).start()

    def restore_wallet_flow(self):
        self.root.update_idletasks()
        mnemonic = simpledialog.askstring("Restore Wallet", "Enter your 12 mnemonic words:", parent=self.root)
        if not mnemonic: return
        
        mnemonic = ' '.join(mnemonic.strip().split())
        
        try:
            validator = Bip39MnemonicValidator(lang=Bip39Languages.ENGLISH)
            if not validator.IsValid(mnemonic):
                raise ValueError("Invalid structure, unknown words, or incorrect checksum.")
        except Exception as e:
            diag_result = check_bip_utils_resources()
            error_message = (f"Mnemonic validation failed.\n\n"
                             f"Details: {e}\n\nDiagnostic Check Result: {diag_result}")
            messagebox.showerror("Error", error_message)
            return

        filepath = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save Restored Wallet As",
            initialfile="restored_wallet" + DEFAULT_WALLET_EXT,
            defaultextension=DEFAULT_WALLET_EXT,
            filetypes=[("CMXP Wallet Files", f"*{DEFAULT_WALLET_EXT}")]
        )
        if not filepath: return

        password = self.ask_for_new_password()
        if not password: return

        self.show_loading("Restoring wallet...")
        threading.Thread(target=self.wallet_operation_thread, args=("restore", filepath, password, mnemonic), daemon=True).start()

    # --- 백그라운드 스레드 작업 ---
    def unlock_wallet_thread(self, filepath, password):
        try:
            with open(filepath, 'r') as f: encrypted_data = json.load(f)
            mnemonic = decrypt_mnemonic(password, encrypted_data)
            
            if mnemonic:
                self.wallet = Wallet(mnemonic)
                self.current_wallet_file = filepath
                self.root.after(0, self.show_main_screen)
            else:
                self.root.after(0, self.handle_failure, "Wrong password or corrupted file.", self.show_welcome_screen)
        except Exception as e:
             traceback_str = traceback.format_exc()
             error_message = (f"Failed to unlock wallet.\n\n"
                              f"Error Type: {type(e).__name__}\nDetails: {e}\n\n"
                              f"Traceback:\n{traceback_str}")
             self.root.after(0, self.handle_failure, error_message, self.show_welcome_screen)

    def wallet_operation_thread(self, operation, filepath, password, mnemonic):
        try:
            if operation == "create":
                temp_wallet = Wallet() 
                mnemonic = temp_wallet.mnemonic
            else: # restore
                temp_wallet = Wallet(mnemonic)

            encrypted_data = encrypt_mnemonic(password, mnemonic)

            with open(filepath, 'w') as f: 
                json.dump(encrypted_data, f)
            
            self.wallet = temp_wallet
            self.current_wallet_file = filepath
            
            if operation == "create":
                self.root.after(0, self.show_backup_screen, mnemonic)
            else:
                self.root.after(0, lambda: messagebox.showinfo("Success", "Wallet restored successfully."))
                self.root.after(0, self.show_main_screen)
        except Exception as e:
            if os.path.exists(filepath):
                try: os.remove(filepath)
                except: pass
            
            traceback_str = traceback.format_exc()
            error_message = (f"Operation failed.\n\n"
                             f"Error Type: {type(e).__name__}\nDetails: {e}\n\n"
                             f"Traceback:\n{traceback_str}")
            self.root.after(0, self.handle_failure, error_message, self.show_welcome_screen)

    def handle_failure(self, message, retry_func=None):
        self.root.lift()
        messagebox.showerror("Error", message)
        if retry_func:
            retry_func()

    # --- UI 컴포넌트 및 화면 ---
    def ask_for_password(self, prompt):
        self.root.update_idletasks()
        return simpledialog.askstring("Password", prompt, parent=self.root, show='*')

    def ask_for_new_password(self):
        dialog = Toplevel(self.root)
        dialog.title("Set Password"); dialog.configure(bg=BG_COLOR)
        dialog.transient(self.root)
        
        ttk.Label(dialog, text="Create a strong password for your wallet.").pack(pady=10, padx=20)
        frame = ttk.Frame(dialog, padding=10); frame.pack()
        ttk.Label(frame, text="New Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        pass_entry1 = ttk.Entry(frame, show='*', width=30); pass_entry1.grid(row=0, column=1, pady=5)
        ttk.Label(frame, text="Confirm Password:").grid(row=1, column=0, sticky=tk.W, pady=5)
        pass_entry2 = ttk.Entry(frame, show='*', width=30); pass_entry2.grid(row=1, column=1, pady=5)
        pass_entry1.focus_set()

        password = None
        def on_ok(event=None):
            nonlocal password
            p1, p2 = pass_entry1.get(), pass_entry2.get()
            if not p1: messagebox.showerror("Error", "Password cannot be empty.", parent=dialog); return
            if p1 != p2: messagebox.showerror("Error", "Passwords do not match.", parent=dialog); return
            password = p1
            dialog.destroy()

        def on_cancel(event=None):
             dialog.destroy()

        dialog.bind('<Return>', on_ok); dialog.bind('<Escape>', on_cancel)
        btn_frame = ttk.Frame(dialog); btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="OK", command=on_ok).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)

        dialog.grab_set()
        self.root.wait_window(dialog) 
        return password
    
    def show_backup_screen(self, mnemonic):
        self.clear_screen(); self.setup_menu(); self.update_title()
        frame = ttk.Frame(self.root, padding=30); frame.pack(expand=True, fill='both')

        ttk.Label(frame, text="!! Backup Your Recovery Phrase !!", foreground=ERROR_COLOR, font=(FONT_FAMILY, FONT_SIZE_LARGE, "bold")).pack(pady=15)
        ttk.Label(frame, text="Write down these 12 words securely. This is the ONLY way to recover your wallet.", justify=tk.CENTER).pack(pady=10)

        mnemonic_text = tk.Text(frame, height=4, width=60, wrap=tk.WORD, font=(FONT_MONO, 12, "bold"), bg=BUTTON_BG, fg=FG_COLOR, relief=tk.FLAT, padx=10, pady=10)
        mnemonic_text.insert(tk.END, mnemonic); mnemonic_text.config(state=tk.DISABLED); mnemonic_text.pack(pady=20)
        
        confirm_var = tk.IntVar()
        check = tk.Checkbutton(frame, text="I have securely stored my recovery phrase.", variable=confirm_var, bg=BG_COLOR, fg=FG_COLOR, selectcolor=BG_COLOR, activebackground=BG_COLOR, activeforeground=ACCENT_COLOR)
        check.pack(pady=15)

        def on_continue():
            if confirm_var.get() == 1: self.show_main_screen()
            else: messagebox.showwarning("Warning", "You must back up your phrase before continuing.")

        ttk.Button(frame, text="Continue", command=on_continue).pack(pady=10)

    def show_main_screen(self):
        self.clear_screen()
        self.setup_menu()
        self.update_title()
        
        # --- Status Bar (하단 노드 상태 표시줄) ---
        status_bar = ttk.Frame(self.root, padding=5)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(status_bar, text="Node Status:").pack(side=tk.LEFT, padx=(5,0))
        self.node_status_label = ttk.Label(status_bar, text="Syncing...", foreground=ACCENT_COLOR, font=(FONT_FAMILY, 10))
        self.node_status_label.pack(side=tk.LEFT, padx=(5,0))

        # --- Header Frame (잔액) ---
        header_frame = ttk.Frame(self.root, padding=15)
        header_frame.pack(fill=tk.X)
        ttk.Label(header_frame, text="Balance:", font=(FONT_FAMILY, FONT_SIZE_LARGE)).pack(side=tk.LEFT, anchor='s')
        # 폰트 일관성 적용
        self.balance_label = ttk.Label(header_frame, text="Syncing...", font=(FONT_MONO, FONT_SIZE_LARGE, "bold"), foreground=ACCENT_COLOR)
        self.balance_label.pack(side=tk.LEFT, padx=10, anchor='s')
        # 아이콘 적용
        self.refresh_button = ttk.Button(header_frame, text="Refresh", image=self.icons.get("refresh"), compound="left", command=self.refresh_balance)
        self.refresh_button.pack(side=tk.RIGHT)

        # --- Tab Control (메인 컨텐츠) ---
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill='both', padx=10, pady=5)
        send_frame = ttk.Frame(notebook, padding=20)
        receive_frame = ttk.Frame(notebook, padding=20)
        notebook.add(send_frame, text='  Send  ')
        notebook.add(receive_frame, text='  Receive  ')
        
        self.setup_send_tab(send_frame)
        self.setup_receive_tab(receive_frame)
        self.refresh_balance()

    def setup_send_tab(self, frame):
        ttk.Label(frame, text="Send CMXP", style="Title.TLabel").grid(row=0, column=0, columnspan=3, pady=(0, 20), sticky=tk.W)
        ttk.Label(frame, text="Recipient Address:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.recipient_entry = ttk.Entry(frame, font=(FONT_MONO, 10))
        self.recipient_entry.grid(row=1, column=1, sticky=tk.EW, pady=10, padx=10)
        ttk.Label(frame, text="Amount (CMXP):").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.amount_entry = ttk.Entry(frame, font=(FONT_MONO, 10))
        self.amount_entry.grid(row=2, column=1, sticky=tk.EW, pady=10, padx=10)
        # 아이콘 적용
        self.send_button = ttk.Button(frame, text="Send Transaction", image=self.icons.get("send"), compound="left", command=self.send_transaction)
        self.send_button.grid(row=3, column=1, sticky=tk.E, pady=20)
        
        warning_frame = ttk.Frame(frame, padding=10)
        warning_frame.grid(row=4, column=0, columnspan=3, sticky=tk.EW, pady=(15,0))
        ttk.Label(warning_frame, text="⚠️ Important Warning & Disclaimer ⚠️", foreground=ERROR_COLOR, font=(FONT_FAMILY, 13, "bold")).pack(anchor=tk.W)
        disclaimer_text = (
            "• This project and its coin (CMXP) hold NO monetary value and are not investment products.\n"
            "• The network may be halted or reset at any time without prior notice.\n"
            "• All participation is at the user's own risk. Please do not trade this coin for money or other assets.\n"
            "• This source code is provided 'AS IS' without warranty of any kind."
        )
        ttk.Label(warning_frame, text=disclaimer_text, justify=tk.LEFT, font=(FONT_FAMILY, 11)).pack(anchor=tk.W, pady=(5,0))

        frame.columnconfigure(1, weight=1)

    def setup_receive_tab(self, frame):
        ttk.Label(frame, text="Receive CMXP", style="Title.TLabel").pack(pady=(0, 20), anchor=tk.W)
        ttk.Label(frame, text="Your Wallet Address:").pack(pady=10)
        address_entry = ttk.Entry(frame, font=(FONT_MONO, 10), justify=tk.CENTER)
        address_entry.insert(0, self.wallet.address)
        address_entry.config(state='readonly')
        address_entry.pack(pady=10, fill=tk.X, padx=50)

        # 동적 피드백 적용
        copy_button = ttk.Button(frame, text="Copy Address", image=self.icons.get("copy"), compound="left")
        def copy_address_feedback():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.wallet.address)
            original_text = "Copy Address"
            original_style = "TButton"
            copy_button.config(text="✓ Copied!", style="Success.TButton", state=tk.DISABLED)
            def revert():
                copy_button.config(text=original_text, style=original_style, state=tk.NORMAL)
            self.root.after(2000, revert)
        copy_button.config(command=copy_address_feedback)
        copy_button.pack(pady=10)

        try:
            qr = qrcode.QRCode(version=1, box_size=6, border=4)
            qr.add_data(self.wallet.address)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
            self.qr_image = ImageTk.PhotoImage(image=img)
            qr_label = tk.Label(frame, image=self.qr_image, bg=BG_COLOR)
            qr_label.pack(pady=20)
        except Exception as e:
            ttk.Label(frame, text=f"Could not generate QR code: {e}\n(Requires qrcode and pillow libraries)", foreground=ERROR_COLOR).pack(pady=20)

    # --- 지갑 기능 구현 ---
    def refresh_balance(self):
        if not self.wallet: return
        self.balance_label.config(text="Syncing...", foreground=ACCENT_COLOR)
        if hasattr(self, 'node_status_label'):
             self.node_status_label.config(text="Syncing...", foreground=ACCENT_COLOR)
        if hasattr(self, 'refresh_button') and self.refresh_button.winfo_exists():
             self.refresh_button.config(state=tk.DISABLED)
        threading.Thread(target=self.fetch_balance_thread, daemon=True).start()

    def fetch_balance_thread(self):
        try:
            response = requests.get(f"{self.node_url}/balance/{self.wallet.address}", timeout=10)
            response.raise_for_status() # 2xx가 아니면 에러 발생
            data = response.json()
            balance_val = float(data.get('balance', 0.0))
            self.root.after(0, lambda: self.balance_label.config(text=f"{balance_val:.8f} CMXP", foreground=SUCCESS_COLOR))
            # 노드 상태 업데이트 (성공)
            if hasattr(self, 'node_status_label'):
                self.root.after(0, lambda: self.node_status_label.config(text="● Online", foreground=SUCCESS_COLOR))
        except Exception as e:
            self.root.after(0, lambda: self.balance_label.config(text="Sync Error", foreground=ERROR_COLOR))
            # 노드 상태 업데이트 (실패)
            if hasattr(self, 'node_status_label'):
                self.root.after(0, lambda: self.node_status_label.config(text="● Offline", foreground=ERROR_COLOR))
            print(f"Error fetching balance: {e}")
        finally:
            if hasattr(self, 'refresh_button') and self.refresh_button.winfo_exists():
                 self.root.after(0, lambda: self.refresh_button.config(state=tk.NORMAL))

    def send_transaction(self):
        recipient = self.recipient_entry.get().strip()
        amount = self.amount_entry.get().strip()

        if not recipient or not amount:
            messagebox.showerror("Error", "Recipient address and amount are required."); return
            
        if recipient == self.wallet.address:
             messagebox.showerror("Error", "Cannot send coins to yourself."); return

        if not messagebox.askyesno("Confirm Transaction", f"Are you sure you want to send {amount} CMXP?"):
            return

        self.send_button.config(state=tk.DISABLED, text="Sending...")
        threading.Thread(target=self.send_transaction_thread, args=(recipient, amount), daemon=True).start()

    def send_transaction_thread(self, recipient, amount):
        try:
            tx_data = self.wallet.sign_transaction(recipient, amount)
            headers = {'Content-Type': 'application/json'}
            response = requests.post(f"{self.node_url}/transactions/new", json=tx_data, headers=headers, timeout=15)
            response.raise_for_status()
            
            self.root.after(0, lambda: messagebox.showinfo("Success", "Transaction sent successfully! It will be mined shortly."))
            self.root.after(0, self.recipient_entry.delete, 0, tk.END)
            self.root.after(0, self.amount_entry.delete, 0, tk.END)
            self.root.after(1500, self.refresh_balance)

        except Exception as e:
            error_message = f"Transaction failed.\n\n"
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json().get('message', 'Unknown node error')
                    error_message += f"Node Error: {error_detail} (Status: {e.response.status_code})"
                except json.JSONDecodeError:
                    error_message += f"Node Error: {e.response.text} (Status: {e.response.status_code})"
            else:
                error_message += f"Error Type: {type(e).__name__}\nDetails: {e}"
            self.root.after(0, lambda: messagebox.showerror("Error", error_message))
        finally:
            if hasattr(self, 'send_button') and self.send_button.winfo_exists():
                self.root.after(0, lambda: self.send_button.config(state=tk.NORMAL, text="Send Transaction"))

if __name__ == '__main__':
    root = tk.Tk()
    app = WalletApp(root)
    root.mainloop()
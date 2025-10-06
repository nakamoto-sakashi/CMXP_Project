# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
#
# All rights reserved.
#
# This software is provided "as is", without warranty of any kind, express or
# implied, including but not limited to the warranties of merchantability,
# fitness for a particular purpose and noninfringement. In no event shall the
# authors or copyright holders be liable for any claim, damages or other
# liability, whether in an action of contract, tort or otherwise, arising from,
# out of or in connection with the software or the use or other dealings in the
# software.

import tkinter as tk
from tkinter import messagebox, simpledialog, Toplevel, ttk, filedialog
import json, os, requests, hashlib, threading
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39MnemonicValidator, Bip44, Bip44Coins, Bip44Changes
# QR 코드 생성을 위한 라이브러리 임포트
import qrcode
from PIL import Image, ImageTk
import traceback # 상세 오류 추적용

# core.py 임포트 (동일 디렉토리 필요)
try:
    # core.py의 경로는 실제 환경에 맞게 조정해야 할 수 있습니다.
    from core import Transaction 
except ImportError as e:
    print(f"Error importing core.py: {e}. Ensure core.py is in the same directory.")
    Transaction = None
    
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import ecdsa
import sys

# --- Configuration ---
# 노드 주소 설정 (개발 환경 기준, 배포 시 변경 가능)
NODE_URL = "https://cmxp-node.onrender.com" 
DEFAULT_WALLET_EXT = ".dat"

# 스타일 테마
BG_COLOR = "#282c34"; FG_COLOR = "#abb2bf"; ACCENT_COLOR = "#61afef"
SUCCESS_COLOR = "#98c379"; ERROR_COLOR = "#e06c75"; BUTTON_BG = "#3e4451"; ENTRY_BG = "#1e2229"
FONT_FAMILY = "Arial"; FONT_SIZE_LARGE = 18; FONT_SIZE_NORMAL = 12

# --- 암호화/복호화 함수 ---
def encrypt_mnemonic(password, mnemonic_str):
    # (암호화 로직 생략 - 이전과 동일)
    pass

def decrypt_mnemonic(password, encrypted_data):
    # (복호화 로직 생략 - 이전과 동일)
    pass

# --- Wallet 클래스 ---
class Wallet:
    def __init__(self, mnemonic=None):
        # 니모닉을 항상 문자열(str)로 처리하여 안정성 확보
        if mnemonic:
            self.mnemonic = str(mnemonic)
        else:
            # Bip39MnemonicGenerator는 객체를 반환하므로 str()로 변환
            self.mnemonic = str(Bip39MnemonicGenerator().FromWordsNumber(12))
            
        self.private_key, self.address = self._derive_keys(self.mnemonic)

    def _derive_keys(self, mnemonic_str):
        seed_bytes = Bip39SeedGenerator(mnemonic_str).Generate()
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
        signing_key = ecdsa.SigningKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
        signature = signing_key.sign(tx_hash.encode())
        tx.signature = signature
        return tx.to_dict()

# --- GUI Application ---
class WalletApp:
    def __init__(self, root):
        self.root = root
        self.wallet = None
        self.current_wallet_file = None # 현재 로드된 파일 경로 추적
        self.qr_image = None # QR 이미지 참조 유지 (가비지 컬렉션 방지)
        self.node_url = NODE_URL
        self.setup_styles()
        # 시작 시 항상 환영 화면 표시 (지갑 선택)
        self.show_welcome_screen()

    def setup_styles(self):
        self.root.configure(bg=BG_COLOR); self.root.geometry("800x600")
        self.style = ttk.Style(); self.style.theme_use('clam')
        self.style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL))
        self.style.configure("TButton", background=BUTTON_BG, foreground=FG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"), padding=8)
        self.style.map("TButton", background=[('active', ACCENT_COLOR)])
        self.style.configure("TEntry", fieldbackground=ENTRY_BG, foreground=FG_COLOR, insertcolor=FG_COLOR)
        self.style.configure("TFrame", background=BG_COLOR)
        self.style.configure("Title.TLabel", font=(FONT_FAMILY, FONT_SIZE_LARGE, "bold"), foreground=ACCENT_COLOR)
        self.style.configure("TProgressbar", background=SUCCESS_COLOR, troughcolor=BUTTON_BG)
        # 탭 스타일 설정
        self.style.configure("TNotebook", background=BG_COLOR)
        self.style.configure("TNotebook.Tab", background=BUTTON_BG, foreground=FG_COLOR, padding=[20, 10])
        self.style.map("TNotebook.Tab", background=[("selected", BG_COLOR)], foreground=[("selected", ACCENT_COLOR)])
        self.update_title()

    def update_title(self):
        title = "CMXP Wallet"
        if self.current_wallet_file:
            filename = os.path.basename(self.current_wallet_file); title += f" - [{filename}]"
        self.root.title(title)
        
    def setup_menu(self):
        menubar = tk.Menu(self.root, bg=BG_COLOR, fg=FG_COLOR); self.root.config(menu=menubar)
        file_menu = tk.Menu(menubar, tearoff=0, bg=BUTTON_BG, fg=FG_COLOR); menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Wallet...", command=self.create_new_wallet_flow)
        file_menu.add_command(label="Open Wallet...", command=self.open_wallet_flow)
        file_menu.add_separator()
        file_menu.add_command(label="Restore Wallet (Mnemonic)...", command=self.restore_wallet_flow)
        if self.wallet:
            file_menu.add_separator(); file_menu.add_command(label="Close Wallet", command=self.close_wallet)
        file_menu.add_separator(); file_menu.add_command(label="Exit", command=self.root.quit)

    def clear_screen(self):
        self.root.config(menu=""); [widget.destroy() for widget in self.root.winfo_children()]
            
    def show_loading(self, message="Loading..."):
        self.clear_screen(); frame = ttk.Frame(self.root); frame.pack(expand=True)
        ttk.Label(frame, text=message, font=(FONT_FAMILY, FONT_SIZE_LARGE)).pack(pady=20)
        progress = ttk.Progressbar(frame, orient="horizontal", length=200, mode="indeterminate")
        progress.pack(pady=10); progress.start()

    def show_welcome_screen(self):
        self.clear_screen(); self.setup_menu(); self.update_title()
        frame = ttk.Frame(self.root); frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        ttk.Label(frame, text="Welcome to CMXP Wallet", style="Title.TLabel").pack(pady=20)
        ttk.Button(frame, text="Open Wallet File (.dat)...", command=self.open_wallet_flow).pack(pady=10, fill='x')
        ttk.Separator(frame, orient='horizontal').pack(pady=15, fill='x')
        ttk.Button(frame, text="Create New Wallet...", command=self.create_new_wallet_flow).pack(pady=10, fill='x')
        ttk.Button(frame, text="Restore Wallet (Mnemonic)...", command=self.restore_wallet_flow).pack(pady=10, fill='x')

    def close_wallet(self):
        self.wallet = None; self.current_wallet_file = None; self.show_welcome_screen()

    # --- 지갑 관리 흐름 (Flows) ---

    def open_wallet_flow(self):
        filepath = filedialog.askopenfilename(title="Open Wallet File", filetypes=[("CMXP Wallet Files", f"*{DEFAULT_WALLET_EXT}")])
        if not filepath: return
        password = self.ask_for_password(f"Enter password for {os.path.basename(filepath)}:")
        if not password: return
        self.show_loading("Unlocking wallet...")
        threading.Thread(target=self.unlock_wallet_thread, args=(filepath, password), daemon=True).start()

    def create_new_wallet_flow(self):
        filepath = filedialog.asksaveasfilename(title="Create New Wallet File", initialfile="wallet" + DEFAULT_WALLET_EXT, defaultextension=DEFAULT_WALLET_EXT, filetypes=[("CMXP Wallet Files", f"*{DEFAULT_WALLET_EXT}")])
        if not filepath: return
        password = self.ask_for_new_password()
        if not password: return
        self.show_loading("Generating new wallet...")
        threading.Thread(target=self.wallet_operation_thread, args=("create", filepath, password, None), daemon=True).start()

    # (오류 수정 반영) 지갑 복원 흐름
    def restore_wallet_flow(self):
        mnemonic = simpledialog.askstring("Restore Wallet", "Enter your 12 mnemonic words:", parent=self.root)
        if not mnemonic: return
        
        # 입력값 정규화 (공백 제거)
        mnemonic = ' '.join(mnemonic.strip().split())
        
        try:
            # (중요) BIP39 유효성 검사. EXE 환경에서 wordlist 누락 시 여기서 에러 발생 가능.
            if not Bip39MnemonicValidator(mnemonic).IsValid():
                raise ValueError("Invalid structure, unknown words, or incorrect checksum.")
        except Exception as e:
            # 에러 발생 시 명확한 메시지 제공 (EXE 빌드 문제 가능성 포함)
            error_message = f"Invalid mnemonic phrase.\n\nDetails: {e}\n\nIf running from EXE, this might indicate missing wordlist files during the build process."
            messagebox.showerror("Error", error_message); return

        # 유효성 검사 통과 후 진행
        filepath = filedialog.asksaveasfilename(title="Save Restored Wallet As", initialfile="restored_wallet" + DEFAULT_WALLET_EXT, defaultextension=DEFAULT_WALLET_EXT, filetypes=[("CMXP Wallet Files", f"*{DEFAULT_WALLET_EXT}")])
        if not filepath: return

        password = self.ask_for_new_password()
        if not password: return

        self.show_loading("Restoring wallet...")
        threading.Thread(target=self.wallet_operation_thread, args=("restore", filepath, password, mnemonic), daemon=True).start()


    # --- 백그라운드 스레드 작업 ---

    def unlock_wallet_thread(self, filepath, password):
        # (unlock_wallet_thread 로직 생략)
        pass

    # (오류 수정 반영) 지갑 생성/복원 통합 스레드 (에러 핸들링 강화)
    def wallet_operation_thread(self, operation, filepath, password, mnemonic):
        try:
            if operation == "create":
                temp_wallet = Wallet() 
                mnemonic = temp_wallet.mnemonic
            else: # restore
                # Wallet 생성 시 발생 가능한 예외 처리
                temp_wallet = Wallet(mnemonic)

            # 무거운 작업 (암호화)
            encrypted_data = encrypt_mnemonic(password, mnemonic)

            # 파일 저장
            with open(filepath, 'w') as f: 
                json.dump(encrypted_data, f)
            
            self.wallet = temp_wallet
            self.current_wallet_file = filepath
            
            # UI 업데이트 (메인 스레드에서)
            if operation == "create":
                self.root.after(0, self.show_backup_screen, mnemonic)
            else:
                self.root.after(0, lambda: messagebox.showinfo("Success", "Wallet restored successfully."))
                self.root.after(0, self.show_main_screen)

        except Exception as e:
            # (중요) 에러 발생 시 상세 정보를 캡처하여 사용자에게 표시
            if os.path.exists(filepath):
                try: os.remove(filepath)
                except: pass
            
            # 상세 에러 트레이스백 캡처
            traceback_str = traceback.format_exc()
            error_message = (f"Operation failed: {type(e).__name__} - {e}\n\n"
                             f"Details:\n{traceback_str}\n\n"
                             "If running from EXE, this often means PyInstaller missed dependencies. Check the build command.")
            
            self.root.after(0, self.handle_failure, error_message, self.show_welcome_screen)

    def handle_failure(self, message, retry_func=None):
        messagebox.showerror("Error", message); retry_func() if retry_func else None

    # --- UI 컴포넌트 및 화면 ---
    
    def ask_for_password(self, prompt):
        return simpledialog.askstring("Password", prompt, parent=self.root, show='*')

    def ask_for_new_password(self):
        # (비밀번호 입력 다이얼로그 생략)
        pass
    
    def show_backup_screen(self, mnemonic):
        # (백업 화면 생략)
        pass

    # --- 메인 지갑 화면 구현 (핵심 기능) ---
    def show_main_screen(self):
        self.clear_screen()
        self.setup_menu()
        self.update_title()

        # 1. 헤더 프레임 (잔액)
        header_frame = ttk.Frame(self.root, padding=15)
        header_frame.pack(fill=tk.X)
        
        ttk.Label(header_frame, text="Balance:", font=(FONT_FAMILY, FONT_SIZE_LARGE)).pack(side=tk.LEFT)
        
        # 잔액 표시 레이블
        self.balance_label = ttk.Label(header_frame, text="Syncing...", font=(FONT_FAMILY, FONT_SIZE_LARGE, "bold"), foreground=ACCENT_COLOR)
        self.balance_label.pack(side=tk.LEFT, padx=10)
        
        self.refresh_button = ttk.Button(header_frame, text="Refresh", command=self.refresh_balance)
        self.refresh_button.pack(side=tk.RIGHT)

        # 2. 탭 컨트롤 (Notebook)
        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill='both', padx=10, pady=10)

        send_frame = ttk.Frame(notebook, padding=20)
        receive_frame = ttk.Frame(notebook, padding=20)
        
        notebook.add(send_frame, text='  Send  ')
        notebook.add(receive_frame, text='  Receive  ')
        
        self.setup_send_tab(send_frame)
        self.setup_receive_tab(receive_frame)
        
        # 시작 시 잔액 조회
        self.refresh_balance()

    def setup_send_tab(self, frame):
        ttk.Label(frame, text="Send CMXP", style="Title.TLabel").grid(row=0, column=0, columnspan=3, pady=(0, 20), sticky=tk.W)

        ttk.Label(frame, text="Recipient Address:").grid(row=1, column=0, sticky=tk.W, pady=10)
        self.recipient_entry = ttk.Entry(frame, font=("Consolas", 10))
        self.recipient_entry.grid(row=1, column=1, sticky=tk.EW, pady=10, padx=10)

        ttk.Label(frame, text="Amount (CMXP):").grid(row=2, column=0, sticky=tk.W, pady=10)
        self.amount_entry = ttk.Entry(frame, font=("Consolas", 10))
        self.amount_entry.grid(row=2, column=1, sticky=tk.EW, pady=10, padx=10)

        self.send_button = ttk.Button(frame, text="Send Transaction", command=self.send_transaction)
        self.send_button.grid(row=3, column=1, sticky=tk.E, pady=30)
        
        frame.columnconfigure(1, weight=1)

    def setup_receive_tab(self, frame):
        ttk.Label(frame, text="Receive CMXP", style="Title.TLabel").pack(pady=(0, 20), anchor=tk.W)
        
        ttk.Label(frame, text="Your Wallet Address:").pack(pady=10)
        
        # 복사 가능한 Entry 위젯 사용
        address_entry = ttk.Entry(frame, font=("Consolas", 10), justify=tk.CENTER)
        address_entry.insert(0, self.wallet.address)
        address_entry.config(state='readonly')
        address_entry.pack(pady=10, fill=tk.X, padx=50)

        # 복사 버튼
        def copy_address():
            self.root.clipboard_clear()
            self.root.clipboard_append(self.wallet.address)
            messagebox.showinfo("Copied", "Address copied to clipboard.")
        
        ttk.Button(frame, text="Copy Address", command=copy_address).pack(pady=10)

        # QR 코드 생성 및 표시
        try:
            qr = qrcode.QRCode(version=1, box_size=6, border=4)
            qr.add_data(self.wallet.address)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white").convert('RGB')
            
            # PIL 이미지를 Tkinter PhotoImage로 변환
            self.qr_image = ImageTk.PhotoImage(image=img)
            qr_label = tk.Label(frame, image=self.qr_image, bg=BG_COLOR)
            qr_label.pack(pady=20)
        except Exception as e:
            # QR 생성 실패 시 (Pillow 라이브러리 문제 등)
            ttk.Label(frame, text=f"Could not generate QR code: {e}\n(Requires qrcode and pillow libraries)", foreground=ERROR_COLOR).pack(pady=20)

    # --- 지갑 기능 구현 ---

    def refresh_balance(self):
        if not self.wallet: return
        self.balance_label.config(text="Syncing...", foreground=ACCENT_COLOR)
        # 위젯 존재 확인 후 비활성화
        if hasattr(self, 'refresh_button') and self.refresh_button.winfo_exists():
             self.refresh_button.config(state=tk.DISABLED)
        # 네트워크 요청은 스레드에서 처리
        threading.Thread(target=self.fetch_balance_thread, daemon=True).start()

    def fetch_balance_thread(self):
        try:
            # 노드 API 호출 (node_main.py의 /balance/<address> 사용)
            response = requests.get(f"{self.node_url}/balance/{self.wallet.address}", timeout=15)
            if response.status_code == 200:
                data = response.json()
                balance_val = float(data.get('balance', 0.0))
                # UI 업데이트는 메인 스레드에서
                self.root.after(0, lambda: self.balance_label.config(text=f"{balance_val:.8f} CMXP", foreground=SUCCESS_COLOR))
            else:
                raise Exception(f"Node returned status {response.status_code}")
        except Exception as e:
            self.root.after(0, lambda: self.balance_label.config(text="Sync Error", foreground=ERROR_COLOR))
            print(f"Error fetching balance: {e}")
        finally:
            # 위젯이 존재하는지 확인 후 상태 변경
            if hasattr(self, 'refresh_button') and self.refresh_button.winfo_exists():
                 self.root.after(0, lambda: self.refresh_button.config(state=tk.NORMAL))

    def send_transaction(self):
        recipient = self.recipient_entry.get().strip()
        amount = self.amount_entry.get().strip()

        if not recipient or not amount:
            messagebox.showerror("Error", "Recipient address and amount are required."); return
            
        if recipient == self.wallet.address:
             messagebox.showerror("Error", "Cannot send coins to yourself."); return

        # 확인 다이얼로그
        if not messagebox.askyesno("Confirm Transaction", f"Are you sure you want to send {amount} CMXP?"):
            return

        self.send_button.config(state=tk.DISABLED, text="Sending...")
        # 서명 및 전송은 스레드에서 처리
        threading.Thread(target=self.send_transaction_thread, args=(recipient, amount), daemon=True).start()

    def send_transaction_thread(self, recipient, amount):
        try:
            # 1. 트랜잭션 생성 및 서명
            tx_data = self.wallet.sign_transaction(recipient, amount)
            
            # 2. 노드로 전송
            headers = {'Content-Type': 'application/json'}
            response = requests.post(f"{self.node_url}/transactions/new", json=tx_data, headers=headers, timeout=15)
            
            if response.status_code == 201:
                self.root.after(0, lambda: messagebox.showinfo("Success", "Transaction sent successfully! It will be mined shortly."))
                # 입력 필드 초기화
                self.root.after(0, self.recipient_entry.delete, 0, tk.END)
                self.root.after(0, self.amount_entry.delete, 0, tk.END)
                # 잔액 변화 예상되므로 잠시 후 새로고침
                self.root.after(1500, self.refresh_balance)
            else:
                error_msg = response.json().get('message', 'Unknown error')
                # 잔액 부족 등 노드에서 반환한 에러 메시지 표시
                self.root.after(0, lambda: messagebox.showerror("Error", f"Transaction failed: {error_msg} (Status: {response.status_code})"))

        except ValueError as e:
             # 금액 형식 오류 등
             self.root.after(0, lambda: messagebox.showerror("Error", f"Invalid input: {e}"))
        except Exception as e:
            # 네트워크 오류 등
            self.root.after(0, lambda: messagebox.showerror("Error", f"An error occurred: {e}"))
        finally:
            # 위젯이 존재하는지 확인 후 상태 변경
            if hasattr(self, 'send_button') and self.send_button.winfo_exists():
                self.root.after(0, lambda: self.send_button.config(state=tk.NORMAL, text="Send Transaction"))


if __name__ == '__main__':
    root = tk.Tk()
    app = WalletApp(root)
    root.mainloop()
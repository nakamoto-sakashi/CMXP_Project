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
from tkinter import messagebox, simpledialog, Toplevel
import json, os, requests, hashlib
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39MnemonicValidator, Bip44, Bip44Coins, Bip44Changes
from core import Transaction
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import ecdsa

NODE_URL = "http://127.0.0.1:5000"
WALLET_FILE = "cmxp_wallet.json"
BG_COLOR = "#0D0D0D"
FG_COLOR = "#00FF00"

FONT_FAMILY = "Courier"
FONT_SIZE_XXLARGE = 22
FONT_SIZE_LARGE = 18
FONT_SIZE_NORMAL = 14
FONT_SIZE_SMALL = 12
FONT_SIZE_XSMALL = 10

def encrypt_mnemonic(password, mnemonic_str):
    salt = get_random_bytes(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=16)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(mnemonic_str.encode('utf-8'))
    return {'salt': salt.hex(), 'nonce': cipher.nonce.hex(), 'ciphertext': ciphertext.hex(), 'tag': tag.hex()}

def decrypt_mnemonic(password, encrypted_data):
    try:
        salt = bytes.fromhex(encrypted_data['salt'])
        nonce = bytes.fromhex(encrypted_data['nonce'])
        ciphertext = bytes.fromhex(encrypted_data['ciphertext'])
        tag = bytes.fromhex(encrypted_data['tag'])
        key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000, dklen=16)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_mnemonic_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_mnemonic_bytes.decode('utf-8')
    except (ValueError, KeyError):
        return None

class Wallet:
    def __init__(self, mnemonic=None):
        if mnemonic: self.mnemonic = mnemonic
        else: self.mnemonic = Bip39MnemonicGenerator().FromWordsNumber(12)
        self.private_key, self.address = self._derive_keys(self.mnemonic)

    def _derive_keys(self, mnemonic):
        seed_bytes = Bip39SeedGenerator(str(mnemonic)).Generate()
        bip44_mst = Bip44.FromSeed(seed_bytes, Bip44Coins.BITCOIN)
        bip44_acc = bip44_mst.Purpose().Coin().Account(0).Change(Bip44Changes.CHAIN_EXT).AddressIndex(0)
        return bip44_acc.PrivateKey(), bip44_acc.PublicKey().RawCompressed().ToHex()

    def sign_transaction(self, recipient, amount):
        tx = Transaction(self.address, recipient, float(amount))
        tx_hash = tx.calculate_hash()
        pk_bytes = self.private_key.Raw().ToBytes()
        signing_key = ecdsa.SigningKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
        signature = signing_key.sign(tx_hash.encode())
        tx.signature = signature
        return tx.to_dict()

class WalletApp:
    def __init__(self, root):
        self.root = root
        self.wallet = None
        self.setup_styles()
        self.show_warning_popup()
        self.check_wallet_file()

    def setup_styles(self):
        self.root.title("CMXP Wallet")
        self.root.configure(bg=BG_COLOR)
        self.root.geometry("750x550")

    def check_wallet_file(self):
        if not os.path.exists(WALLET_FILE):
            self.show_welcome_screen()
            return
        
        password = self.ask_for_password("Enter password to unlock wallet:")
        if not password:
            self.root.destroy()
            return

        with open(WALLET_FILE, 'r') as f:
            try:
                encrypted_data = json.load(f)
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Wallet file is corrupted. Please delete cmxp_wallet.json and restore from mnemonic.")
                self.root.destroy()
                return

        mnemonic = decrypt_mnemonic(password, encrypted_data)
        if mnemonic:
            self.wallet = Wallet(mnemonic)
            self.show_main_screen()
        else:
            messagebox.showerror("Error", "Wrong password.")
            self.check_wallet_file()

    def show_welcome_screen(self):
        self.clear_screen()
        frame = tk.Frame(self.root, bg=BG_COLOR)
        frame.pack(expand=True)
        tk.Label(frame, text="Welcome to CMXP Wallet", fg=FG_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE_LARGE)).pack(pady=10)
        tk.Button(frame, text="Create New Wallet", command=self.create_wallet, fg=BG_COLOR, bg=FG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(pady=5)
        tk.Button(frame, text="Restore Wallet", command=self.restore_wallet, fg=BG_COLOR, bg=FG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(pady=5)

    def create_wallet(self):
        password = self.ask_for_new_password()
        if not password: return

        new_mnemonic = str(Bip39MnemonicGenerator().FromWordsNumber(12))
        encrypted_data = encrypt_mnemonic(password, new_mnemonic)
        with open(WALLET_FILE, 'w') as f: json.dump(encrypted_data, f)
        
        self.wallet = Wallet(new_mnemonic)
        messagebox.showinfo("IMPORTANT - BACKUP PHRASE", f"Wallet created and encrypted successfully!\n\nYOUR 12-WORD RECOVERY PHRASE IS:\n\n{new_mnemonic}\n\nWrite this down and store it in a safe place. It is the ONLY way to recover your wallet if you forget your password.")
        self.show_main_screen()
    
    def restore_wallet(self):
        mnemonic = simpledialog.askstring("Restore Wallet", "Enter your 12 mnemonic words:", parent=self.root)
        if not mnemonic: return
        
        try:
            validator = Bip39MnemonicValidator()
            if not validator.IsValid(mnemonic):
                raise ValueError("Invalid Mnemonic")
        except ValueError:
            messagebox.showerror("Error", "Invalid mnemonic phrase."); return

        password = self.ask_for_new_password()
        if not password: return

        encrypted_data = encrypt_mnemonic(password, mnemonic)
        with open(WALLET_FILE, 'w') as f: json.dump(encrypted_data, f)
        
        self.wallet = Wallet(mnemonic)
        messagebox.showinfo("Success", "Wallet restored and encrypted successfully.")
        self.show_main_screen()

    def ask_for_password(self, prompt):
        return simpledialog.askstring("Password", prompt, parent=self.root, show='*')

    def ask_for_new_password(self):
        dialog = Toplevel(self.root)
        dialog.title("Set Password")
        dialog.configure(bg=BG_COLOR); dialog.transient(self.root); dialog.grab_set()
        
        tk.Label(dialog, text="Create a password for your wallet.", fg=FG_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE_SMALL)).pack(pady=10, padx=20)
        tk.Label(dialog, text="New Password:", fg=FG_COLOR, bg=BG_COLOR).pack(); pass_entry1 = tk.Entry(dialog, show='*', width=30); pass_entry1.pack(pady=5)
        tk.Label(dialog, text="Confirm Password:", fg=FG_COLOR, bg=BG_COLOR).pack(); pass_entry2 = tk.Entry(dialog, show='*', width=30); pass_entry2.pack(pady=5)
        
        password = None
        def on_ok():
            nonlocal password
            if pass_entry1.get() != pass_entry2.get(): messagebox.showerror("Error", "Passwords do not match.", parent=dialog); return
            if not pass_entry1.get(): messagebox.showerror("Error", "Password cannot be empty.", parent=dialog); return
            password = pass_entry1.get()
            dialog.destroy()
            
        tk.Button(dialog, text="OK", command=on_ok, fg=BG_COLOR, bg=FG_COLOR).pack(pady=10); self.root.wait_window(dialog)
        return password

    def show_main_screen(self):
        self.clear_screen()
        header_frame = tk.Frame(self.root, bg=BG_COLOR); header_frame.pack(fill='x', padx=20, pady=10)
        tk.Label(header_frame, text="CMXP Wallet", fg=FG_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE_XXLARGE, "bold")).pack()
        
        balance_frame = tk.Frame(self.root, bg="#1a1a1a", relief="solid", borderwidth=1); balance_frame.pack(fill='x', padx=20, pady=10)
        tk.Label(balance_frame, text="Balance:", fg=FG_COLOR, bg="#1a1a1a", font=(FONT_FAMILY, FONT_SIZE_LARGE)).pack(side="left", padx=10, pady=10)
        self.balance_label = tk.Label(balance_frame, text="Querying...", fg="white", bg="#1a1a1a", font=(FONT_FAMILY, FONT_SIZE_LARGE)); self.balance_label.pack(side="left", padx=10, pady=10)
        tk.Button(balance_frame, text="Refresh", command=self.update_balance, fg=BG_COLOR, bg=FG_COLOR, font=(FONT_FAMILY, FONT_SIZE_SMALL), relief="solid", borderwidth=1).pack(side="right", padx=10, pady=10)
        
        addr_frame = tk.Frame(self.root, bg="#1a1a1a", relief="solid", borderwidth=1); addr_frame.pack(fill='x', padx=20, pady=5)
        tk.Label(addr_frame, text="My Address:", fg=FG_COLOR, bg="#1a1a1a", font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(side="left", padx=10, pady=10)
        addr_text = tk.Entry(addr_frame, fg="black", bg="white", font=(FONT_FAMILY, FONT_SIZE_XSMALL), relief="solid", justify="center", bd=1); addr_text.insert(0, self.wallet.address); addr_text.config(state="readonly"); addr_text.pack(side="left", fill='x', expand=True, padx=10, pady=10)

        send_frame = tk.Frame(self.root, bg=BG_COLOR); send_frame.pack(fill='both', expand=True, padx=20, pady=15)
        tk.Label(send_frame, text="--- Send ---", fg=FG_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE_LARGE, "bold")).pack()
        tk.Label(send_frame, text="Recipient Address:", fg=FG_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(anchor='w', pady=(10,0))
        self.recipient_entry = tk.Entry(send_frame, fg="white", bg="#333333", font=(FONT_FAMILY, FONT_SIZE_SMALL)); self.recipient_entry.pack(fill='x', ipady=5)
        tk.Label(send_frame, text="Amount:", fg=FG_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(anchor='w', pady=(10,0))
        self.amount_entry = tk.Entry(send_frame, fg="white", bg="#333333", font=(FONT_FAMILY, FONT_SIZE_SMALL)); self.amount_entry.pack(fill='x', ipady=5)
        tk.Button(send_frame, text="Send", command=self.confirm_send, fg=BG_COLOR, bg=FG_COLOR, font=(FONT_FAMILY, FONT_SIZE_LARGE)).pack(pady=20)
        self.update_balance()

    def update_balance(self):
        self.balance_label.config(text="Querying...")
        try:
            response = requests.get(f"{NODE_URL}/chain", timeout=5)
            if response.status_code == 200:
                chain = response.json()['chain']
                balance = 0
                for block in chain:
                    if isinstance(block['data'], list):
                        for tx in block['data']:
                            if tx.get('recipient') == self.wallet.address: balance += tx.get('amount', 0)
                            if tx.get('sender') == self.wallet.address: balance -= tx.get('amount', 0)
                    elif isinstance(block['data'], dict) and 'pre_mine_distribution' in block['data']:
                        for tx in block['data']['pre_mine_distribution']:
                            if tx.get('recipient') == self.wallet.address:
                                balance += tx.get('amount', 0)
                self.balance_label.config(text=f"{balance:.8f} CMXP")
            else: self.balance_label.config(text="Node connection failed")
        except requests.exceptions.RequestException: self.balance_label.config(text="Node connection failed")

    def confirm_send(self):
        recipient, amount = self.recipient_entry.get(), self.amount_entry.get()
        if not recipient or not amount: messagebox.showerror("Error", "Please enter both recipient address and amount."); return
        dialog = Toplevel(self.root); dialog.title("Confirm Transaction"); dialog.configure(bg=BG_COLOR); dialog.transient(self.root); dialog.grab_set()
        msg = f"Recipient: {recipient}\nAmount: {amount} CMXP\n\nDo you really want to send?"; tk.Label(dialog, text=msg, fg=FG_COLOR, bg=BG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL)).pack(padx=20, pady=10)
        password = None
        def do_send():
            nonlocal password
            password = self.ask_for_password("Enter password to confirm:")
            if password: dialog.destroy()
        tk.Button(dialog, text="Confirm & Send", command=do_send, fg=BG_COLOR, bg=FG_COLOR).pack(pady=10); self.root.wait_window(dialog)
        if password: self.send_transaction(recipient, amount, password)

    def send_transaction(self, recipient, amount, password):
        with open(WALLET_FILE) as f:
            stored_mnemonic = decrypt_mnemonic(password, json.load(f))
        
        if not stored_mnemonic or stored_mnemonic != self.wallet.mnemonic:
            messagebox.showerror("Error", "Wrong password."); return
        try:
            signed_tx = self.wallet.sign_transaction(recipient, amount)
            headers = {'Content-Type': 'application/json'}
            response = requests.post(f"{NODE_URL}/transactions/new", json=signed_tx, headers=headers, timeout=10)
            if response.status_code == 201:
                messagebox.showinfo("Success", "Transaction sent successfully."); self.recipient_entry.delete(0, 'end'); self.amount_entry.delete(0, 'end'); self.update_balance()
            else: messagebox.showerror("Send Failed", f"Error: {response.text}")
        except requests.exceptions.RequestException: messagebox.showerror("Send Failed", "Could not connect to the node.")

    def show_warning_popup(self):
        messagebox.showwarning("⚠️ IMPORTANT WARNING ⚠️", "The CMXP coin is intended purely for learning and experimental purposes.\n\nThis coin holds NO monetary value and should NEVER be traded for money or other assets.")

    def clear_screen(self):
        for widget in self.root.winfo_children(): widget.destroy()

if __name__ == '__main__':
    root = tk.Tk()
    app = WalletApp(root)
    root.mainloop()
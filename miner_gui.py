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

# miner_gui.py (XMRig Launcher Version)
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import subprocess
import sys
import os

# --- Helper function to find xmrig.exe ---
def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

# --- GUI Application ---
class MinerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CMXP Miner (powered by XMRig)")
        self.root.geometry("800x500")
        self.root.configure(bg="#2d2d2d")

        self.node_url = "https://cmxp-node.onrender.com"
        self.xmrig_process = None
        self.mining_thread = None

        # --- UI Elements ---
        main_frame = tk.Frame(root, bg="#2d2d2d", padx=15, pady=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Wallet Address Input
        addr_frame = tk.Frame(main_frame, bg="#2d2d2d")
        addr_frame.pack(fill=tk.X)
        tk.Label(addr_frame, text="Your Wallet Address:", fg="white", bg="#2d2d2d", font=("Arial", 12)).pack(side=tk.LEFT, padx=(0, 10))
        self.wallet_entry = tk.Entry(addr_frame, width=70, font=("Arial", 10))
        self.wallet_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Control Buttons
        button_frame = tk.Frame(main_frame, bg="#2d2d2d", pady=10)
        button_frame.pack(fill=tk.X)
        self.toggle_button = tk.Button(button_frame, text="Start Mining", command=self.toggle_mining, font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", width=15)
        self.toggle_button.pack(side=tk.LEFT, padx=5)

        # Log Output
        log_frame = tk.Frame(main_frame, bg="#2d2d2d")
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg="black", fg="lime", font=("Courier New", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.insert(tk.END, "Welcome to CMXP Miner!\nEnter your wallet address and click 'Start Mining'.\n\n")

    def log(self, message):
        self.log_text.insert(tk.END, message)
        self.log_text.see(tk.END)

    def toggle_mining(self):
        if self.mining_thread and self.mining_thread.is_alive():
            self.stop_mining()
        else:
            self.start_mining()

    def start_mining(self):
        wallet_address = self.wallet_entry.get().strip()
        if not wallet_address:
            messagebox.showerror("Error", "Please enter a valid wallet address.")
            return

        self.toggle_button.config(state=tk.DISABLED)
        self.log("Starting mining process...\n")

        self.mining_thread = threading.Thread(target=self._run_xmrig_process, args=(wallet_address,), daemon=True)
        self.mining_thread.start()

    def stop_mining(self):
        self.log("\nStopping mining process...\n")
        if self.xmrig_process:
            self.xmrig_process.terminate()
        self.toggle_button.config(state=tk.NORMAL, text="Start Mining", bg="#4CAF50")

    def _run_xmrig_process(self, wallet_address):
        try:
            xmrig_path = resource_path("xmrig.exe")
            if not os.path.exists(xmrig_path):
                self.log("FATAL ERROR: xmrig.exe not found!\n")
                self.stop_mining()
                return

            self.toggle_button.config(state=tk.NORMAL, text="Stop Mining", bg="#f44336")

            # Command to run XMRig in the background
            command = [
                xmrig_path,
                '--daemon',
                '-o', self.node_url,
                '-u', wallet_address,
                '-a', 'rx/0',
                '--no-color' # Important for clean log parsing
            ]

            # This flag prevents the black console window from popping up on Windows
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE

            self.xmrig_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                startupinfo=si
            )

            # Read output line by line in real-time
            for line in self.xmrig_process.stdout:
                self.log(line)
            
            self.xmrig_process.wait()

        except Exception as e:
            self.log(f"An error occurred: {e}\n")
        
        # When process finishes (or is stopped), reset the button
        if self.toggle_button.winfo_exists():
            self.stop_mining()

if __name__ == '__main__':
    root = tk.Tk()
    app = MinerApp(root)
    root.mainloop()
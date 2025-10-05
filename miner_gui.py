# miner_gui.py
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import sys
import os
from miner import mine, cpu_count # miner.py에서 mine 함수와 cpu_count를 가져옵니다.

# --- GUI Application ---
class MinerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CMXP Miner")
        self.root.geometry("700x450")
        self.root.configure(bg="#2d2d2d")

        self.node_url = "https://cmxp-node.onrender.com"
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
        self.start_button = tk.Button(button_frame, text="Start Mining", command=self.start_mining, font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", state=tk.NORMAL)
        self.start_button.pack(side=tk.LEFT, padx=5)

        # Log Output
        log_frame = tk.Frame(main_frame, bg="#2d2d2d")
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg="black", fg="lime", font=("Courier New", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Redirect stdout to the log widget
        sys.stdout = self.TextRedirector(self.log_text)

    def start_mining(self):
        wallet_address = self.wallet_entry.get().strip()
        if not wallet_address:
            messagebox.showerror("Error", "Please enter a valid wallet address.")
            return
        
        # Disable button to prevent multiple starts
        self.start_button.config(state=tk.DISABLED, text="Mining...")

        # Run the miner in a separate thread to avoid freezing the GUI
        self.mining_thread = threading.Thread(
            target=mine, 
            args=(self.node_url, wallet_address, cpu_count()),
            daemon=True
        )
        self.mining_thread.start()

    # Helper class to redirect print output
    class TextRedirector:
        def __init__(self, widget):
            self.widget = widget

        def write(self, str):
            self.widget.insert(tk.END, str)
            self.widget.see(tk.END)

        def flush(self):
            pass

if __name__ == '__main__':
    root = tk.Tk()
    app = MinerApp(root)
    root.mainloop()
# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
# (Argon2id Native Python Miner GUI with Long Polling)
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
from tkinter import scrolledtext, messagebox, ttk
import threading
import requests
import time
import sys
from multiprocessing import Process, Queue as ProcQueue, Event, cpu_count, freeze_support
from queue import Queue as ThreadQueue # 스레드 간 통신용
from datetime import datetime

# core.py 및 miner.py의 공통 요소 임포트
try:
    from core import Block, MAX_TARGET
    from miner import worker, get_current_timestamp
except ImportError as e:
    print(f"Error importing modules: {e}. Ensure core.py and miner.py are present.")
    sys.exit(1)

# --- GUI 스타일 설정 ---
BG_COLOR = "#282c34"
FG_COLOR = "#abb2bf"
ACCENT_COLOR = "#61afef"
SUCCESS_COLOR = "#98c379"
ERROR_COLOR = "#e06c75"

# --- GUI Application ---
class MinerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CMXP Miner (Argon2id)")
        self.root.geometry("900x650")

        # 기본 설정값
        self.node_url = tk.StringVar(value="https://cmxp-node.onrender.com") 
        self.num_threads = tk.IntVar(value=max(1, cpu_count() - 1))

        # 채굴 관련 변수 초기화
        self.processes = []
        self.stop_event = Event()
        self.stats_queue = ProcQueue() 
        self.is_mining = False
        self.new_work_queue = ThreadQueue(maxsize=1) # 새 작업을 전달할 큐
        
        # 통계 변수
        self.total_hashes = 0
        self.last_stats_time = time.time()
        self.accepted_shares = 0
        self.rejected_shares = 0
        self.current_difficulty = 0.0
        self.current_block = 0
        self.current_hashrate = 0.0

        # 종료 처리 관련
        self.shutdown_requested = False
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.setup_styles()
        self.setup_ui()
        self.start_stats_thread()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        self.root.configure(bg=BG_COLOR)
        style.configure('.', background=BG_COLOR, foreground=FG_COLOR, font=("Consolas", 10))
        style.configure('TFrame', background=BG_COLOR)
        style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR)
        style.configure('TButton', background="#3e4451", foreground=FG_COLOR, relief="flat")
        style.map('TButton', background=[('active', ACCENT_COLOR), ('disabled', '#5c6370')])
        style.configure('TEntry', fieldbackground="#3e4451", foreground=FG_COLOR, insertcolor=FG_COLOR, relief="flat")
        style.configure('Header.TFrame', background="#1e2127")
        style.configure('Stats.TLabel', font=("Consolas", 10, "bold"))

    def setup_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)
        header_frame = ttk.Frame(main_frame, style='Header.TFrame', padding=15)
        header_frame.pack(fill=tk.X)
        ttk.Label(header_frame, text="Node URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.node_entry = ttk.Entry(header_frame, textvariable=self.node_url)
        self.node_entry.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=(5, 15))
        ttk.Label(header_frame, text="Wallet Address:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.wallet_entry = ttk.Entry(header_frame)
        self.wallet_entry.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=(5, 15))
        ttk.Label(header_frame, text="Threads:").grid(row=0, column=2, sticky=tk.W, pady=5)
        self.threads_spinbox = tk.Spinbox(header_frame, textvariable=self.num_threads, from_=1, to=cpu_count(), width=5, font=("Consolas", 10), bg="#3e4451", fg=FG_COLOR, relief="flat")
        self.threads_spinbox.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)
        self.toggle_button = tk.Button(header_frame, text="▶ Start Mining", command=self.toggle_mining, bg=SUCCESS_COLOR, fg="white", font=("Consolas", 10, "bold"), relief="flat")
        self.toggle_button.grid(row=1, column=2, columnspan=2, sticky=tk.EW, pady=5, padx=5)
        header_frame.columnconfigure(1, weight=1)
        log_frame = ttk.Frame(main_frame, padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg="black", fg="white", font=("Consolas", 9), relief="flat")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log_text.tag_config("INFO", foreground=FG_COLOR)
        self.log_text.tag_config("SUCCESS", foreground=SUCCESS_COLOR)
        self.log_text.tag_config("ERROR", foreground=ERROR_COLOR)
        self.log_text.tag_config("SYSTEM", foreground="#e5c07b")
        self.log("Welcome to CMXP Argon2id Miner! Configure settings and click 'Start Mining'.\n", "SYSTEM")
        stats_frame = ttk.Frame(main_frame, style='Header.TFrame', padding=5)
        stats_frame.pack(fill=tk.X)
        self.hashrate_label = ttk.Label(stats_frame, text="Hashrate: 0.00 H/s", style='Stats.TLabel')
        self.hashrate_label.pack(side=tk.LEFT, padx=10)
        self.block_label = ttk.Label(stats_frame, text="Block: 0", style='Stats.TLabel')
        self.block_label.pack(side=tk.LEFT, padx=10)
        self.diff_label = ttk.Label(stats_frame, text="Diff: 0.0000", style='Stats.TLabel')
        self.diff_label.pack(side=tk.LEFT, padx=10)
        self.shares_label = ttk.Label(stats_frame, text="Accepted: 0 / Rejected: 0", style='Stats.TLabel')
        self.shares_label.pack(side=tk.RIGHT, padx=10)

    def on_closing(self):
        if self.is_mining:
            self.log("Close requested. Shutting down mining processes...", "SYSTEM")
            self.shutdown_requested = True
            self.stop_mining()
        else:
            self.root.destroy()

    def log(self, message, level="INFO"):
        timestamp = get_current_timestamp()
        self.root.after(0, self._update_log, f"[{timestamp}] {message}\n", level)

    def _update_log(self, message, level):
        if self.log_text.winfo_exists():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, message, level)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)

    def toggle_mining(self):
        if self.is_mining:
            self.stop_mining()
        else:
            self.start_mining()

    def start_mining(self):
        wallet_address = self.wallet_entry.get().strip()
        node_url = self.node_url.get().strip()
        try:
            threads = self.num_threads.get()
        except tk.TclError:
             messagebox.showerror("Error", "Invalid number of threads."); return

        if not wallet_address or not node_url:
            messagebox.showerror("Error", "Please enter Node URL and Wallet Address."); return

        self.is_mining = True
        self.toggle_button.config(text="■ Stop Mining", bg=ERROR_COLOR)
        self.set_settings_state(tk.DISABLED)
        self.log(f"Starting mining process with {threads} threads...", "SYSTEM")

        # 1. 작업 수신 스레드 (롱 폴링 담당)
        self.work_fetcher = threading.Thread(target=self.run_work_fetcher, args=(node_url, wallet_address), daemon=True)
        self.work_fetcher.start()

        # 2. 채굴 제어 스레드 (프로세스 관리 담당)
        self.mining_controller = threading.Thread(target=self.run_mining_controller, args=(node_url, wallet_address, threads), daemon=True)
        self.mining_controller.start()

    def stop_mining(self):
        if not self.is_mining: return
        self.log("Stopping mining process...", "SYSTEM")
        self.is_mining = False
        self.stop_event.set()
        if self.new_work_queue.empty(): self.new_work_queue.put(None)
        self.toggle_button.config(state=tk.DISABLED, text="Stopping...")

    def set_settings_state(self, state):
        self.node_entry.config(state=state)
        self.wallet_entry.config(state=state)
        self.threads_spinbox.config(state=state)

    def run_work_fetcher(self, node_url, miner_address):
        while self.is_mining:
            try:
                response = requests.get(f"{node_url}/mining/get-work-longpoll", 
                                        params={'miner_address': miner_address}, 
                                        timeout=130)
                if response.status_code == 200:
                    if self.new_work_queue.full():
                        try: self.new_work_queue.get_nowait()
                        except: pass
                    self.new_work_queue.put(response.json())
                else:
                    self.log(f"Failed to get work: {response.status_code}", "ERROR")
                    time.sleep(10)
            except requests.exceptions.RequestException:
                if self.is_mining:
                    self.log("Network connection lost... retrying.", "ERROR")
                    time.sleep(10)
            except Exception as e:
                 if self.is_mining:
                    self.log(f"Work fetcher error: {e}", "ERROR")
                    time.sleep(10)

    def run_mining_controller(self, node_url, miner_address, num_threads):
        while self.is_mining:
            try:
                work_data = self.new_work_queue.get()
                if work_data is None or not self.is_mining: break

                if self.processes:
                    self.stop_event.set()
                    for p in self.processes:
                        p.join(timeout=0.5); p.terminate() if p.is_alive() else None
                    self.processes = []
                self.stop_event.clear()

                work_data['target'] = int(work_data['target'])
                self.current_difficulty = MAX_TARGET / work_data['target']
                self.current_block = work_data['index']
                self.root.after(0, self.update_stats_bar)
                self.log(f"New work for block #{self.current_block} | Difficulty: {self.current_difficulty:.4f}", "INFO")

                timestamp = time.time()
                work_queue, result_queue = ProcQueue(), ProcQueue()
                
                for i in range(num_threads):
                    w_data = work_data.copy()
                    w_data['timestamp'] = timestamp
                    w_data['nonce_start'], w_data['nonce_step'] = i, num_threads
                    work_queue.put(w_data)
                    p = Process(target=worker, args=(work_queue, result_queue, self.stop_event, self.stats_queue))
                    self.processes.append(p)
                    p.start()

                found_block = None
                while self.is_mining and found_block is None:
                    if not self.new_work_queue.empty(): break
                    if not result_queue.empty():
                        found_block = result_queue.get()
                        break
                    time.sleep(0.1)
                
                if self.is_mining and found_block:
                    self.submit_block(found_block, node_url, miner_address)

            except Exception as e:
                if self.is_mining: self.log(f"Mining controller error: {e}", "ERROR")

        self.root.after(0, self.finalize_stop)

    def submit_block(self, found_block, node_url, miner_address):
        found_block.hash = found_block.calculate_hash()
        headers = {'Content-Type': 'application/json'}
        payload = {'miner_address': miner_address, 'block_data': found_block.to_dict()}
        try:
            submit_response = requests.post(f"{node_url}/mining/submit-block", json=payload, headers=headers, timeout=10)
            if submit_response.status_code == 201:
                self.accepted_shares += 1
                self.log(f"✅ Block #{found_block.index} FOUND! | ACCEPTED.", "SUCCESS")
            else:
                self.rejected_shares += 1
                self.log(f"❌ Block #{found_block.index} REJECTED: {submit_response.status_code} {submit_response.text}", "ERROR")
            self.update_stats_bar()
        except requests.exceptions.RequestException as e:
            self.log(f"Network error submitting block: {e}", "ERROR")

    def finalize_stop(self):
        self.is_mining = False
        # 프로세스가 남아있을 경우 확실하게 정리
        if self.processes:
            self.stop_event.set()
            for p in self.processes:
                p.join(timeout=0.5); p.terminate() if p.is_alive() else None
            self.processes = []

        if self.toggle_button.winfo_exists():
            self.toggle_button.config(state=tk.NORMAL, text="▶ Start Mining", bg=SUCCESS_COLOR)
            self.set_settings_state(tk.NORMAL)
        
        self.current_hashrate = 0.0
        self.update_stats_bar()
        self.log("Mining finalized and stopped.", "SYSTEM")
        
        if self.shutdown_requested:
            self.root.destroy()

    def start_stats_thread(self):
        stats_thread = threading.Thread(target=self.update_stats_loop, daemon=True)
        stats_thread.start()

    def update_stats_loop(self):
        while True:
            while not self.stats_queue.empty():
                self.total_hashes += self.stats_queue.get()
            current_time = time.time()
            if self.is_mining and current_time - self.last_stats_time >= 2:
                elapsed_time = current_time - self.last_stats_time
                if elapsed_time > 0:
                    self.current_hashrate = self.total_hashes / elapsed_time
                    self.root.after(0, self.update_stats_bar)
                self.total_hashes = 0
                self.last_stats_time = current_time
            time.sleep(0.5)

    def update_stats_bar(self):
        if self.hashrate_label.winfo_exists():
            self.hashrate_label.config(text=f"Hashrate: {self.current_hashrate:.2f} H/s")
            self.block_label.config(text=f"Block: {self.current_block}")
            self.diff_label.config(text=f"Diff: {self.current_difficulty:.4f}")
            self.shares_label.config(text=f"Accepted: {self.accepted_shares} / Rejected: {self.rejected_shares}")

if __name__ == '__main__':
    freeze_support() 
    root = tk.Tk()
    app = MinerApp(root)
    root.mainloop()
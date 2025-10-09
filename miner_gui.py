# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
# (Argon2id Native Python Miner GUI)
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
import os
from multiprocessing import Process, Queue, Event, cpu_count, freeze_support
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
# --- [수정됨] 채굴 성공 및 경고 메시지를 위한 새 색상 정의 ---
VIBRANT_SUCCESS_COLOR = "#c678dd" # 화려한 마젠타 색상
WARNING_COLOR_YELLOW = "#e5c07b"

JOB_CHECK_INTERVAL = 10 
# --- [추가됨] 경고 메시지 출력 간격 (초 단위) ---
WARNING_INTERVAL = 1800 # 30분

# --- GUI Application ---
class MinerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CMXP Miner (Argon2id)")
        self.root.geometry("950x700")

        # 기본 설정값
        self.node_url = tk.StringVar(value="https://cmxp-node.onrender.com") 
        self.num_threads = tk.IntVar(value=max(1, cpu_count() - 1))

        # 채굴 관련 변수 초기화
        self.processes = []
        self.stop_event = Event()
        self.stats_queue = Queue() 
        self.is_mining = False
        
        # 통계 변수
        self.total_hashes = 0
        self.last_stats_time = time.time()
        self.accepted_shares = 0
        self.rejected_shares = 0
        self.current_difficulty = 0.0
        self.current_block = 0
        self.current_hashrate = 0.0

        # --- [추가됨] 경고 메시지 타이머 변수 ---
        self.last_warning_time = 0
        
        # 로그 애니메이션 관련 변수
        self.spinner = ['⛏️     ', ' ⛏️    ', '  ⛏️   ', '   ⛏️  ', '    ⛏️ ', '     ⛏️']
        self.spinner_index = 0

        # 종료 처리 관련
        self.shutdown_requested = False
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.setup_styles()
        self.setup_ui()
        self.start_stats_thread()

    def setup_styles(self):
        style = ttk.Style(); style.theme_use('clam')
        self.root.configure(bg=BG_COLOR)
        # --- [수정됨] 기본 폰트 크기 1 증가 ---
        style.configure('.', background=BG_COLOR, foreground=FG_COLOR, font=("Consolas", 11))
        style.configure('TFrame', background=BG_COLOR)
        style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR)
        style.configure('TButton', background="#3e4451", foreground=FG_COLOR, relief="flat")
        style.map('TButton', background=[('active', ACCENT_COLOR), ('disabled', '#5c6370')])
        style.configure('TEntry', fieldbackground="#3e4451", foreground=FG_COLOR, insertcolor=FG_COLOR, relief="flat")
        style.configure('Header.TFrame', background="#1e2127")
        # --- [수정됨] 통계 라벨 폰트 크기 1 증가 ---
        style.configure('Stats.TLabel', font=("Consolas", 11, "bold"))

    def setup_ui(self):
        main_frame = ttk.Frame(self.root); main_frame.pack(fill=tk.BOTH, expand=True)
        header_frame = ttk.Frame(main_frame, style='Header.TFrame', padding=15); header_frame.pack(fill=tk.X)
        ttk.Label(header_frame, text="Node URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.node_entry = ttk.Entry(header_frame, textvariable=self.node_url); self.node_entry.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=(5, 15))
        ttk.Label(header_frame, text="Wallet Address:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.wallet_entry = ttk.Entry(header_frame); self.wallet_entry.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=(5, 15))
        ttk.Label(header_frame, text="Threads:").grid(row=0, column=2, sticky=tk.W, pady=5)
        # --- [수정됨] 스핀박스 폰트 크기 1 증가 ---
        self.threads_spinbox = tk.Spinbox(header_frame, textvariable=self.num_threads, from_=1, to=cpu_count(), width=5, font=("Consolas", 11), bg="#3e4451", fg=FG_COLOR, relief="flat"); self.threads_spinbox.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)
        # --- [수정됨] 시작 버튼 폰트 크기 1 증가 ---
        self.toggle_button = tk.Button(header_frame, text="▶ Start Mining", command=self.toggle_mining, bg=SUCCESS_COLOR, fg="white", font=("Consolas", 11, "bold"), relief="flat"); self.toggle_button.grid(row=1, column=2, columnspan=2, sticky=tk.EW, pady=5, padx=5)
        header_frame.columnconfigure(1, weight=1)
        log_frame = ttk.Frame(main_frame, padding=10); log_frame.pack(fill=tk.BOTH, expand=True)
        # --- [수정됨] 로그 텍스트 폰트 크기 1 증가 ---
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg="black", fg="white", font=("Consolas", 10), relief="flat"); self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # --- [수정됨] 로그 태그 설정 (성공/에러/시스템 + 새 태그 추가) ---
        self.log_text.tag_config("INFO", foreground=FG_COLOR)
        self.log_text.tag_config("SUCCESS", foreground=SUCCESS_COLOR) # 일반 성공(연두색)은 유지
        self.log_text.tag_config("ERROR", foreground=ERROR_COLOR)
        self.log_text.tag_config("SYSTEM", foreground=WARNING_COLOR_YELLOW)
        self.log_text.tag_config("STALE", foreground="#d19a66")
        
        # --- [추가됨] 새로운 태그: 블록 발견(화려함) 및 경고 메시지용 ---
        self.log_text.tag_config("FOUND", foreground=VIBRANT_SUCCESS_COLOR, font=("Consolas", 12, "bold"))
        self.log_text.tag_config("WARN_BORDER", foreground=WARNING_COLOR_YELLOW, font=("Consolas", 12, "bold"))
        self.log_text.tag_config("WARN_HEADER", foreground=ERROR_COLOR, font=("Consolas", 12, "bold"))
        self.log_text.tag_config("WARN_BODY", foreground="white", font=("Consolas", 12, "bold"))

        self.log("Welcome to CMXP Argon2id Miner! Configure settings and click 'Start Mining'.\n", "SYSTEM")
        stats_frame = ttk.Frame(main_frame, style='Header.TFrame', padding=5); stats_frame.pack(fill=tk.X)
        self.hashrate_label = ttk.Label(stats_frame, text="Hashrate: 0.00 H/s", style='Stats.TLabel'); self.hashrate_label.pack(side=tk.LEFT, padx=10)
        self.block_label = ttk.Label(stats_frame, text="Block: 0", style='Stats.TLabel'); self.block_label.pack(side=tk.LEFT, padx=10)
        self.diff_label = ttk.Label(stats_frame, text="Diff: 0.0000", style='Stats.TLabel'); self.diff_label.pack(side=tk.LEFT, padx=10)
        self.shares_label = ttk.Label(stats_frame, text="Accepted: 0 / Rejected: 0", style='Stats.TLabel'); self.shares_label.pack(side=tk.RIGHT, padx=10)

    # --- [추가됨] 경고 메시지를 GUI 로그 창에 표시하는 함수 ---
    def display_warning_message(self):
        if not self.log_text.winfo_exists(): return

        BOX_WIDTH = 80  # 박스 내부의 가로 너비 (문자 기준)

        # 각 줄의 텍스트 정의
        header_text = "/!\\ IMPORTANT WARNING /!\\"
        line1_text = "CMXP coin is intended for learning and experimental purposes only."
        line2_text = "This coin holds NO monetary value and should NEVER be traded for money"
        line3_text = "or other assets. Use at your own risk. Please mine responsibly."

        # .center() 와 .ljust()를 사용해 자동으로 공백을 채워 정렬된 문자열 생성
        border_line = f"+{'-' * BOX_WIDTH}+\n"
        header_line_content = header_text.center(BOX_WIDTH)
        line1_content = f" {line1_text}".ljust(BOX_WIDTH)
        line2_content = f" {line2_text}".ljust(BOX_WIDTH)
        line3_content = f" {line3_text}".ljust(BOX_WIDTH)

        # GUI에 텍스트 삽입
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, "\n")
        self.log_text.insert(tk.END, border_line, "WARN_BORDER")

        self.log_text.insert(tk.END, "|", "WARN_BORDER")
        self.log_text.insert(tk.END, header_line_content, "WARN_HEADER")
        self.log_text.insert(tk.END, "|\n", "WARN_BORDER")

        self.log_text.insert(tk.END, border_line, "WARN_BORDER")

        self.log_text.insert(tk.END, "|", "WARN_BORDER")
        self.log_text.insert(tk.END, line1_content, "WARN_BODY")
        self.log_text.insert(tk.END, "|\n", "WARN_BORDER")

        self.log_text.insert(tk.END, "|", "WARN_BORDER")
        self.log_text.insert(tk.END, line2_content, "WARN_BODY")
        self.log_text.insert(tk.END, "|\n", "WARN_BORDER")

        self.log_text.insert(tk.END, "|", "WARN_BORDER")
        self.log_text.insert(tk.END, line3_content, "WARN_BODY")
        self.log_text.insert(tk.END, "|\n", "WARN_BORDER")
        
        self.log_text.insert(tk.END, border_line, "WARN_BORDER")
        self.log_text.insert(tk.END, "\n")
        
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)

    def on_closing(self):
        if self.is_mining:
            self.log("Close requested. Shutting down mining processes...", "SYSTEM"); self.shutdown_requested = True; self.stop_mining()
        else: self.root.destroy()

    def log(self, message, level="INFO"):
        timestamp = get_current_timestamp()
        self.root.after(0, self._update_log, f"[{timestamp}] {message}\n", level)

    def _update_log(self, message, level):
        if self.log_text.winfo_exists():
            self.log_text.config(state=tk.NORMAL)
            self.log_text.insert(tk.END, message, level)
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)

    def _update_searching_log(self, char):
        if not self.log_text.winfo_exists(): return
        self.log_text.config(state=tk.NORMAL)
        
        last_line_start = self.log_text.index("end-1c").split('.')[0] + ".0"
        last_line_text = self.log_text.get(last_line_start, "end-1c")

        if "Searching for block" in last_line_text:
            self.log_text.delete(last_line_start, tk.END)

        timestamp = get_current_timestamp()
        message = f"[{timestamp}] Searching for block #{self.current_block}... {char}\n"
        self.log_text.insert(tk.END, message, "SYSTEM")
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
    
    def _clear_searching_log(self):
        if self.log_text.winfo_exists():
            self.log_text.config(state=tk.NORMAL)
            last_line_start = self.log_text.index("end-1c").split('.')[0] + ".0"
            last_line_text = self.log_text.get(last_line_start, "end-1c")
            if "Searching for block" in last_line_text:
                self.log_text.delete(last_line_start, tk.END)
            self.log_text.config(state=tk.DISABLED)

    def toggle_mining(self):
        if self.is_mining: self.stop_mining()
        else: self.start_mining()

    def start_mining(self):
        wallet_address = self.wallet_entry.get().strip()
        node_url = self.node_url.get().strip()
        try: threads = self.num_threads.get()
        except tk.TclError: messagebox.showerror("Error", "Invalid number of threads."); return
        if not wallet_address or not node_url: messagebox.showerror("Error", "Please enter Node URL and Wallet Address."); return
        self.is_mining = True; self.stop_event.clear()
        self.toggle_button.config(text="■ Stop Mining", bg=ERROR_COLOR); self.set_settings_state(tk.DISABLED)
        self.log(f"Starting mining process with {threads} threads...", "SYSTEM")

        # --- [추가됨] 채굴 시작 시 경고 메시지 표시 및 타이머 초기화 ---
        self.display_warning_message()
        self.last_warning_time = time.time()
        
        self.mining_thread = threading.Thread(target=self.run_mining_loop, args=(node_url, wallet_address, threads), daemon=True); self.mining_thread.start()

    def stop_mining(self):
        if not self.is_mining: return
        self.log("Stopping mining process...", "SYSTEM"); self.is_mining = False; self.stop_event.set()
        self.toggle_button.config(state=tk.DISABLED, text="Stopping...")

    def set_settings_state(self, state):
        self.node_entry.config(state=state); self.wallet_entry.config(state=state); self.threads_spinbox.config(state=state)

    def check_work_status_gui(self, node_url, current_previous_hash, stop_checking, stale_work_event):
        while not stop_checking.is_set():
            try:
                response = requests.get(f"{node_url}/mining/latest-block", timeout=5)
                if response.status_code == 200:
                    latest_info = response.json()
                    if latest_info.get('hash') != current_previous_hash:
                        self.log(f"New block #{latest_info.get('index')} detected. Restarting work.", "STALE")
                        time.sleep(1) 
                        stale_work_event.set()
                        break
                elif response.status_code != 404: self.log(f"Could not get latest block info: {response.status_code}", "ERROR")
            except requests.exceptions.RequestException: pass
            time.sleep(JOB_CHECK_INTERVAL)

    def run_mining_loop(self, node_url, miner_address, num_threads):
        while self.is_mining:
            # --- [추가됨] 30분마다 경고 메시지 재출력 로직 ---
            if time.time() - self.last_warning_time > WARNING_INTERVAL:
                self.root.after(0, self.display_warning_message)
                self.last_warning_time = time.time()
            
            self.processes, checker_thread = [], None
            stale_work_event, stop_checking_event = threading.Event(), threading.Event()
            try:
                response = requests.get(f"{node_url}/mining/get-work", params={'miner_address': miner_address}, timeout=10)
                if not self.is_mining: break
                if response.status_code != 200: self.log(f"Failed to get work: {response.status_code} {response.text}", "ERROR"); time.sleep(10); continue
                work_data = response.json(); work_data['target'] = int(work_data['target'])
                if work_data['target'] <= 0: self.log("Invalid target received.", "ERROR"); time.sleep(10); continue
                self.current_difficulty = MAX_TARGET / work_data['target']; self.current_block = work_data['index']
                self.root.after(0, self.update_stats_bar)
                self.log(f"New work for block #{self.current_block} | Difficulty: {self.current_difficulty:.4f}")
                timestamp, work_queue, result_queue = time.time(), Queue(), Queue()
                current_previous_hash = work_data['previous_hash']
                checker_thread = threading.Thread(target=self.check_work_status_gui, args=(node_url, current_previous_hash, stop_checking_event, stale_work_event), daemon=True); checker_thread.start()
                for i in range(num_threads):
                    w_data = work_data.copy(); w_data.update({'timestamp': timestamp, 'nonce_start': i, 'nonce_step': num_threads})
                    p = Process(target=worker, args=(work_queue, result_queue, self.stop_event, self.stats_queue)); self.processes.append(p)
                    work_queue.put(w_data); p.start()
                found_block = None; animation_last_update = time.time()
                while self.is_mining and found_block is None and not stale_work_event.is_set():
                    if not result_queue.empty(): found_block = result_queue.get(); break
                    if time.time() - animation_last_update > 3.0:
                        char = self.spinner[self.spinner_index]
                        self.root.after(0, self._update_searching_log, char)
                        self.spinner_index = (self.spinner_index + 1) % len(self.spinner)
                        animation_last_update = time.time()
                    time.sleep(0.1)
                
                self.root.after(0, self._clear_searching_log)
                
                if not self.stop_event.is_set(): self.stop_event.set()
                stop_checking_event.set()
                if checker_thread: checker_thread.join(timeout=1)
                for p in self.processes: p.join(timeout=0.5); p.terminate()
                self.processes = []
                if stale_work_event.is_set():
                    if self.is_mining: self.stop_event.clear(); continue
                    else: break
                if self.is_mining and found_block: self.submit_block(found_block, node_url, miner_address)
                if self.is_mining: self.stop_event.clear()
            except requests.exceptions.RequestException as e:
                if self.is_mining: self.log(f"Network error: {e}. Retrying in 10s...", "ERROR"); time.sleep(10)
            except Exception as e:
                if self.is_mining: self.log(f"Unexpected error in mining loop: {e}", "ERROR"); self.is_mining = False; break
        self.root.after(0, self.finalize_stop)

    def submit_block(self, found_block, node_url, miner_address):
        found_block.hash = found_block.calculate_hash()
        headers = {'Content-Type': 'application/json'}; payload = {'miner_address': miner_address, 'block_data': found_block.to_dict()}
        try:
            submit_response = requests.post(f"{node_url}/mining/submit-block", json=payload, headers=headers, timeout=10)
            if submit_response.status_code == 201:
                self.accepted_shares += 1
                # --- [수정됨] 로그 레벨을 'FOUND'로 변경하여 새 스타일 적용 ---
                self.log(f"✅ Block #{found_block.index} FOUND! | ACCEPTED. 🚀 🎉 🥳", "FOUND")
            else:
                self.rejected_shares += 1; self.log(f"❌ Block #{found_block.index} REJECTED: {submit_response.text}", "ERROR")
            self.root.after(0, self.update_stats_bar)
        except requests.exceptions.RequestException as e: self.log(f"Network error submitting block: {e}", "ERROR")

    def finalize_stop(self):
        self.is_mining = False
        if self.toggle_button.winfo_exists():
            self.toggle_button.config(state=tk.NORMAL, text="▶ Start Mining", bg=SUCCESS_COLOR); self.set_settings_state(tk.NORMAL)
        self.current_hashrate = 0.0; self.update_stats_bar()
        self.log("Mining finalized and stopped.", "SYSTEM")
        if self.shutdown_requested: self.root.destroy()

    def start_stats_thread(self):
        stats_thread = threading.Thread(target=self.update_stats_loop, daemon=True); stats_thread.start()

    def update_stats_loop(self):
        while True:
            while not self.stats_queue.empty(): self.total_hashes += self.stats_queue.get()
            current_time = time.time()
            if self.is_mining and current_time - self.last_stats_time >= 2:
                elapsed_time = current_time - self.last_stats_time
                if elapsed_time > 0: self.current_hashrate = self.total_hashes / elapsed_time; self.root.after(0, self.update_stats_bar)
                self.total_hashes = 0; self.last_stats_time = current_time
            time.sleep(0.5)

    def update_stats_bar(self):
        if self.hashrate_label.winfo_exists():
            self.hashrate_label.config(text=f"Hashrate: {self.current_hashrate:.2f} H/s"); self.block_label.config(text=f"Block: {self.current_block}")
            self.diff_label.config(text=f"Diff: {self.current_difficulty:.4f}"); self.shares_label.config(text=f"Accepted: {self.accepted_shares} / Rejected: {self.rejected_shares}")

# Entry point
if __name__ == '__main__':
    freeze_support() 
    root = tk.Tk(); app = MinerApp(root); root.mainloop()
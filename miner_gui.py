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
# (이 파일들이 동일 디렉토리에 있어야 합니다)
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

        # 종료 처리 관련 (FIX 1-1)
        self.shutdown_requested = False
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

        self.setup_styles()
        self.setup_ui()
        self.start_stats_thread()

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        
        # Dark Theme Configuration
        self.root.configure(bg=BG_COLOR)
        style.configure('.', background=BG_COLOR, foreground=FG_COLOR, font=("Consolas", 10))
        style.configure('TFrame', background=BG_COLOR)
        style.configure('TLabel', background=BG_COLOR, foreground=FG_COLOR)
        style.configure('TButton', background="#3e4451", foreground=FG_COLOR, relief="flat")
        style.map('TButton', background=[('active', ACCENT_COLOR), ('disabled', '#5c6370')])
        style.configure('TEntry', fieldbackground="#3e4451", foreground=FG_COLOR, insertcolor=FG_COLOR, relief="flat")
        
        # Custom Styles
        style.configure('Header.TFrame', background="#1e2127")
        style.configure('Stats.TLabel', font=("Consolas", 10, "bold"))

    def setup_ui(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- 설정 헤더 프레임 ---
        header_frame = ttk.Frame(main_frame, style='Header.TFrame', padding=15)
        header_frame.pack(fill=tk.X)

        # Node URL Input
        ttk.Label(header_frame, text="Node URL:").grid(row=0, column=0, sticky=tk.W, pady=5)
        self.node_entry = ttk.Entry(header_frame, textvariable=self.node_url)
        self.node_entry.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=(5, 15))

        # Wallet Address Input
        ttk.Label(header_frame, text="Wallet Address:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.wallet_entry = ttk.Entry(header_frame)
        self.wallet_entry.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=(5, 15))

        # Threads Selector
        ttk.Label(header_frame, text="Threads:").grid(row=0, column=2, sticky=tk.W, pady=5)
        # 표준 tk.Spinbox 사용 (스타일링 용이성)
        self.threads_spinbox = tk.Spinbox(header_frame, textvariable=self.num_threads, from_=1, to=cpu_count(), width=5, font=("Consolas", 10), bg="#3e4451", fg=FG_COLOR, relief="flat")
        self.threads_spinbox.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)

        # Start/Stop Button (tk.Button으로 색상 제어)
        self.toggle_button = tk.Button(header_frame, text="▶ Start Mining", command=self.toggle_mining, bg=SUCCESS_COLOR, fg="white", font=("Consolas", 10, "bold"), relief="flat")
        self.toggle_button.grid(row=1, column=2, columnspan=2, sticky=tk.EW, pady=5, padx=5)

        header_frame.columnconfigure(1, weight=1)

        # --- 로그 출력 프레임 ---
        log_frame = ttk.Frame(main_frame, padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg="black", fg="white", font=("Consolas", 9), relief="flat")
        self.log_text.pack(fill=tk.BOTH, expand=True)
        
        # 로그 색상 태그 설정 (디자인 개선: 1)
        self.log_text.tag_config("INFO", foreground=FG_COLOR)
        self.log_text.tag_config("SUCCESS", foreground=SUCCESS_COLOR)
        self.log_text.tag_config("ERROR", foreground=ERROR_COLOR)
        self.log_text.tag_config("SYSTEM", foreground="#e5c07b") # Yellow

        self.log("Welcome to CMXP Argon2id Miner! Configure settings and click 'Start Mining'.\n", "SYSTEM")

        # --- 상태 표시줄 (Stats Bar) ---
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

    # (FIX 1-1) 안전한 종료 처리 핸들러
    def on_closing(self):
        if self.is_mining:
            # 채굴 중일 경우, 종료 요청 플래그 설정 후 채굴 중지 시작
            self.log("Close requested. Shutting down mining processes...", "SYSTEM")
            self.shutdown_requested = True
            self.stop_mining()
            # 여기서 destroy()를 호출하지 않고, finalize_stop()이 처리하도록 대기
        else:
            # 채굴 중이 아니면 즉시 종료
            self.root.destroy()

    def log(self, message, level="INFO"):
        timestamp = get_current_timestamp()
        # GUI 업데이트는 메인 스레드에서만 가능
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
        # (Start mining 로직 생략 - 변경 없음)
        wallet_address = self.wallet_entry.get().strip()
        node_url = self.node_url.get().strip()
        try:
            threads = self.num_threads.get()
        except tk.TclError:
             messagebox.showerror("Error", "Invalid number of threads.")
             return

        if not wallet_address or not node_url:
            messagebox.showerror("Error", "Please enter Node URL and Wallet Address.")
            return

        self.is_mining = True
        self.stop_event.clear()
        self.toggle_button.config(text="■ Stop Mining", bg=ERROR_COLOR)
        self.set_settings_state(tk.DISABLED)
        self.log(f"Starting mining process with {threads} threads...", "SYSTEM")

        self.mining_thread = threading.Thread(target=self.run_mining_loop, args=(node_url, wallet_address, threads), daemon=True)
        self.mining_thread.start()

    def stop_mining(self):
        if not self.is_mining: return
        self.log("Stopping mining process...", "SYSTEM")
        self.is_mining = False
        self.stop_event.set()
        self.toggle_button.config(state=tk.DISABLED, text="Stopping...")

    def set_settings_state(self, state):
        # (Settings state 로직 생략 - 변경 없음)
        self.node_entry.config(state=state)
        self.wallet_entry.config(state=state)
        self.threads_spinbox.config(state=state)

    def run_mining_loop(self, node_url, miner_address, num_threads):
        # (Mining loop 로직 생략 - 핵심 로직 변경 없음)
        while self.is_mining:
            try:
                # 1. 작업 가져오기
                response = requests.get(f"{node_url}/mining/get-work", params={'miner_address': miner_address}, timeout=10)
                if response.status_code != 200:
                    self.log(f"Failed to get work: {response.status_code} {response.text}", "ERROR")
                    time.sleep(10); continue
                
                work_data = response.json()
                work_data['target'] = int(work_data['target'])

                if work_data['target'] <= 0:
                    self.log("Invalid target received.", "ERROR"); time.sleep(10); continue

                self.current_difficulty = MAX_TARGET / work_data['target']
                self.current_block = work_data['index']
                self.update_stats_bar() # 상태 표시줄 업데이트

                self.log(f"New work for block #{self.current_block} | Difficulty: {self.current_difficulty:.4f}")

                # 2. 채굴 준비 및 실행
                timestamp = time.time()
                work_queue, result_queue = Queue(), Queue()
                
                self.processes = []
                for i in range(num_threads):
                    w_data = work_data.copy()
                    w_data['timestamp'] = timestamp
                    w_data['nonce_start'], w_data['nonce_step'] = i, num_threads
                    work_queue.put(w_data)
                    p = Process(target=worker, args=(work_queue, result_queue, self.stop_event, self.stats_queue))
                    self.processes.append(p)
                    p.start()

                # 3. 결과 대기
                found_block = None
                while self.is_mining and found_block is None:
                    if not result_queue.empty():
                        found_block = result_queue.get()
                        break
                    time.sleep(0.1)

                # 4. 프로세스 정리
                if not self.stop_event.is_set():
                    self.stop_event.set()

                for p in self.processes:
                    p.join(timeout=0.5)
                    if p.is_alive():
                        p.terminate()
                self.processes = []
                
                # 5. 블록 제출
                if self.is_mining and found_block:
                    self.submit_block(found_block, node_url, miner_address)

                # 다음 라운드를 위해 이벤트 초기화
                if self.is_mining:
                    self.stop_event.clear() 

            except requests.exceptions.RequestException as e:
                if self.is_mining:
                    self.log(f"Network error: {e}. Retrying in 10s...", "ERROR")
                    time.sleep(10)
            except Exception as e:
                if self.is_mining:
                    self.log(f"Unexpected error: {e}", "ERROR")
                    self.is_mining = False
                    break
        
        # 채굴 루프 종료 후 UI 상태 복원 및 종료 처리 (FIX 1-1)
        self.root.after(0, self.finalize_stop)

    def submit_block(self, found_block, node_url, miner_address):
        # (Submit block 로직 생략 - 변경 없음)
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

    # (FIX 1-1) 종료 처리 통합
    def finalize_stop(self):
        # 메인 스레드에서 UI 최종 업데이트
        self.is_mining = False
        if self.toggle_button.winfo_exists():
            self.toggle_button.config(state=tk.NORMAL, text="▶ Start Mining", bg=SUCCESS_COLOR)
            self.set_settings_state(tk.NORMAL)
        
        self.current_hashrate = 0.0
        self.update_stats_bar()
        self.log("Mining finalized and stopped.", "SYSTEM")
        
        # 종료 요청이 있었다면(X 버튼 클릭) 프로그램 종료
        if self.shutdown_requested:
            self.root.destroy()

    def start_stats_thread(self):
        # (Stats thread 로직 생략 - 변경 없음)
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

# Entry point
if __name__ == '__main__':
    # Windows에서 멀티프로세싱 사용 시 필수 (EXE 빌드 시)
    freeze_support() 
    root = tk.Tk()
    app = MinerApp(root)
    root.mainloop()
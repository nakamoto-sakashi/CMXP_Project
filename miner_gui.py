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
# 멀티프로세싱 관련 임포트. freeze_support는 Windows EXE 빌드 시 필수입니다.
from multiprocessing import Process, Queue, Event, cpu_count, freeze_support
from datetime import datetime

# core.py 및 miner.py의 공통 요소 임포트
from core import Block, MAX_TARGET
# miner.py의 worker 함수 임포트 (실제 채굴 수행)
from miner import worker, get_current_timestamp

# --- GUI Application ---
class MinerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CMXP Miner (Argon2id Native)")
        self.root.geometry("800x600")
        self.root.configure(bg="#2d2d2d")

        # 기본 설정값
        # 배포 시 기본값을 https://cmxp-node.onrender.com 로 변경할 수 있습니다.
        self.node_url = tk.StringVar(value="http://127.0.0.1:5000") 
        self.num_threads = tk.IntVar(value=max(1, cpu_count() - 1)) # 기본값: 코어 수 - 1

        # 채굴 관련 변수 초기화
        self.processes = []
        self.stop_event = Event()
        # stats_queue는 worker로부터 해시 카운트를 받습니다.
        self.stats_queue = Queue() 
        self.is_mining = False
        self.total_hashes = 0
        self.last_stats_time = time.time()

        self.setup_ui()
        self.start_stats_thread()

    def setup_ui(self):
        main_frame = tk.Frame(self.root, bg="#2d2d2d", padx=15, pady=15)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- 설정 프레임 ---
        settings_frame = tk.Frame(main_frame, bg="#3d3d3d", pady=10, padx=10)
        settings_frame.pack(fill=tk.X)

        # Node URL Input
        tk.Label(settings_frame, text="Node URL:", fg="white", bg="#3d3d3d", font=("Arial", 10)).grid(row=0, column=0, sticky=tk.W, pady=5)
        self.node_entry = tk.Entry(settings_frame, textvariable=self.node_url, font=("Arial", 10))
        self.node_entry.grid(row=0, column=1, sticky=tk.EW, pady=5, padx=(5, 10))

        # Wallet Address Input
        tk.Label(settings_frame, text="Wallet Address:", fg="white", bg="#3d3d3d", font=("Arial", 10)).grid(row=1, column=0, sticky=tk.W, pady=5)
        self.wallet_entry = tk.Entry(settings_frame, font=("Arial", 10))
        self.wallet_entry.grid(row=1, column=1, sticky=tk.EW, pady=5, padx=(5, 10))

        # Threads Selector
        tk.Label(settings_frame, text="Threads:", fg="white", bg="#3d3d3d", font=("Arial", 10)).grid(row=0, column=2, sticky=tk.W, pady=5)
        self.threads_spinbox = tk.Spinbox(settings_frame, textvariable=self.num_threads, from_=1, to=cpu_count(), width=5, font=("Arial", 10))
        self.threads_spinbox.grid(row=0, column=3, sticky=tk.W, pady=5, padx=5)

        settings_frame.columnconfigure(1, weight=1)

        # --- 컨트롤 버튼 프레임 ---
        button_frame = tk.Frame(main_frame, bg="#2d2d2d", pady=10)
        button_frame.pack(fill=tk.X)
        self.toggle_button = tk.Button(button_frame, text="Start Mining", command=self.toggle_mining, font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", width=15)
        self.toggle_button.pack(side=tk.LEFT, padx=5)
        
        # Hashrate 표시
        self.hashrate_label = tk.Label(button_frame, text="Hashrate: 0.00 H/s", fg="cyan", bg="#2d2d2d", font=("Arial", 12, "bold"))
        self.hashrate_label.pack(side=tk.RIGHT, padx=5)

        # --- 로그 출력 프레임 ---
        log_frame = tk.Frame(main_frame, bg="#2d2d2d")
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, bg="black", fg="lime", font=("Courier New", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)
        self.log("Welcome to CMXP Argon2id Miner!\nConfigure settings and click 'Start Mining'.\n\n")

    def log(self, message, level="INFO"):
        timestamp = get_current_timestamp()
        # GUI 업데이트는 메인 스레드에서만 가능
        self.root.after(0, self._update_log, f"[{timestamp}] [{level}] {message}\n")

    def _update_log(self, message):
        if self.log_text.winfo_exists():
            self.log_text.insert(tk.END, message)
            self.log_text.see(tk.END)

    def toggle_mining(self):
        if self.is_mining:
            self.stop_mining()
        else:
            self.start_mining()

    def start_mining(self):
        wallet_address = self.wallet_entry.get().strip()
        node_url = self.node_url.get().strip()
        threads = self.num_threads.get()

        if not wallet_address or not node_url:
            messagebox.showerror("Error", "Please enter Node URL and Wallet Address.")
            return

        self.is_mining = True
        self.stop_event.clear()
        self.toggle_button.config(text="Stop Mining", bg="#f44336")
        self.set_settings_state(tk.DISABLED)
        self.log(f"Starting mining process with {threads} threads...")

        # 채굴 로직을 별도 스레드에서 실행하여 GUI가 멈추지 않도록 함
        self.mining_thread = threading.Thread(target=self.run_mining_loop, args=(node_url, wallet_address, threads), daemon=True)
        self.mining_thread.start()

    def stop_mining(self):
        if not self.is_mining: return
        self.log("Stopping mining process...")
        self.is_mining = False
        self.stop_event.set()
        
        # GUI 상태는 run_mining_loop가 종료될 때 최종 업데이트됩니다.
        self.toggle_button.config(state=tk.DISABLED, text="Stopping...")

    def set_settings_state(self, state):
        self.node_entry.config(state=state)
        self.wallet_entry.config(state=state)
        self.threads_spinbox.config(state=state)

    def run_mining_loop(self, node_url, miner_address, num_threads):
        # 이 함수는 백그라운드 스레드에서 실행됩니다.
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
                    self.log("Invalid target received.", "ERROR")
                    time.sleep(10); continue

                difficulty = MAX_TARGET / work_data['target']
                self.log(f"New work for block #{work_data['index']} | Difficulty: {difficulty:.4f}")

                # 2. 채굴 준비 및 실행
                timestamp = time.time()
                work_queue, result_queue = Queue(), Queue()
                
                self.processes = []
                for i in range(num_threads):
                    w_data = work_data.copy()
                    w_data['timestamp'] = timestamp
                    w_data['nonce_start'], w_data['nonce_step'] = i, num_threads
                    work_queue.put(w_data)
                    # miner.py의 worker 함수 사용 (stats_queue 전달)
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
                self.stop_event.set() # 모든 워커에게 중단 신호
                for p in self.processes:
                    p.join(timeout=0.5)
                    if p.is_alive():
                        p.terminate()
                self.processes = []
                
                # 다음 라운드를 위해 이벤트 초기화 (단, 채굴이 활성 상태일 경우에만)
                if self.is_mining:
                    self.stop_event.clear() 

                # 5. 블록 제출 (채굴 중지 신호가 오지 않았고 블록을 찾았을 경우)
                if self.is_mining and found_block:
                    self.submit_block(found_block, node_url, miner_address)

            except requests.exceptions.RequestException as e:
                if self.is_mining:
                    self.log(f"Network error: {e}. Retrying in 10s...", "ERROR")
                    time.sleep(10)
            except Exception as e:
                if self.is_mining:
                    self.log(f"Unexpected error: {e}", "ERROR")
                    self.stop_mining()
                    break
        
        # 채굴 루프 종료 후 UI 상태 복원
        self.root.after(0, self.finalize_stop)

    def submit_block(self, found_block, node_url, miner_address):
        found_block.hash = found_block.calculate_hash()
        headers = {'Content-Type': 'application/json'}
        payload = {'miner_address': miner_address, 'block_data': found_block.to_dict()}
        try:
            submit_response = requests.post(f"{node_url}/mining/submit-block", json=payload, headers=headers, timeout=10)
            
            if submit_response.status_code == 201:
                self.log(f"✅ Block #{found_block.index} FOUND! | SUBMITTED.", "SUCCESS")
            else:
                self.log(f"❌ Block #{found_block.index} REJECTED: {submit_response.status_code} {submit_response.text}", "ERROR")
        except requests.exceptions.RequestException as e:
            self.log(f"Network error submitting block: {e}", "ERROR")

    def finalize_stop(self):
        # 메인 스레드에서 UI 최종 업데이트
        self.toggle_button.config(state=tk.NORMAL, text="Start Mining", bg="#4CAF50")
        self.set_settings_state(tk.NORMAL)
        self.hashrate_label.config(text="Hashrate: 0.00 H/s")
        self.log("Mining finalized and stopped.")

    def start_stats_thread(self):
        # 통계 수집 및 출력을 위한 별도 스레드
        stats_thread = threading.Thread(target=self.update_stats, daemon=True)
        stats_thread.start()

    def update_stats(self):
        # 백그라운드 스레드에서 실행되어 주기적으로 해시레이트 계산
        while True:
            # 통계 큐 확인 및 합산
            while not self.stats_queue.empty():
                self.total_hashes += self.stats_queue.get()

            # 주기적 통계 출력 (2초마다)
            current_time = time.time()
            if self.is_mining and current_time - self.last_stats_time >= 2:
                elapsed_time = current_time - self.last_stats_time
                if elapsed_time > 0:
                    hashrate = self.total_hashes / elapsed_time
                    # UI 업데이트는 메인 스레드에서
                    self.root.after(0, lambda hr=hashrate: self.hashrate_label.config(text=f"Hashrate: {hr:.2f} H/s"))
                
                self.total_hashes = 0
                self.last_stats_time = current_time
            
            time.sleep(0.5)

# Entry point
if __name__ == '__main__':
    # Windows에서 멀티프로세싱을 사용한 GUI 앱을 빌드할 때 필수
    freeze_support() 
    root = tk.Tk()
    app = MinerApp(root)
    # 앱 종료 시 채굴 프로세스 확실히 종료
    root.protocol("WM_DELETE_WINDOW", app.stop_mining)
    root.mainloop()
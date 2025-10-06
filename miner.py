# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
# (Algorithm changed to Argon2id)
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

import requests, argparse, time, json
import argon2.low_level
from multiprocessing import Process, Queue, cpu_count, Event
# Import Block and constants from core.py
from core import (
    Block, MAX_TARGET, CMXP_ARGON2_SALT, ARGON2_TIME_COST, 
    ARGON2_MEMORY_COST, ARGON2_HASH_LEN, ARGON2_TYPE
)
from datetime import datetime
import colorama
from colorama import Fore, Style

# --- Constants ---
WARNING_INTERVAL = 1800 # 30 minutes

def get_current_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# --- 핵심 수정 사항: worker 함수가 Argon2를 사용하고 통계를 보고하도록 변경 ---
# stats_queue 추가: 해시레이트 계산을 위해 사용
def worker(work_queue, result_queue, stop_event, stats_queue):
    
    hash_count = 0
    while not stop_event.is_set():
        try:
            # 타임아웃을 설정하여 stop_event를 주기적으로 확인
            work_data = work_queue.get(timeout=1)
        except Exception: # Queue.Empty exception
            continue

        if work_data is None: break

        block_to_mine = Block(
            index=work_data['index'], timestamp=work_data['timestamp'],
            data=work_data['data'], previous_hash=work_data['previous_hash'],
            target=work_data['target'], nonce=work_data['nonce_start']
        )
        
        target = block_to_mine.target
        nonce_step = work_data['nonce_step']
        
        while not stop_event.is_set():
            hashing_blob = block_to_mine.get_normalized_hashing_blob()
            
            try:
                # Argon2id 해시 계산
                # 채굴 시 병렬성은 1로 설정 (멀티프로세싱으로 병렬화 구현)
                work_hash_bytes = argon2.low_level.hash_secret_raw(
                    secret=hashing_blob,
                    salt=CMXP_ARGON2_SALT,
                    time_cost=ARGON2_TIME_COST,
                    memory_cost=ARGON2_MEMORY_COST,
                    parallelism=1, 
                    hash_len=ARGON2_HASH_LEN,
                    type=ARGON2_TYPE
                )
            except Exception as e:
                print(f"[{get_current_timestamp()}] [ERROR] Argon2 hashing failed: {e}")
                stop_event.set()
                break

            hash_count += 1

            if int.from_bytes(work_hash_bytes, 'big') < target:
                stats_queue.put(hash_count) # 최종 통계 전송
                result_queue.put(block_to_mine)
                return # 블록 발견 시 종료
            
            block_to_mine.nonce += nonce_step

            # 주기적으로 통계 업데이트 (Argon2는 느리므로 5회마다 보고)
            if hash_count >= 5: 
                stats_queue.put(hash_count)
                hash_count = 0
                if stop_event.is_set(): break

# --------------------------------------------------------------------

def mine(node_url, miner_address, num_threads):
    colorama.init(autoreset=True)
    
    print(f"[*] CMXP Argon2id Multithreaded Miner starting...")
    print(f"[*] Threads: {num_threads} | Node: {node_url} | Wallet: {miner_address}")
    
    last_warning_time = time.time()
    print_warning()
    
    # 통계 관련 변수
    total_hashes = 0
    last_stats_time = time.time()

    while True:
        try:
            # 1. 작업 가져오기
            response = requests.get(f"{node_url}/mining/get-work", params={'miner_address': miner_address}, timeout=10)
            if response.status_code != 200:
                print(f"[{get_current_timestamp()}] [ERROR] Failed to get work: {response.status_code} {response.text}")
                time.sleep(10); continue
            
            work_data = response.json()
            # Target을 int로 변환
            work_data['target'] = int(work_data['target'])
            
            if work_data['target'] <= 0:
                print(f"[{get_current_timestamp()}] [ERROR] Invalid target received.")
                time.sleep(10); continue

            difficulty = MAX_TARGET / work_data['target']
            print(f"[{get_current_timestamp()}] New work for block #{work_data['index']} | Difficulty: {difficulty:.4f}")

            # 2. 채굴 준비
            timestamp = time.time()
            work_queue, result_queue, stats_queue = Queue(), Queue(), Queue()
            stop_event = Event()

            processes = []
            for i in range(num_threads):
                w_data = work_data.copy()
                w_data['timestamp'] = timestamp
                w_data['nonce_start'], w_data['nonce_step'] = i, num_threads
                work_queue.put(w_data)
                # stats_queue를 워커에 전달
                p = Process(target=worker, args=(work_queue, result_queue, stop_event, stats_queue))
                processes.append(p)
                p.start()
            
            # 3. 결과 대기 및 통계 출력
            start_time = time.time()
            found_block = None
            
            while found_block is None:
                # 결과 확인 (비블로킹 방식)
                if not result_queue.empty():
                    found_block = result_queue.get()
                    break
                
                # 통계 수집
                while not stats_queue.empty():
                    total_hashes += stats_queue.get()

                # 주기적 통계 출력 (5초마다)
                current_time = time.time()
                if current_time - last_stats_time >= 5:
                    elapsed_time = current_time - last_stats_time
                    hashrate = total_hashes / elapsed_time
                    print(f"[{get_current_timestamp()}] Hashrate: {hashrate:.2f} H/s")
                    total_hashes = 0
                    last_stats_time = current_time
                
                time.sleep(0.1) # CPU 부하 감소

            # 4. 프로세스 정리
            stop_event.set()
            end_time = time.time()
            
            found_block.hash = found_block.calculate_hash()
            
            for p in processes:
                p.join(timeout=1)
                if p.is_alive():
                    p.terminate()

            # 5. 블록 제출
            headers = {'Content-Type': 'application/json'}
            payload = {'miner_address': miner_address, 'block_data': found_block.to_dict()}
            submit_response = requests.post(f"{node_url}/mining/submit-block", json=payload, headers=headers, timeout=10)
            
            if submit_response.status_code == 201:
                print(Fore.MAGENTA + f"[{get_current_timestamp()}] ✅ Block #{found_block.index} FOUND! (Time: {end_time - start_time:.2f}s) | Submitted.")
            else:
                print(Fore.RED + f"[{get_current_timestamp()}] ❌ Block #{found_block.index} REJECTED: {submit_response.status_code} {submit_response.text}")
            
            if time.time() - last_warning_time > WARNING_INTERVAL:
                print_warning(); last_warning_time = time.time()

        except requests.exceptions.RequestException as e:
            print(f"[{get_current_timestamp()}] [ERROR] Network error: {e}. Retrying in 10 seconds...")
            time.sleep(10)
        except Exception as e:
            print(f"[{get_current_timestamp()}] [ERROR] Unexpected error: {e}")
            # 에러 발생 시 프로세스 정리 시도
            if 'stop_event' in locals() and not stop_event.is_set(): stop_event.set()
            if 'processes' in locals():
                 for p in processes:
                    if p.is_alive(): p.terminate()
            time.sleep(5)

def print_warning():
    # (Warning message remains the same)
    print()
    print(f"{Fore.YELLOW}+------------------------------------------------------+")
    print(f"{Fore.YELLOW}|            {Fore.RED}⚠️ IMPORTANT WARNING ⚠️{Fore.YELLOW}                   |")
    print(f"{Fore.YELLOW}+------------------------------------------------------+")
    print(f"{Fore.YELLOW}| {Style.BRIGHT + Fore.WHITE}CMXP coin is intended for learning and experimental  {Fore.YELLOW}|")
    print(f"{Fore.YELLOW}| {Style.BRIGHT + Fore.WHITE}purposes only. This coin holds NO monetary value and {Fore.YELLOW}|")
    print(f"{Fore.YELLOW}| {Style.BRIGHT + Fore.WHITE}should NEVER be traded for money or other assets.    {Fore.YELLOW}|")
    print(f"{Fore.YELLOW}+------------------------------------------------------+{Style.RESET_ALL}\n")

if __name__ == '__main__':
    # Required for PyInstaller/multiprocessing on Windows
    from multiprocessing import freeze_support
    freeze_support()

    parser = argparse.ArgumentParser(description="CMXP Argon2id Multithreaded CPU Miner")
    parser.add_argument('--node', default='http://127.0.0.1:5000', type=str, help='URL of the CMXP node')
    parser.add_argument('--wallet', required=True, type=str, help='Wallet address')
    parser.add_argument('--threads', default=cpu_count(), type=int, help='Number of threads')
    args = parser.parse_args()
    mine(args.node, args.wallet, args.threads)
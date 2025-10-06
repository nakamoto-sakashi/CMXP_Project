# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
# (Argon2id with Long Polling)
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

import requests, argparse, time, json, threading
import argon2.low_level
from multiprocessing import Process, Queue as ProcQueue, cpu_count, Event
from queue import Queue as ThreadQueue
from core import Block, MAX_TARGET, CMXP_ARGON2_SALT, ARGON2_TIME_COST, ARGON2_MEMORY_COST, ARGON2_HASH_LEN, ARGON2_TYPE
from datetime import datetime
import colorama
from colorama import Fore, Style

# --- Constants ---
WARNING_INTERVAL = 1800 # 30 minutes

def get_current_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def worker(work_queue, result_queue, stop_event, stats_queue):
    hash_count = 0
    while not stop_event.is_set():
        try:
            work_data = work_queue.get(timeout=1)
        except Exception:
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
                work_hash_bytes = argon2.low_level.hash_secret_raw(
                    secret=hashing_blob, salt=CMXP_ARGON2_SALT, time_cost=ARGON2_TIME_COST,
                    memory_cost=ARGON2_MEMORY_COST, parallelism=1, hash_len=ARGON2_HASH_LEN,
                    type=ARGON2_TYPE
                )
            except Exception as e:
                print(f"[{get_current_timestamp()}] [ERROR] Argon2 hashing failed: {e}")
                stop_event.set()
                break
            hash_count += 1
            if int.from_bytes(work_hash_bytes, 'big') < target:
                stats_queue.put(hash_count)
                result_queue.put(block_to_mine)
                return
            if hash_count >= 5: 
                stats_queue.put(hash_count)
                hash_count = 0
                if stop_event.is_set(): break

def work_fetcher(node_url, miner_address, new_work_queue, stop_mining_event):
    while not stop_mining_event.is_set():
        try:
            response = requests.get(f"{node_url}/mining/get-work-longpoll", 
                                    params={'miner_address': miner_address}, 
                                    timeout=130)
            if response.status_code == 200:
                if new_work_queue.full():
                    try: new_work_queue.get_nowait()
                    except: pass
                new_work_queue.put(response.json())
            else:
                print(f"[{get_current_timestamp()}] {Fore.RED}[ERROR] Failed to get work: {response.status_code}")
                time.sleep(10)
        except requests.exceptions.RequestException:
            if not stop_mining_event.is_set():
                print(f"[{get_current_timestamp()}] {Fore.RED}[ERROR] Network connection lost... retrying.")
                time.sleep(10)
        except Exception as e:
            if not stop_mining_event.is_set():
                print(f"[{get_current_timestamp()}] {Fore.RED}[ERROR] Work fetcher error: {e}")
                time.sleep(10)

def mine(node_url, miner_address, num_threads):
    colorama.init(autoreset=True)
    print(f"[*] CMXP Argon2id Multithreaded Miner starting...")
    print(f"[*] Threads: {num_threads} | Node: {node_url} | Wallet: {miner_address}")
    
    last_warning_time = time.time()
    print_warning()
    
    new_work_queue = ThreadQueue(maxsize=1)
    stop_mining_event = threading.Event()
    
    fetcher_thread = threading.Thread(target=work_fetcher, args=(node_url, miner_address, new_work_queue, stop_mining_event))
    fetcher_thread.daemon = True
    fetcher_thread.start()

    processes = []
    processes_stop_event = Event()
    total_hashes = 0
    last_stats_time = time.time()

    try:
        while not stop_mining_event.is_set():
            try:
                work_data = new_work_queue.get()
                if work_data is None: break

                if processes:
                    processes_stop_event.set()
                    for p in processes:
                        p.join(timeout=0.5); p.terminate() if p.is_alive() else None
                
                work_data['target'] = int(work_data['target'])
                difficulty = MAX_TARGET / work_data['target']
                print(f"[{get_current_timestamp()}] New work for block #{work_data['index']} | Difficulty: {difficulty:.4f}")

                timestamp = time.time()
                work_queue, result_queue, stats_queue = ProcQueue(), ProcQueue(), ProcQueue()
                processes_stop_event = Event()

                processes = []
                for i in range(num_threads):
                    w_data = work_data.copy()
                    w_data['timestamp'] = timestamp
                    w_data['nonce_start'], w_data['nonce_step'] = i, num_threads
                    work_queue.put(w_data)
                    p = Process(target=worker, args=(work_queue, result_queue, processes_stop_event, stats_queue))
                    processes.append(p)
                    p.start()
                
                start_time = time.time()
                found_block = None
                while found_block is None:
                    if not new_work_queue.empty(): break
                    if not result_queue.empty():
                        found_block = result_queue.get()
                        break
                    
                    while not stats_queue.empty(): total_hashes += stats_queue.get()
                    current_time = time.time()
                    if current_time - last_stats_time >= 5:
                        hashrate = total_hashes / (current_time - last_stats_time) if (current_time - last_stats_time) > 0 else 0
                        print(f"[{get_current_timestamp()}] Hashrate: {hashrate:.2f} H/s")
                        total_hashes = 0
                        last_stats_time = current_time
                    time.sleep(0.1)

                if found_block:
                    end_time = time.time()
                    found_block.hash = found_block.calculate_hash()
                    headers = {'Content-Type': 'application/json'}
                    payload = {'miner_address': miner_address, 'block_data': found_block.to_dict()}
                    submit_response = requests.post(f"{node_url}/mining/submit-block", json=payload, headers=headers, timeout=10)
                    
                    if submit_response.status_code == 201:
                        print(Fore.MAGENTA + f"[{get_current_timestamp()}] ✅ Block #{found_block.index} FOUND! (Time: {end_time - start_time:.2f}s) | Submitted.")
                    else:
                        print(Fore.RED + f"[{get_current_timestamp()}] ❌ Block #{found_block.index} REJECTED: {submit_response.status_code} {submit_response.text}")
                
                if time.time() - last_warning_time > WARNING_INTERVAL:
                    print_warning(); last_warning_time = time.time()

            except (ThreadQueue.Empty):
                continue
            except requests.exceptions.RequestException as e:
                print(f"[{get_current_timestamp()}] [ERROR] Network error: {e}. Retrying...")
                time.sleep(10)
            except Exception as e:
                print(f"[{get_current_timestamp()}] [ERROR] Unexpected error in main loop: {e}")
                time.sleep(5)
                
    except KeyboardInterrupt:
        print("\n[*] Shutting down miner...")
    finally:
        stop_mining_event.set()
        processes_stop_event.set()
        for p in processes:
            p.join(timeout=0.5); p.terminate() if p.is_alive() else None
        print("[*] Miner stopped.")

def print_warning():
    print()
    print(f"{Fore.YELLOW}+------------------------------------------------------+")
    print(f"{Fore.YELLOW}|            {Fore.RED}⚠️ IMPORTANT WARNING ⚠️{Fore.YELLOW}                   |")
    print(f"{Fore.YELLOW}+------------------------------------------------------+")
    print(f"{Fore.YELLOW}| {Style.BRIGHT + Fore.WHITE}CMXP coin is intended for learning and experimental  {Fore.YELLOW}|")
    print(f"{Fore.YELLOW}| {Style.BRIGHT + Fore.WHITE}purposes only. This coin holds NO monetary value and {Fore.YELLOW}|")
    print(f"{Fore.YELLOW}| {Style.BRIGHT + Fore.WHITE}should NEVER be traded for money or other assets.    {Fore.YELLOW}|")
    print(f"{Fore.YELLOW}+------------------------------------------------------+{Style.RESET_ALL}\n")

if __name__ == '__main__':
    from multiprocessing import freeze_support
    freeze_support()
    parser = argparse.ArgumentParser(description="CMXP Argon2id Multithreaded CPU Miner")
    parser.add_argument('--node', default='http://127.0.0.1:5000', type=str, help='URL of the CMXP node')
    parser.add_argument('--wallet', required=True, type=str, help='Wallet address')
    parser.add_argument('--threads', default=cpu_count(), type=int, help='Number of threads')
    args = parser.parse_args()
    mine(args.node, args.wallet, args.threads)
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

import requests, argparse, time, json, randomx
from multiprocessing import Process, Queue, cpu_count, Event
from core import Block
from datetime import datetime
import colorama
from colorama import Fore, Style

# --- Constants ---
MAX_TARGET = (2**256) - 1
WARNING_INTERVAL = 1800 # 30 minutes in seconds

def get_current_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def worker(work_queue, result_queue, stop_event):
    key = b'CMXP-is-a-cpu-mineable-coin!'
    rx = randomx.RandomX(key=key)
    while not stop_event.is_set():
        work_data = work_queue.get()
        if work_data is None: break

        block_to_mine = Block(
            index=work_data['index'],
            timestamp=work_data['timestamp'],
            data=work_data['data'],
            previous_hash=work_data['previous_hash'],
            target=work_data['target'],
            nonce=work_data['nonce_start']
        )
        
        while not stop_event.is_set():
            hashing_blob = (str(block_to_mine.index) + str(block_to_mine.timestamp) + str(block_to_mine.data) + str(block_to_mine.previous_hash) + str(block_to_mine.target) + str(block_to_mine.nonce)).encode()
            work_hash_bytes = rx.calculate_hash(hashing_blob)
            if int.from_bytes(work_hash_bytes, 'big') < block_to_mine.target:
                result_queue.put(block_to_mine)
                return
            block_to_mine.nonce += work_data['nonce_step']

def mine(node_url, miner_address, num_threads):
    colorama.init(autoreset=True)
    
    print(f"[*] CMXP Multithreaded Miner starting...")
    print(f"[*] Using {num_threads} threads.")
    print(f"[*] Node: {node_url}")
    print(f"[*] Miner Address: {miner_address}")
    
    last_warning_time = time.time()
    print_warning()

    while True:
        try:
            response = requests.get(f"{node_url}/mining/get-work", params={'miner_address': miner_address}, timeout=10)
            if response.status_code != 200:
                print(f"[{get_current_timestamp()}] [ERROR] Failed to get work: {response.text}")
                time.sleep(10)
                continue
            
            work_data = response.json()
            difficulty = MAX_TARGET / work_data['target']
            num_tx = len(work_data.get('data', []))
            print(f"[{get_current_timestamp()}] New work for block #{work_data['index']} | Transactions: {num_tx} | Difficulty: {difficulty:.2f}")

            timestamp = time.time()
            work_queue, result_queue = Queue(), Queue()
            stop_event = Event()

            processes = []
            for i in range(num_threads):
                w_data = work_data.copy()
                w_data['timestamp'] = timestamp
                w_data['nonce_start'], w_data['nonce_step'] = i, num_threads
                work_queue.put(w_data)
                p = Process(target=worker, args=(work_queue, result_queue, stop_event))
                processes.append(p)
                p.start()
            
            start_time = time.time()
            found_block = result_queue.get()
            stop_event.set()
            end_time = time.time()
            
            found_block.hash = found_block.calculate_hash()
            
            for p in processes:
                p.terminate()
            for p in processes:
                p.join()

            headers = {'Content-Type': 'application/json'}
            payload = {'miner_address': miner_address, 'block_data': found_block.to_dict()}
            submit_response = requests.post(f"{node_url}/mining/submit-block", json=payload, headers=headers, timeout=10)
            
            if submit_response.status_code == 201:
                print(Fore.MAGENTA + f"[{get_current_timestamp()}] ✅ Block #{found_block.index} found! (Nonce: {found_block.nonce}, Time: {end_time - start_time:.2f}s) | Submitted.")
            else:
                print(f"[{get_current_timestamp()}] ❌ Block #{found_block.index} rejected by node: {submit_response.text}")
            
            if time.time() - last_warning_time > WARNING_INTERVAL:
                print_warning()
                last_warning_time = time.time()

        except Exception as e:
            print(f"[{get_current_timestamp()}] [ERROR] An error occurred in the main loop: {e}")
            time.sleep(10)

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
    parser = argparse.ArgumentParser(description="CMXP Multithreaded CPU Miner")
    parser.add_argument('--node', default='http://127.0.0.1:5000', type=str, help='URL of the CMXP node to connect to')
    parser.add_argument('--wallet', required=True, type=str, help='Wallet address to receive mining rewards')
    parser.add_argument('--threads', default=cpu_count(), type=int, help='Number of CPU threads to use for mining')
    args = parser.parse_args()
    mine(args.node, args.wallet, args.threads)
# 파일명: miner_stratum.py (WebSocket 최종 버전)

import asyncio
import websockets
import json
import time
import argparse
from multiprocessing import Process, Queue, cpu_count, Event, freeze_support
from datetime import datetime
import colorama
from colorama import Fore, Style

from core import (
    Block, MAX_TARGET, CMXP_ARGON2_SALT, ARGON2_TIME_COST,
    ARGON2_MEMORY_COST, ARGON2_HASH_LEN, ARGON2_TYPE
)
import argon2.low_level

def get_current_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def print_warning():
    print(f"\n{Fore.YELLOW}+------------------------------------------------------+\n"
          f"|            {Fore.RED}⚠️ IMPORTANT WARNING ⚠️{Fore.YELLOW}                   |\n"
          f"+------------------------------------------------------+\n"
          f"| {Style.BRIGHT + Fore.WHITE}CMXP coin is intended for learning and experimental  {Fore.YELLOW}|\n"
          f"| {Style.BRIGHT + Fore.WHITE}purposes only. This coin holds NO monetary value and {Fore.YELLOW}|\n"
          f"| {Style.BRIGHT + Fore.WHITE}should NEVER be traded for money or other assets.    {Fore.YELLOW}|\n"
          f"+------------------------------------------------------+{Style.RESET_ALL}\n")

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
                    secret=hashing_blob, salt=CMXP_ARGON2_SALT,
                    time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST,
                    parallelism=1, hash_len=ARGON2_HASH_LEN, type=ARGON2_TYPE
                )
            except Exception:
                stop_event.set()
                break
            hash_count += 1
            if int.from_bytes(work_hash_bytes, 'big') < target:
                stats_queue.put(hash_count)
                result_queue.put({
                    "job_id": work_data["job_id"], "nonce": block_to_mine.nonce,
                    "timestamp": block_to_mine.timestamp
                })
                return
            if hash_count % 5 == 0:
                stats_queue.put(hash_count)
                hash_count = 0

async def mine(uri, miner_address, num_threads):
    colorama.init(autoreset=True)
    print_warning()
    print(f"[*] CMXP WebSocket Miner starting...")
    print(f"[*] Threads: {num_threads} | Server: {uri} | Wallet: {miner_address}")

    processes, stop_event = [], Event()
    work_queue, result_queue, stats_queue = Queue(), Queue(), Queue()
    total_hashes, last_stats_time = 0, time.time()

    while True:
        try:
            async with websockets.connect(uri) as websocket:
                print(f"[*] Successfully connected to Stratum server: {uri}")
                while True:
                    try:
                        message_str = await asyncio.wait_for(websocket.recv(), timeout=1.0)
                        message = json.loads(message_str)
                        method = message.get("method")

                        if method == "mining.authorize":
                            auth_msg = {"id": 1, "method": "mining.authorize", "params": [miner_address]}
                            await websocket.send(json.dumps(auth_msg))

                        elif method == "mining.notify":
                            job_id, prev_hash, index, data, target, clean_job = message["params"]
                            if clean_job and processes:
                                stop_event.set()
                                for p in processes: p.join()
                                processes = []

                            print(f"\n[*] New job received for block #{index} | Difficulty: {MAX_TARGET/int(target):.4f}")
                            stop_event.clear()
                            current_timestamp = time.time()
                            for i in range(num_threads):
                                work_data = {
                                    "job_id": job_id, "index": index, "data": data,
                                    "previous_hash": prev_hash, "target": int(target),
                                    "timestamp": current_timestamp, "nonce_start": i, "nonce_step": num_threads
                                }
                                work_queue.put(work_data)
                                p = Process(target=worker, args=(work_queue, result_queue, stop_event, stats_queue))
                                processes.append(p); p.start()
                        
                        elif message.get("result") is not None:
                            status = "ACCEPTED" if message["result"] else "REJECTED"
                            color = Fore.MAGENTA if message["result"] else Fore.RED
                            print(f"{color}[{get_current_timestamp()}] ✅ Block submission result: {status}")

                    except asyncio.TimeoutError:
                        pass # 메시지가 없으면 타임아웃, 다음 작업으로 넘어감

                    # 논블로킹 방식으로 결과 및 통계 처리
                    if not result_queue.empty():
                        found_result = result_queue.get()
                        nonce_hex = f"{found_result['nonce']:08x}"
                        submit_msg = {
                            "id": 2, "method": "mining.submit",
                            "params": [found_result["job_id"], nonce_hex, str(found_result["timestamp"])]
                        }
                        print(f"{Fore.MAGENTA}\n[{get_current_timestamp()}] ✨ Solution found! Submitting nonce {nonce_hex}...")
                        await websocket.send(json.dumps(submit_msg))
                    
                    while not stats_queue.empty(): total_hashes += stats_queue.get()
                    if time.time() - last_stats_time >= 5:
                        hashrate = total_hashes / (time.time() - last_stats_time)
                        print(f"[{get_current_timestamp()}] Hashrate: {hashrate:.2f} H/s", end='\r')
                        total_hashes, last_stats_time = 0, time.time()
        
        except (websockets.exceptions.ConnectionClosed, ConnectionRefusedError) as e:
            print(f"{Fore.RED}\n[ERROR] Connection lost: {e}. Reconnecting in 10 seconds...")
            if not stop_event.is_set(): stop_event.set()
            for p in processes: 
                if p.is_alive(): p.join()
            processes = []
            await asyncio.sleep(10)
        except Exception as e:
            print(f"{Fore.RED}\n[FATAL] An unexpected error occurred: {e}")
            break

if __name__ == '__main__':
    freeze_support()
    parser = argparse.ArgumentParser(description="CMXP Stratum CPU Miner (WebSocket)")
    parser.add_argument('--uri', default='wss://cmxp-stratum-node.onrender.com', type=str, help='WebSocket URI of the Stratum server (e.g., wss://host.com or ws://localhost:3333)')
    parser.add_argument('--wallet', required=True, type=str, help='Your CMXP wallet address')
    parser.add_argument('--threads', default=cpu_count(), type=int, help='Number of threads')
    args = parser.parse_args()
    
    try:
        asyncio.run(mine(args.uri, args.wallet, args.threads))
    except KeyboardInterrupt:
        print("\n[*] Miner shutting down.")
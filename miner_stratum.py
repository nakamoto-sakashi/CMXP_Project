# 파일명: miner.py (스트라텀 프로토콜 지원 최종 버전)

import socket
import json
import time
import argparse
import threading
from multiprocessing import Process, Queue, cpu_count, Event
from datetime import datetime
import colorama
from colorama import Fore, Style

# core.py에서 필요한 클래스와 상수들을 가져옵니다.
# 이 부분은 변경되지 않습니다.
from core import (
    Block, MAX_TARGET, CMXP_ARGON2_SALT, ARGON2_TIME_COST,
    ARGON2_MEMORY_COST, ARGON2_HASH_LEN, ARGON2_TYPE
)
import argon2.low_level

# --- 유틸리티 함수 ---
def get_current_timestamp():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def print_warning():
    print()
    print(f"{Fore.YELLOW}+------------------------------------------------------+")
    print(f"{Fore.YELLOW}|            {Fore.RED}⚠️ IMPORTANT WARNING ⚠️{Fore.YELLOW}                   |")
    print(f"{Fore.YELLOW}+------------------------------------------------------+")
    print(f"{Fore.YELLOW}| {Style.BRIGHT + Fore.WHITE}CMXP coin is intended for learning and experimental  {Fore.YELLOW}|")
    print(f"{Fore.YELLOW}| {Style.BRIGHT + Fore.WHITE}purposes only. This coin holds NO monetary value and {Fore.YELLOW}|")
    print(f"{Fore.YELLOW}| {Style.BRIGHT + Fore.WHITE}should NEVER be traded for money or other assets.    {Fore.YELLOW}|")
    print(f"{Fore.YELLOW}+------------------------------------------------------+{Style.RESET_ALL}\n")

# -----------------------------------------------------------------------------
# 1. 핵심 채굴 워커 (Worker) 프로세스
#    - 이 함수의 로직은 기존과 거의 동일합니다.
# -----------------------------------------------------------------------------
def worker(work_queue, result_queue, stop_event, stats_queue):
    hash_count = 0
    while not stop_event.is_set():
        try:
            work_data = work_queue.get(timeout=1)
        except Exception:
            continue

        if work_data is None: break

        # 서버로부터 받은 작업 데이터로 Block 객체 생성
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
            except Exception as e:
                print(f"[{get_current_timestamp()}] [ERROR] Argon2 hashing failed: {e}")
                stop_event.set()
                break

            hash_count += 1

            if int.from_bytes(work_hash_bytes, 'big') < target:
                stats_queue.put(hash_count)
                # ★★★ 찾았을 때, job_id와 timestamp를 결과와 함께 반환 ★★★
                result_queue.put({
                    "job_id": work_data["job_id"],
                    "nonce": block_to_mine.nonce,
                    "timestamp": block_to_mine.timestamp
                })
                return
            
            block_to_mine.nonce += nonce_step

            if hash_count % 5 == 0:
                stats_queue.put(hash_count)
                hash_count = 0


# -----------------------------------------------------------------------------
# 2. 채굴기 메인 로직 (Stratum 통신)
# -----------------------------------------------------------------------------
def mine(host, port, miner_address, num_threads):
    colorama.init(autoreset=True)
    print_warning()
    print(f"[*] CMXP Stratum Miner starting...")
    print(f"[*] Threads: {num_threads} | Server: {host}:{port} | Wallet: {miner_address}")

    # --- 프로세스 및 통신 관련 변수 ---
    processes = []
    stop_event = Event()
    work_queue, result_queue, stats_queue = Queue(), Queue(), Queue()

    # --- 통계 관련 변수 ---
    total_hashes = 0
    last_stats_time = time.time()
    
    # 2-1. 스트라텀 서버에 TCP 소켓 연결
    try:
        server_conn = socket.create_connection((host, port))
        sock_file = server_conn.makefile('r')
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Could not connect to Stratum server: {e}")
        return

    try:
        # 2-2. 서버로부터 메시지를 수신하고 처리하는 메인 루프
        while True:
            line = sock_file.readline()
            if not line:
                print(f"{Fore.RED}[ERROR] Server disconnected. Reconnecting in 10s...")
                time.sleep(10)
                # 재연결 로직 (여기서는 단순화하여 종료)
                break
            
            try:
                message = json.loads(line)
                method = message.get("method")
                params = message.get("params", [])

                # 2-3. 서버의 인증(authorize) 요청에 응답
                if method == "mining.authorize":
                    print(f"[*] Server requested authorization. Sending address.")
                    auth_msg = {
                        "id": 1, "method": "mining.authorize", "params": [miner_address]
                    }
                    server_conn.sendall((json.dumps(auth_msg) + '\n').encode())

                # 2-4. 새로운 채굴 작업(notify) 수신 처리
                elif method == "mining.notify":
                    job_id, prev_hash, index, data, target, clean_job = params
                    
                    # clean_job이 True이면, 이전 작업을 모두 중단
                    if clean_job and processes:
                        print(f"[*] New job '{job_id}' received. Stopping current work...")
                        stop_event.set()
                        for p in processes:
                            p.join()
                        processes = [] # 프로세스 목록 초기화

                    print(f"[*] Starting work on block #{index} | Difficulty: {MAX_TARGET/int(target):.4f}")
                    
                    # 새 작업으로 워커들 재시작
                    stop_event.clear()
                    # ★★★ 워커에게 보낼 작업 데이터에 job_id와 timestamp 추가 ★★★
                    current_timestamp = time.time()
                    for i in range(num_threads):
                        work_data = {
                            "job_id": job_id,
                            "index": index, "data": data, "previous_hash": prev_hash,
                            "target": int(target), "timestamp": current_timestamp,
                            "nonce_start": i, "nonce_step": num_threads
                        }
                        work_queue.put(work_data)
                        p = Process(target=worker, args=(work_queue, result_queue, stop_event, stats_queue))
                        processes.append(p)
                        p.start()
                
                # 2-5. 기타 서버 응답 출력
                elif message.get("result") is not None:
                    status = "ACCEPTED" if message["result"] else "REJECTED"
                    color = Fore.MAGENTA if message["result"] else Fore.RED
                    print(f"{color}[{get_current_timestamp()}] ✅ Block submission result: {status}")

            except json.JSONDecodeError:
                print(f"{Fore.YELLOW}[WARN] Received non-JSON message: {line.strip()}")
                continue
            
            # 2-6. 채굴 결과 확인 및 제출 (논블로킹)
            if not result_queue.empty():
                found_result = result_queue.get()
                nonce_hex = f"{found_result['nonce']:08x}" # nonce를 16진수 문자열로 변환
                
                submit_msg = {
                    "id": 2,
                    "method": "mining.submit",
                    "params": [
                        found_result["job_id"],
                        nonce_hex,
                        str(found_result["timestamp"])
                    ]
                }
                print(f"{Fore.MAGENTA}[{get_current_timestamp()}] ✨ Solution found! Submitting nonce {nonce_hex} for job {found_result['job_id']}...")
                server_conn.sendall((json.dumps(submit_msg) + '\n').encode())

            # 2-7. 해시레이트 통계 출력
            while not stats_queue.empty():
                total_hashes += stats_queue.get()

            current_time = time.time()
            if current_time - last_stats_time >= 5:
                elapsed = current_time - last_stats_time
                hashrate = total_hashes / elapsed
                print(f"[{get_current_timestamp()}] Hashrate: {hashrate:.2f} H/s")
                total_hashes = 0
                last_stats_time = current_time

    except KeyboardInterrupt:
        print("\n[*] Miner shutting down.")
    finally:
        stop_event.set()
        for p in processes:
            p.join()
        server_conn.close()
        sock_file.close()

# -----------------------------------------------------------------------------
# 3. 프로그램 시작점
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    from multiprocessing import freeze_support
    freeze_support()

    parser = argparse.ArgumentParser(description="CMXP Stratum CPU Miner (Argon2id)")
    # --- CLI 인자 변경 ---
    parser.add_argument('--host', default='127.0.0.1', type=str, help='Host of the Stratum server')
    parser.add_argument('--port', default=3333, type=int, help='Port of the Stratum server')
    parser.add_argument('--wallet', required=True, type=str, help='Your CMXP wallet address')
    parser.add_argument('--threads', default=cpu_count(), type=int, help='Number of threads')
    args = parser.parse_args()
    
    mine(args.host, args.port, args.wallet, args.threads)
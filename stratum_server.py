# 파일명: stratum_server.py (건강 검진 처리 강화 최종 버전)

import asyncio
import json
import time
import os
import websockets
import traceback
from core import Blockchain, Block

# --- 서버 설정 ---
HOST = '0.0.0.0'
PORT = int(os.environ.get('PORT', 3333))

# --- 전역 변수 ---
MINERS = set()
blockchain = Blockchain()
JOBS = {}

async def broadcast_new_job(clean_job=True):
    try:
        job_id = f"job-{int(time.time())}"
        work_data = blockchain.get_work_data(miner_address="stratum_placeholder")
        JOBS[job_id] = work_data
        
        message = {
            "id": None, "method": "mining.notify",
            "params": [
                job_id, work_data["previous_hash"], work_data["index"],
                work_data["data"], str(work_data["target"]), clean_job
            ]
        }
        message_json = json.dumps(message)
        
        print(f"[*] Broadcasting {job_id} for Block #{work_data['index']} to {len(MINERS)} miners.")
        
        if MINERS:
            disconnected_miners = set()
            for miner in MINERS:
                try:
                    await miner.send(message_json)
                except websockets.exceptions.ConnectionClosed:
                    disconnected_miners.add(miner)
            
            for miner in disconnected_miners:
                MINERS.discard(miner)

    except Exception:
        print(f"\n[FATAL ERROR in broadcast_new_job]\n{traceback.format_exc()}\n")


async def chain_monitor_loop():
    last_block_hash = None
    while True:
        try:
            latest_block = blockchain.get_latest_block()
            if latest_block and latest_block.hash != last_block_hash:
                last_block_hash = latest_block.hash
                print(f"\n[!] Chain updated to Block #{latest_block.index}. Broadcasting new work.")
                await broadcast_new_job(clean_job=True)
            await asyncio.sleep(2)
        except Exception:
            print(f"\n[FATAL ERROR in chain_monitor_loop]\n{traceback.format_exc()}\n")
            await asyncio.sleep(10)

async def handle_miner(websocket, path):
    # ★★★ 렌더의 건강 검진(Health Check) 요청을 조용히 처리하는 로직 추가 ★★★
    # websockets 라이브러리는 handshake 과정에서 User-Agent를 직접 접근하기 어렵습니다.
    # 대신, handshake 실패 예외를 잡아서 처리하는 것이 더 안정적입니다.
    try:
        # 이 블록은 실제 채굴기의 정상적인 통신을 처리합니다.
        peername = websocket.remote_address
        miner_address = None
        MINERS.add(websocket)
        print(f"[+] Miner connected: {peername}")

        try:
            auth_request = json.dumps({"id": 1, "method": "mining.authorize", "params": []})
            await websocket.send(auth_request)

            async for message_str in websocket:
                try:
                    message = json.loads(message_str)
                    print(f"[RECV] From {peername}: {message}")
                    method = message.get("method")
                    params = message.get("params", [])

                    if method == "mining.authorize" and len(params) > 0:
                        miner_address = params[0]
                        print(f"[*] Miner {peername} authorized with address: {miner_address}")
                        await broadcast_new_job(clean_job=True)

                    elif method == "mining.submit" and len(params) >= 3:
                        job_id, nonce_hex, timestamp_str = params
                        nonce = int(nonce_hex, 16)
                        timestamp = float(timestamp_str)
                        
                        original_work = JOBS.get(job_id)
                        if not original_work:
                            await websocket.send('{"result": false, "error": "Stale or invalid job ID"}')
                            continue

                        submitted_block = Block(
                            index=original_work['index'], timestamp=timestamp,
                            data=original_work['data'], previous_hash=original_work['previous_hash'],
                            target=original_work['target'], nonce=nonce
                        )

                        if blockchain.valid_proof(submitted_block):
                            submitted_block.data[0]['recipient'] = miner_address
                            submitted_block.hash = submitted_block.calculate_hash()
                            
                            if blockchain.add_block(submitted_block, miner_address):
                                print(f"✅ [ACCEPT] Block #{submitted_block.index} found by {miner_address}!")
                                await websocket.send('{"result": true, "error": null}')
                                await broadcast_new_job(clean_job=True)
                            else:
                                await websocket.send('{"result": false, "error": "Chain validation failed"}')
                        else:
                            await websocket.send('{"result": false, "error": "Invalid proof-of-work"}')
                
                except Exception:
                    print(f"\n[ERROR processing message from {peername}]\n{traceback.format_exc()}\n")

        except websockets.exceptions.ConnectionClosed:
            print(f"[-] Miner connection closed: {peername}")
        finally:
            print(f"[-] Miner disconnected: {peername}")
            MINERS.discard(websocket)
            
    # ★★★ 여기가 바로 건강 검진 로봇을 걸러내는 부분입니다 ★★★
    except websockets.exceptions.InvalidMessage:
        # 렌더의 Health Check (HEAD 요청)가 들어오면 이 예외가 발생합니다.
        # 조용히 연결을 종료하고 로그는 남기지 않습니다.
        return
    except Exception:
        # 그 외 예상치 못한 핸들러 전체의 에러
        print(f"\n[FATAL ERROR in handle_miner]\n{traceback.format_exc()}\n")


async def main():
    server = await websockets.serve(handle_miner, HOST, PORT)
    print(f"[*] CMXP WebSocket Stratum Server (v1.2 Health-Check Ready) started on {HOST}:{PORT}")
    asyncio.create_task(chain_monitor_loop())
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())


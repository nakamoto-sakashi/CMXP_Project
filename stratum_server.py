# 파일명: stratum_server.py (최종 버전)

import asyncio
import json
import time
import os
import websockets
import traceback
from core import Blockchain, Block

# --- 서버 설정 ---
HOST = '0.0.0.0'
PORT = 10000

# --- 전역 변수 ---
MINERS = set()
blockchain = Blockchain()
JOBS = {}
LATEST_JOB_MESSAGE = None

async def broadcast_new_job(clean_job=True):
    global LATEST_JOB_MESSAGE
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
        LATEST_JOB_MESSAGE = message_json
        
        print(f"[*] Broadcasting new job '{job_id}' for Block #{work_data['index']} to {len(MINERS)} miners.")
        
        if MINERS:
            await asyncio.wait([miner.send(message_json) for miner in MINERS if not miner.closed])

    except Exception:
        print(f"\n[FATAL ERROR in broadcast_new_job]\n{traceback.format_exc()}\n")


async def chain_monitor_loop():
    last_block_hash = None
    while True:
        try:
            latest_block = blockchain.get_latest_block()
            current_hash = latest_block.hash if latest_block else "0"
            
            if current_hash != last_block_hash:
                last_block_hash = current_hash
                print(f"\n[!] Chain updated to Block #{latest_block.index if latest_block else -1}. Broadcasting new work.")
                await broadcast_new_job(clean_job=True)
            
            await asyncio.sleep(5)
        except Exception:
            print(f"\n[FATAL ERROR in chain_monitor_loop]\n{traceback.format_exc()}\n")
            await asyncio.sleep(10)

# [수정됨] handle_miner 함수의 인자에서 'path'를 제거했습니다.
async def handle_miner(websocket):
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
                    
                    if LATEST_JOB_MESSAGE:
                        print(f"[*] Sending latest job to newly connected miner {peername}")
                        await websocket.send(LATEST_JOB_MESSAGE)
                    else:
                        print("[WARN] No job available yet. Miner will wait for the next block.")

                elif method == "mining.submit" and len(params) >= 3 and miner_address:
                    job_id, nonce_hex, timestamp_str = params
                    nonce, timestamp = int(nonce_hex, 16), float(timestamp_str)
                    original_work = JOBS.get(job_id)

                    if not original_work:
                        await websocket.send('{"result": false, "error": "Job not found or expired"}')
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


async def main():
    print("[INIT] Creating initial job...")
    await broadcast_new_job()

    server = await websockets.serve(handle_miner, HOST, PORT)
    print(f"[*] CMXP Stratum Worker (v2.2 Final) started on {HOST}:{PORT}")
    
    asyncio.create_task(chain_monitor_loop())
    
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
# 파일명: stratum_server.py (건강 검진 응답 기능 탑재 최종 버전)

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

# ★★★ 렌더의 건강 검진(Health Check) 요청을 처리하는 함수 ★★★
async def health_check_handler(path, request_headers):
    # 렌더가 /healthz 경로로 GET 요청을 보내면,
    if path == "/healthz":
        # "OK" 라는 의미의 HTTP 200 응답을 보내줍니다.
        return websockets.http11.Response(200, "OK", headers={"Content-Type": "text/plain"})
    # 그 외의 요청은 웹소켓 핸들러로 넘깁니다.
    return None

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
            await asyncio.wait([miner.send(message_json) for miner in MINERS if not miner.closed])

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
                    # ... (submit 처리 로직은 이전과 동일)
                    job_id, nonce_hex, timestamp_str = params
                    nonce, timestamp = int(nonce_hex, 16), float(timestamp_str)
                    original_work = JOBS.get(job_id)
                    if not original_work: continue
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

async def main():
    # ★★★ 웹소켓 서버를 시작할 때, process_request 옵션으로 건강 검진 핸들러를 등록 ★★★
    server = await websockets.serve(
        handle_miner,
        HOST,
        PORT,
        process_request=health_check_handler
    )
    print(f"[*] CMXP WebSocket Stratum Server (v1.3 Final) started on {HOST}:{PORT}")
    asyncio.create_task(chain_monitor_loop())
    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
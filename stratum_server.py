# 파일명: stratum_server.py (WebSocket 최종 버전)

import asyncio
import json
import time
import os
import websockets  # websockets 라이브러리 임포트
from core import Blockchain, Block

# --- 서버 설정 ---
HOST = '0.0.0.0'
# 렌더 환경변수가 있으면 그 포트를 쓰고, 없으면(로컬이면) 3333번을 사용
PORT = int(os.environ.get('PORT', 3333))

# --- 전역 변수 ---
MINERS = set()  # 연결된 채굴기(websocket 객체)를 저장
blockchain = Blockchain()
JOBS = {}  # 전파된 채굴 작업 정보 저장

async def broadcast_new_job(clean_job=True):
    """모든 연결된 채굴기에게 새로운 채굴 작업을 전송합니다."""
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
    
    # 모든 연결된 채굴기(websocket 객체)에 메시지 전송
    if MINERS:
        # websockets.broadcast(MINERS, message_json) # 더 효율적인 방법
        await asyncio.wait([miner.send(message_json) for miner in MINERS])

async def chain_monitor_loop():
    """블록체인 상태를 감시하여 새 블록이 생기면 작업을 전파합니다."""
    last_block_hash = None
    while True:
        latest_block = blockchain.get_latest_block()
        if latest_block and latest_block.hash != last_block_hash:
            last_block_hash = latest_block.hash
            print(f"\n[!] Chain updated to Block #{latest_block.index}. Broadcasting new work.")
            await broadcast_new_job(clean_job=True)
        await asyncio.sleep(2)

async def handle_miner(websocket, path):
    """개별 채굴기와의 통신을 처리하는 핸들러입니다."""
    peername = websocket.remote_address
    miner_address = None
    MINERS.add(websocket)
    print(f"[+] Miner connected: {peername}")

    try:
        # 접속 시 인증 요청
        auth_request = json.dumps({"id": 1, "method": "mining.authorize", "params": []})
        await websocket.send(auth_request)

        # 채굴기로부터 오는 메시지를 계속 처리
        async for message_str in websocket:
            try:
                message = json.loads(message_str)
            except json.JSONDecodeError:
                continue
            
            print(f"[RECV] From {peername}: {message}")
            method = message.get("method")
            params = message.get("params", [])

            if method == "mining.authorize" and len(params) > 0:
                miner_address = params[0]
                print(f"[*] Miner {peername} authorized with address: {miner_address}")
                # 인증 성공 후 즉시 새 작업 전송
                await broadcast_new_job(clean_job=True)

            elif method == "mining.submit" and len(params) >= 3:
                job_id, nonce_hex, timestamp_str = params
                nonce = int(nonce_hex, 16)
                timestamp = float(timestamp_str)
                
                original_work = JOBS.get(job_id)
                if not original_work:
                    await websocket.send('{"result": false, "error": "Stale or invalid job ID"}')
                    continue

                # 블록 재구성 및 검증
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

    except websockets.exceptions.ConnectionClosed:
        print(f"[-] Miner connection closed: {peername}")
    finally:
        print(f"[-] Miner disconnected: {peername}")
        MINERS.remove(websocket)

async def main():
    # TCP 서버 대신 WebSocket 서버를 시작합니다.
    server = await websockets.serve(handle_miner, HOST, PORT)
    print(f"[*] CMXP WebSocket Stratum Server started on {HOST}:{PORT}")
    asyncio.create_task(chain_monitor_loop())
    await server.wait_closed()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server is shutting down.")
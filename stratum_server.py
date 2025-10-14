# 파일명: stratum_server.py (최종 버전)

import asyncio
import json
import time
import os
from core import Blockchain, Block  # Block 클래스도 임포트합니다.

# --- 서버 설정 ---
HOST = '0.0.0.0'
# 렌더 환경변수가 있으면 그 포트를 쓰고, 없으면(로컬이면) 3333번을 사용
PORT = int(os.environ.get('PORT', 3333))

# --- 전역 변수 ---
MINERS = set()  # 연결된 채굴기(writer 객체) 집합
blockchain = Blockchain()  # 블록체인 인스턴스
JOBS = {}  # 전파된 채굴 작업(Job) 정보를 저장하는 딕셔너리 (job_id: work_data)

# -----------------------------------------------------------------------------
# 1. 채굴 작업(Job) 생성 및 전파 로직
# -----------------------------------------------------------------------------
async def broadcast_new_job(clean_job=True):
    """모든 연결된 채굴기에게 새로운 채굴 작업을 전송합니다."""
    
    job_id = f"job-{int(time.time())}"
    
    # 1-1. core.py에서 새로운 작업 데이터 가져오기
    #      코인베이스 주소는 실제 채굴기의 주소로 설정되어야 하므로 여기서는 임시 데이터만 생성
    work_data = blockchain.get_work_data(miner_address="stratum_placeholder")
    JOBS[job_id] = work_data  # 생성된 작업 정보를 저장
    
    # 1-2. 스트라텀 프로토콜 메시지 생성
    message = {
        "id": None,
        "method": "mining.notify",
        "params": [
            job_id,
            work_data["previous_hash"],
            work_data["index"],
            work_data["data"],
            str(work_data["target"]),
            clean_job
        ]
    }
    message_json = json.dumps(message) + '\n'
    encoded_message = message_json.encode('utf-8')
    
    print(f"[*] Broadcasting {job_id} for Block #{work_data['index']} to {len(MINERS)} miners.")

    # 1-3. 연결된 모든 채굴기에게 메시지 전송
    disconnected_miners = set()
    for writer in MINERS:
        try:
            if not writer.is_closing():
                writer.write(encoded_message)
                await writer.drain()
            else:
                disconnected_miners.add(writer)
        except ConnectionError:
            disconnected_miners.add(writer)
    
    for miner in disconnected_miners:
        MINERS.discard(miner)

# -----------------------------------------------------------------------------
# 2. 블록체인 상태 감시 루프
# -----------------------------------------------------------------------------
async def chain_monitor_loop():
    """블록체인의 최신 상태를 감시하여 새 블록이 생기면 작업을 전파합니다."""
    last_block_hash = None
    
    while True:
        latest_block = blockchain.get_latest_block()
        
        if latest_block and latest_block.hash != last_block_hash:
            last_block_hash = latest_block.hash
            print(f"\n[!] Chain updated to Block #{latest_block.index}. Broadcasting new work.")
            await broadcast_new_job(clean_job=True)

        await asyncio.sleep(2)

# -----------------------------------------------------------------------------
# 3. 개별 채굴기와의 통신 처리 로직 (핵심 수정 부분)
# -----------------------------------------------------------------------------
async def handle_miner(reader, writer):
    """새로운 채굴기가 접속했을 때 호출되는 함수입니다."""
    peername = writer.get_extra_info('peername')
    miner_address = None
    MINERS.add(writer)

    try:
        # 3-1. 채굴기 접속 시, 주소를 등록하도록 요청 (Authorize)
        #      실제 프로토콜은 subscribe -> authorize 순서지만 단순화
        auth_request = json.dumps({"id": 1, "method": "mining.authorize", "params": []}) + '\n'
        writer.write(auth_request.encode('utf-8'))
        await writer.drain()

        while True:
            data = await reader.readline()
            if not data: break

            message_str = data.decode('utf-8').strip()
            
            try:
                message = json.loads(message_str)
            except json.JSONDecodeError:
                print(f"[WARN] Malformed JSON from {peername}: {message_str}")
                continue
                
            print(f"[RECV] From {peername}: {message}")

            # 3-2. 메시지 종류에 따라 처리
            method = message.get("method")
            params = message.get("params", [])

            if method == "mining.authorize" and len(params) > 0:
                miner_address = params[0]
                # TODO: 주소 유효성 검사 추가
                print(f"[*] Miner {peername} authorized with address: {miner_address}")
                # 인증 성공 후 첫 작업 전송
                await broadcast_new_job(clean_job=True)

            elif method == "mining.submit" and len(params) >= 3:
                if not miner_address:
                    print(f"[WARN] Unauthorized submit from {peername}")
                    continue
                
                job_id, nonce, timestamp = params[0], int(params[1], 16), float(params[2])
                
                # 3-3. 제출된 작업 검증
                original_work = JOBS.get(job_id)
                if not original_work:
                    print(f"[REJECT] Stale or invalid job ID '{job_id}' from {miner_address}")
                    continue

                # 3-4. 블록 재구성 및 PoW 검증
                submitted_block = Block(
                    index=original_work['index'],
                    timestamp=timestamp,
                    data=original_work['data'],
                    previous_hash=original_work['previous_hash'],
                    target=original_work['target'],
                    nonce=nonce
                )

                if blockchain.valid_proof(submitted_block):
                    # 3-5. PoW 검증 성공 시, 블록체인에 추가
                    # 코인베이스 트랜잭션의 수신자를 실제 채굴자 주소로 변경
                    submitted_block.data[0]['recipient'] = miner_address
                    submitted_block.hash = submitted_block.calculate_hash() # 해시 재계산

                    if blockchain.add_block(submitted_block, miner_address):
                        print(f"✅ [ACCEPT] Block #{submitted_block.index} found by {miner_address}!")
                        # 성공 응답 전송
                        writer.write(b'{"result": true, "error": null}\n')
                        await writer.drain()
                        # ★★★ 블록이 추가되었으므로 즉시 모든 채굴기에게 새 작업 전파 ★★★
                        await broadcast_new_job(clean_job=True)
                    else:
                        print(f"❌ [REJECT] Block #{submitted_block.index} from {miner_address} failed chain validation.")
                        writer.write(b'{"result": false, "error": "Chain validation failed"}\n')
                        await writer.drain()
                else:
                    print(f"❌ [REJECT] Invalid PoW for block #{submitted_block.index} from {miner_address}")
                    writer.write(b'{"result": false, "error": "Invalid proof-of-work"}\n')
                    await writer.drain()

    except (ConnectionResetError, BrokenPipeError):
        print(f"[-] Miner connection lost: {peername}")
    except Exception as e:
        print(f"[!] Unhandled error with miner {peername}: {e}")
    finally:
        print(f"[-] Miner disconnected: {peername}")
        MINERS.discard(writer)
        if not writer.is_closing():
            writer.close()

# -----------------------------------------------------------------------------
# 4. 메인 실행 함수
# -----------------------------------------------------------------------------
async def main():
    server = await asyncio.start_server(handle_miner, HOST, PORT)
    print(f"[*] CMXP Stratum Server (v1.0 Final) started on {HOST}:{PORT}")
    
    asyncio.create_task(chain_monitor_loop())
    
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Server is shutting down.")
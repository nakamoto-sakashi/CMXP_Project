# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
# (Argon2id Version)
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

from flask import Flask, jsonify, request
# core.py의 경로는 실제 환경에 맞게 조정해야 할 수 있습니다.
from core import Blockchain, Transaction, Block 
import time, argparse, ecdsa

app = Flask(__name__)
# Blockchain 인스턴스 생성 (수정된 core.py 사용)
blockchain = Blockchain()

def is_valid_address(address_hex):
    if not isinstance(address_hex, str) or len(address_hex) != 66:
        return False
    try:
        # 주소 형식 및 타원 곡선 유효성 검사
        ecdsa.VerifyingKey.from_string(bytes.fromhex(address_hex), curve=ecdsa.SECP256k1)
        return True
    except (ValueError, ecdsa.errors.MalformedPointError, TypeError):
        return False

# 노드 시작 시 경고창 출력
print("\n+------------------------------------------------------+")
print("|            ⚠️ IMPORTANT WARNING ⚠️                   |")
print("+------------------------------------------------------+")
print("| CMXP Node (Argon2id) Starting...                     |")
print("| This coin holds NO monetary value. DO NOT trade.     |")
print("+------------------------------------------------------+\n")


# --- API 엔드포인트 ---

# 잔액 조회 엔드포인트
@app.route('/balance/<address>', methods=['GET'])
def get_balance(address):
    # '0' 주소는 코인베이스이므로 유효성 검사 예외 허용
    if not is_valid_address(address) and address != '0':
        return jsonify({'message': 'Invalid wallet address format'}), 400
        
    try:
        # core.py에 구현된 get_balance 호출 (include_pending=True 기본값 사용)
        balance = blockchain.get_balance(address)
        return jsonify({'address': address, 'balance': balance}), 200
    except Exception as e:
        return jsonify({'message': f"Error calculating balance: {e}"}), 500

# --- 채굴 관련 엔드포인트 ---
@app.route('/mining/get-work', methods=['GET'])
def get_work():
    miner_address = request.args.get('miner_address')
    if not miner_address: return jsonify({'message': "Missing miner_address parameter"}), 400
    
    if not is_valid_address(miner_address):
         return jsonify({'message': 'Invalid wallet address format'}), 400

    work_data = blockchain.get_work_data(miner_address)
    # JSON 호환성을 위해 target을 문자열로 변환
    work_data['target'] = str(work_data['target'])
    return jsonify(work_data), 200

@app.route('/mining/submit-block', methods=['POST'])
def submit_block():
    values = request.get_json()
    if not values: return jsonify({'message': "Missing block data"}), 400
    
    block_data, submitter_address = values.get('block_data'), values.get('miner_address')
    if not all([block_data, submitter_address]): return jsonify({'message': "Missing values"}), 400
    
    try:
        block = blockchain.dict_to_block(block_data)
    except Exception as e:
        return jsonify({'message': f"Invalid block data format: {e}"}), 400
    
    # add_block 내부에서 PoW 및 트랜잭션 검증 수행
    if blockchain.add_block(block, submitter_address):
        print(f"\n[ACCEPTED] Block #{block.index} added to the chain.")
        return jsonify({'message': f'Block #{block.index} accepted'}), 201
    else: 
        print(f"[REJECTED] Block #{block.index} rejected.")
        # 거부 사유 명확화 (잔액 부족 포함)
        return jsonify({'message': 'Block was rejected (Invalid PoW, chain rules, or insufficient funds for transactions)'}), 400

# --- 트랜잭션 엔드포인트 ---
@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature', 'timestamp']
    if not values or not all(k in values for k in required):
        return jsonify({'message': 'Missing values'}), 400
    
    # 주소 유효성 검사
    if not is_valid_address(values['sender']) or not is_valid_address(values['recipient']):
        return jsonify({'message': 'Invalid wallet address format'}), 400
    
    # 자기 자신에게 송금 금지
    if values['sender'] == values['recipient']:
        return jsonify({'message': 'Sender and recipient cannot be the same'}), 400

    try:
        # 데이터 형식 검증
        signature_bytes = bytes.fromhex(values['signature'])
        amount = float(values['amount'])
        if amount <= 0:
            raise ValueError("Amount must be positive")
    except (ValueError, TypeError) as e:
        return jsonify({'message': f'Invalid data format: {e}'}), 400

    tx = Transaction(
        values['sender'], values['recipient'], amount, 
        signature=signature_bytes, timestamp=values['timestamp']
    )
    
    # add_transaction 내부에서 서명 및 잔액 검증 수행
    if blockchain.add_transaction(tx):
        return jsonify({'message': 'Transaction added to pending pool'}), 201
    else:
        # 잔액 부족 또는 서명 오류
        return jsonify({'message': 'Invalid transaction (check signature or balance)'}), 400
        
# --- 체인 및 노드 관리 엔드포인트 ---
@app.route('/chain', methods=['GET'])
def full_chain():
    # (체인 조회 로직 생략)
    pass

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    # (노드 등록 로직 생략)
    pass

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    # (합의 로직 생략)
    pass

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run a CMXP blockchain node.')
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on for node')
    parser.add_argument('--bootstrap', type=str, help='bootstrap node address to connect to')
    args = parser.parse_args()
    
    # (Bootstrap 로직 생략)

    print(f"\nStarting CMXP node on port {args.port}...")
    # 운영 환경에서는 Gunicorn 사용 권장
    app.run(host='0.0.0.0', port=args.port, threaded=True)
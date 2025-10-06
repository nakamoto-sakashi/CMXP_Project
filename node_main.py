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
from core import Blockchain, Transaction, Block
import time, argparse, ecdsa

app = Flask(__name__)
# Blockchain 인스턴스 생성 (Argon2가 적용된 core.py 사용)
blockchain = Blockchain()

# job_store는 XMRig 통합에만 사용되었으므로 제거됨.

def is_valid_address(address_hex):
    if not isinstance(address_hex, str) or len(address_hex) != 66:
        return False
    try:
        ecdsa.VerifyingKey.from_string(bytes.fromhex(address_hex), curve=ecdsa.SECP256k1)
        return True
    except (ValueError, ecdsa.errors.MalformedPointError):
        return False

# 노드 시작 시 경고창 출력
print("\n+------------------------------------------------------+")
print("|            ⚠️ IMPORTANT WARNING ⚠️                   |")
print("+------------------------------------------------------+")
print("| CMXP Node (Argon2id) Starting...                     |")
print("| This coin holds NO monetary value and is intended    |")
print("| for educational purposes only. DO NOT trade.         |")
print("+------------------------------------------------------+\n")


# --- XMRig 호환을 위한 JSON-RPC 핸들러(/json_rpc)는 제거되었습니다. ---


# --- 표준 API 엔드포인트 ---
@app.route('/mining/get-work', methods=['GET'])
def get_work():
    miner_address = request.args.get('miner_address')
    if not miner_address: return jsonify({'message': "Missing miner_address parameter"}), 400
    
    if not is_valid_address(miner_address):
         return jsonify({'message': 'Invalid wallet address format'}), 400

    work_data = blockchain.get_work_data(miner_address)
    # JSON은 큰 정수를 지원하지 않을 수 있으므로 target을 문자열로 변환하여 반환
    # (miner.py와 core.py는 이를 다시 int로 변환합니다)
    work_data['target'] = str(work_data['target'])
    return jsonify(work_data), 200

@app.route('/mining/submit-block', methods=['POST'])
def submit_block():
    values = request.get_json()
    if not values: return jsonify({'message': "Missing block data"}), 400
    
    block_data, submitter_address = values.get('block_data'), values.get('miner_address')
    if not all([block_data, submitter_address]): return jsonify({'message': "Missing values"}), 400
    
    try:
        # dict_to_block은 내부적으로 문자열 Target을 int로 변환합니다.
        block = blockchain.dict_to_block(block_data)
    except Exception as e:
        return jsonify({'message': f"Invalid block data format: {e}"}), 400
    
    if blockchain.add_block(block, submitter_address):
        print(f"\n[ACCEPTED] Block #{block.index} (mined by: ...{submitter_address[-10:]}) added to the chain.")
        return jsonify({'message': f'Block #{block.index} accepted'}), 201
    else: 
        print(f"[REJECTED] Block #{block.index} rejected.")
        return jsonify({'message': 'Block was rejected (Invalid PoW or chain rules)'}), 400

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    # (트랜잭션 처리 로직은 변경 없음)
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature', 'timestamp']
    if not values or not all(k in values for k in required):
        return jsonify({'message': 'Missing values'}), 400
    
    if not is_valid_address(values['sender']) or not is_valid_address(values['recipient']):
        return jsonify({'message': 'Invalid wallet address format'}), 400
    
    try:
        # 서명(signature)은 hex 문자열로 전달되므로 bytes로 변환
        signature_bytes = bytes.fromhex(values['signature'])
        amount = float(values['amount'])
    except (ValueError, TypeError):
        return jsonify({'message': 'Invalid signature or amount format'}), 400

    tx = Transaction(
        values['sender'], values['recipient'], amount, 
        signature=signature_bytes, timestamp=values['timestamp']
    )
    
    if blockchain.add_transaction(tx):
        return jsonify({'message': 'Transaction added to pending pool'}), 201
    else:
        return jsonify({'message': 'Invalid transaction (check signature)'}), 400
        
@app.route('/chain', methods=['GET'])
def full_chain():
    response = {'chain': [block.to_dict() for block in blockchain.chain], 'length': len(blockchain.chain)}
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    # (노드 등록 로직은 변경 없음)
    values = request.get_json()
    nodes = values.get('nodes') if values else None
    if nodes is None: return "Error: Please supply a valid list of nodes", 400
    for node in nodes:
        try:
            blockchain.register_node(node)
        except ValueError:
             print(f"Warning: Invalid node URL ignored: {node}")
    return jsonify({'message': 'New nodes have been added', 'total_nodes': list(blockchain.nodes)}), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    # (합의 로직은 변경 없음)
    replaced = blockchain.resolve_conflicts()
    chain_as_dicts = [block.to_dict() for block in blockchain.chain]
    if replaced:
        response = {'message': 'Our chain was replaced', 'chain': chain_as_dicts}
    else:
        response = {'message': 'Our chain is authoritative', 'chain': chain_as_dicts}
    return jsonify(response), 200

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run a CMXP blockchain node.')
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on for node')
    parser.add_argument('--bootstrap', type=str, help='bootstrap node address to connect to')
    args = parser.parse_args()
    if args.bootstrap:
        print(f"Attempting to connect to bootstrap node: {args.bootstrap}...")
        try:
            blockchain.register_node(args.bootstrap)
            time.sleep(1)
            if blockchain.resolve_conflicts(): print("Synchronization complete: The chain was replaced.")
            else: print("Synchronization complete: The current chain is authoritative.")
        except ValueError:
             print(f"Error: Invalid bootstrap node address format: {args.bootstrap}")

    print(f"\nStarting CMXP node on port {args.port}...")
    # 운영 환경에서는 Gunicorn 사용 권장, 개발 환경에서는 threaded=True 사용 가능
    app.run(host='0.0.0.0', port=args.port, threaded=True)
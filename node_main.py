# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
# (Argon2id Version)
# Modified by Eric Trump of the CMXP community on October 14, 2025
#
# All rights reserved
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
import time, argparse, ecdsa, requests, threading # threading 임포트 추가

app = Flask(__name__)
blockchain = Blockchain()

# 동기화할 다른 노드(피어)들의 주소 목록
PEER_NODES = [
    'https://cmxp-node.onrender.com', # 개발자 공개 노드
]


def is_valid_address(address_hex):
    if not isinstance(address_hex, str) or len(address_hex) != 66:
        return False
    try:
        ecdsa.VerifyingKey.from_string(bytes.fromhex(address_hex), curve=ecdsa.SECP256k1)
        return True
    except (ValueError, ecdsa.errors.MalformedPointError, TypeError):
        return False

# 노드 시작 시 경고창 상세화
print("\n+--------------------------------------------------------------------------------+")
print("|                           /!\\ IMPORTANT WARNING /!\\                            |")
print("+--------------------------------------------------------------------------------+")
print("| CMXP coin is intended for learning and experimental purposes only.             |")
print("| This coin holds NO monetary value and should NEVER be traded for money         |")
print("| or other assets. Use at your own risk. Please mine responsibly.                |")
print("+--------------------------------------------------------------------------------+\n")


# --- API 엔드포인트 ---

@app.route('/balance/<address>', methods=['GET'])
def get_balance(address):
    if not is_valid_address(address) and address != '0':
        return jsonify({'message': 'Invalid wallet address format'}), 400
    try:
        balance = blockchain.get_balance(address)
        return jsonify({'address': address, 'balance': balance}), 200
    except Exception as e:
        return jsonify({'message': f"Error calculating balance: {e}"}), 500

@app.route('/mining/get-work', methods=['GET'])
def get_work():
    miner_address = request.args.get('miner_address')
    if not miner_address: return jsonify({'message': "Missing miner_address parameter"}), 400
    if not is_valid_address(miner_address):
         return jsonify({'message': 'Invalid wallet address format'}), 400
    work_data = blockchain.get_work_data(miner_address)
    work_data['target'] = str(work_data['target'])
    return jsonify(work_data), 200

@app.route('/mining/latest-block', methods=['GET'])
def get_latest_block_info():
    latest_block = blockchain.get_latest_block()
    if latest_block:
        return jsonify({'index': latest_block.index, 'hash': latest_block.hash}), 200
    return jsonify({'message': 'No blocks in chain yet'}), 404

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
    if blockchain.add_block(block, submitter_address):
        print(f"\n[ACCEPTED] Block #{block.index} added to the chain.")
        return jsonify({'message': f'Block #{block.index} accepted'}), 201
    else:
        print(f"[REJECTED] Block #{block.index} rejected.")
        return jsonify({'message': 'Block was rejected (Invalid PoW, chain rules, or insufficient funds for transactions)'}), 400

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature', 'timestamp']
    if not values or not all(k in values for k in required):
        return jsonify({'message': 'Missing values'}), 400
    if not is_valid_address(values['sender']) or not is_valid_address(values['recipient']):
        return jsonify({'message': 'Invalid wallet address format'}), 400
    if values['sender'] == values['recipient']:
        return jsonify({'message': 'Sender and recipient cannot be the same'}), 400
    try:
        signature_bytes = bytes.fromhex(values['signature'])
        amount = float(values['amount'])
        if amount <= 0: raise ValueError("Amount must be positive")
    except (ValueError, TypeError) as e:
        return jsonify({'message': f'Invalid data format: {e}'}), 400
    tx = Transaction(
        values['sender'], values['recipient'], amount,
        signature=signature_bytes, timestamp=values['timestamp']
    )
    if blockchain.add_transaction(tx):
        return jsonify({'message': 'Transaction added to pending pool'}), 201
    else:
        return jsonify({'message': 'Invalid transaction (check signature or balance)'}), 400

@app.route('/chain', methods=['GET'])
def full_chain():
    response = {'chain': [block.to_dict() for block in blockchain.chain], 'length': len(blockchain.chain)}
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None or not isinstance(nodes, list):
        return jsonify({"message": "Error: Please supply a valid list of nodes"}), 400
    for node in nodes:
        blockchain.register_node(node)
    response = {'message': 'New nodes have been added', 'total_nodes': list(blockchain.nodes)}
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {'message': 'Our chain was replaced', 'new_chain': [block.to_dict() for block in blockchain.chain]}
    else:
        response = {'message': 'Our chain is authoritative', 'chain': [block.to_dict() for block in blockchain.chain]}
    return jsonify(response), 200

# 주기적으로 동기화를 실행할 함수 정의
def periodic_sync():
    """백그라운드에서 주기적으로 다른 노드와 동기화를 시도하는 함수"""
    while True:
        print("\n[PERIODIC-SYNC] Running conflict resolution...")
        replaced = blockchain.resolve_conflicts()
        if replaced:
            print("[PERIODIC-SYNC] Chain was updated by a longer chain from a peer.")
        else:
            print("[PERIODIC-SYNC] Our chain is up to date.")
        time.sleep(60) # 60초마다 반복

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run a CMXP blockchain node.')
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on for node')
    args = parser.parse_args()

    # 다른 노드들을 blockchain 객체에 먼저 등록
    for node in PEER_NODES:
        blockchain.register_node(node)

    # 프로그램 시작 시 최초 1회 동기화 실행
    print("\n[SYNC] Starting initial conflict resolution...")
    replaced = blockchain.resolve_conflicts()
    if replaced:
        print("[SYNC] Chain was replaced by a longer authoritative chain.")
    else:
        print("[SYNC] Our chain is authoritative or no longer chain was found.")

    # 백그라운드에서 주기적 동기화 스레드 시작
    # daemon=True로 설정하여 메인 프로그램 종료 시 스레드도 함께 종료되도록 함
    sync_thread = threading.Thread(target=periodic_sync, daemon=True)
    sync_thread.start()
    print("[SYSTEM] Periodic synchronization thread started (60s interval).")

    print(f"\nCMXP Node (Argon2id) starting on port {args.port}...")
    # threaded=True 옵션은 개발 서버가 여러 요청을 동시에 처리할 수 있게 도와줌
    app.run(host='0.0.0.0', port=args.port, threaded=True)
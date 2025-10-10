# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
# (Argon2id Version)
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
# core.py의 경로는 실제 환경에 맞게 조정해야 할 수 있습니다.
from core import Blockchain, Transaction, Block 
import time, argparse, ecdsa, requests # --- [P2P 추가] --- requests 임포트

app = Flask(__name__)
# Blockchain 인스턴스 생성 (수정된 core.py 사용)
blockchain = Blockchain()

# --- [P2P 추가] ---
# 동기화할 다른 노드(피어)들의 주소 목록
# 실제 운영 시에는 설정 파일이나 DB에서 관리하는 것이 좋습니다.
PEER_NODES = [
    'https://cmxp-node.onrender.com', # 기존 서버 (언젠가 사라질 수 있음)
    'http://[다른유저A_공인_IP]:5000', # 다른 유저의 노드
    'http://[다른유저B_공인_IP]:5000'  # 또 다른 유저의 노드
] # 기존 서버를 기본 피어로 설정


def is_valid_address(address_hex):
    if not isinstance(address_hex, str) or len(address_hex) != 66:
        return False
    try:
        # 주소 형식 및 타원 곡선 유효성 검사
        ecdsa.VerifyingKey.from_string(bytes.fromhex(address_hex), curve=ecdsa.SECP256k1)
        return True
    except (ValueError, ecdsa.errors.MalformedPointError, TypeError):
        return False

# --- [수정됨] --- 노드 시작 시 경고창 상세화 ---
print("\n+--------------------------------------------------------------------------------+")
print("|                            /!\\ IMPORTANT WARNING /!\\                             |")
print("+--------------------------------------------------------------------------------+")
print("| CMXP coin is intended for learning and experimental purposes only.             |")
print("| This coin holds NO monetary value and should NEVER be traded for money         |")
print("| or other assets. Use at your own risk. Please mine responsibly.                |")
print("+--------------------------------------------------------------------------------+\n")


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

# Stale block 감지를 위한 새로운 엔드포인트
@app.route('/mining/latest-block', methods=['GET'])
def get_latest_block_info():
    """
    채굴기가 현재 작업이 유효한지 빠르게 확인할 수 있도록
    마지막 블록의 인덱스와 해시만 반환합니다.
    """
    latest_block = blockchain.get_latest_block()
    if latest_block:
        return jsonify({
            'index': latest_block.index,
            'hash': latest_block.hash
        }), 200
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
        
# --- [P2P 추가] --- 다른 노드와의 동기화를 위한 API 엔드포인트 ---

@app.route('/p2p/get-block-count', methods=['GET'])
def get_block_count():
    """ 현재 노드가 가진 블록의 총 개수를 반환합니다. """
    latest_block = blockchain.get_latest_block()
    count = latest_block.index + 1 if latest_block else 0
    return jsonify({'count': count}), 200

@app.route('/p2p/get-block/<int:index>', methods=['GET'])
def get_block_by_index(index):
    """ 특정 인덱스의 블록 데이터를 반환합니다. """
    block = blockchain.get_block_by_index(index)
    if block:
        return jsonify(block.to_dict()), 200
    else:
        return jsonify({'message': 'Block not found'}), 404

# -----------------------------------------------------------------

# --- 체인 및 노드 관리 엔드포인트 (생략 없이 모두 구현) ---
@app.route('/chain', methods=['GET'])
def full_chain():
    """전체 블록체인 데이터를 반환합니다."""
    response = {
        'chain': [block.to_dict() for block in blockchain.chain],
        'length': len(blockchain.chain),
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    """네트워크에 새로운 노드를 등록합니다."""
    values = request.get_json()
    nodes = values.get('nodes')
    if nodes is None or not isinstance(nodes, list):
        return jsonify({"message": "Error: Please supply a valid list of nodes"}), 400

    for node in nodes:
        blockchain.register_node(node)

    response = {
        'message': 'New nodes have been added',
        'total_nodes': list(blockchain.nodes),
    }
    return jsonify(response), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    """
    네트워크의 다른 노드들과 체인을 비교하여
    가장 긴 유효 체인으로 교체하는 합의 알고리즘을 실행합니다.
    """
    replaced = blockchain.resolve_conflicts()

    if replaced:
        response = {
            'message': 'Our chain was replaced',
            'new_chain': [block.to_dict() for block in blockchain.chain]
        }
    else:
        response = {
            'message': 'Our chain is authoritative',
            'chain': [block.to_dict() for block in blockchain.chain]
        }

    return jsonify(response), 200

# --- [P2P 추가] --- 동기화 로직 함수 ---
def sync_with_peers():
    print("\n[SYNC] Starting synchronization with peer nodes...")
    
    my_latest_block = blockchain.get_latest_block()
    my_block_count = my_latest_block.index + 1 if my_latest_block else 0
    
    best_peer = None
    max_peer_block_count = 0

    # 1. 가장 긴 체인을 가진 피어 찾기
    for peer_url in PEER_NODES:
        try:
            response = requests.get(f"{peer_url}/p2p/get-block-count", timeout=5)
            if response.status_code == 200:
                peer_block_count = response.json().get('count', 0)
                print(f"[SYNC] Peer {peer_url} has {peer_block_count} blocks.")
                if peer_block_count > max_peer_block_count:
                    max_peer_block_count = peer_block_count
                    best_peer = peer_url
            else:
                 print(f"[SYNC-WARN] Could not get block count from {peer_url}")
        except requests.exceptions.RequestException:
            print(f"[SYNC-ERROR] Failed to connect to peer {peer_url}")
    
    # 2. 내 체인이 더 짧으면, 가장 긴 피어로부터 블록 다운로드
    if best_peer and max_peer_block_count > my_block_count:
        print(f"[SYNC] Local chain is behind ({my_block_count} blocks). Syncing with {best_peer} ({max_peer_block_count} blocks)...")
        
        for i in range(my_block_count, max_peer_block_count):
            try:
                print(f"[SYNC] Requesting block #{i}...")
                block_response = requests.get(f"{best_peer}/p2p/get-block/{i}", timeout=10)
                if block_response.status_code == 200:
                    block_data = block_response.json()
                    block = blockchain.dict_to_block(block_data)
                    
                    # add_block을 통해 블록을 추가하면, 기존의 유효성 검증 로직을 그대로 사용 가능
                    # submitter_address는 이 컨텍스트에서 불필요하므로, 임시 값을 넣어줌 (추후 개선 필요)
                    # 실제로는 블록 데이터 안의 코인베이스 트랜잭션 수신자를 사용해야 함
                    coinbase_recipient = block.data[0].get('recipient') if isinstance(block.data, list) and block.data else None
                    if coinbase_recipient:
                        blockchain.add_block(block, coinbase_recipient)
                    else:
                        print(f"[SYNC-ERROR] Could not find recipient in coinbase for block #{i}")
                        break # 문제가 생기면 동기화 중단
                else:
                    print(f"[SYNC-ERROR] Failed to get block #{i} from peer.")
                    break
            except requests.exceptions.RequestException as e:
                print(f"[SYNC-ERROR] Network error during sync: {e}")
                break
        
        print("[SYNC] Synchronization finished.")
    else:
        print("[SYNC] Local chain is up to date.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run a CMXP blockchain node.')
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on for node')
    args = parser.parse_args()
    
    # --- [P2P 추가] --- Flask 서버 시작 전에 동기화 실행
    sync_with_peers()
    
    print(f"\nCMXP Node (Argon2id) starting on port {args.port}...") # 시작 메시지 수정
    # 운영 환경에서는 Gunicorn 사용 권장
    app.run(host='0.0.0.0', port=args.port, threaded=True)
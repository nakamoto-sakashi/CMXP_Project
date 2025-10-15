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
import time, argparse, ecdsa, requests, threading

app = Flask(__name__)
blockchain = Blockchain()

PEER_NODES = [
    'https://cmxp-node.onrender.com',
]

MY_NODE_ADDRESS = ""

def is_valid_address(address_hex):
    if not isinstance(address_hex, str) or len(address_hex) != 66:
        return False
    try:
        ecdsa.VerifyingKey.from_string(bytes.fromhex(address_hex), curve=ecdsa.SECP256k1)
        return True
    except (ValueError, ecdsa.errors.MalformedPointError, TypeError):
        return False

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
    
    # --- [수정됨] 작업 데이터에 '작업 ID' (최신 블록 해시)를 포함시켜 전달 ---
    latest_block = blockchain.get_latest_block()
    work_data['work_id'] = latest_block.hash if latest_block else "0"
    
    return jsonify(work_data), 200

# --- [신규] 채굴기가 현재 작업이 유효한지 빠르게 확인하는 초경량 API ---
@app.route('/mining/work-status', methods=['GET'])
def get_work_status():
    latest_block = blockchain.get_latest_block()
    current_hash = latest_block.hash if latest_block else "0"
    return jsonify({'latest_block_hash': current_hash}), 200

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

    success, message = blockchain.add_block(block, submitter_address)
    
    if success:
        print(f"\n[ACCEPTED] Block #{block.index} added to the chain via submission.")
        broadcast_block(block)
        return jsonify({'message': f'Block #{block.index} accepted'}), 201
    else:
        print(f"[REJECTED] Block #{block.index} rejected. Reason: {message}")
        return jsonify({'message': f'Block was rejected: {message}'}), 400

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

@app.route('/nodes/add_peer', methods=['POST'])
def add_peer():
    values = request.get_json()
    node_url = values.get('node')
    if node_url is None:
        return "Error: Please supply a valid node address", 400
    blockchain.register_node(node_url, MY_NODE_ADDRESS)
    response = {'message': 'New peer has been added', 'total_peers': list(blockchain.nodes.keys())}
    return jsonify(response), 201

@app.route('/nodes/get_peers', methods=['GET'])
def get_peers():
    peers = list(blockchain.nodes.keys())
    return jsonify({'peers': peers}), 200

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {'message': 'Our chain was replaced', 'new_chain': [block.to_dict() for block in blockchain.chain]}
    else:
        response = {'message': 'Our chain is authoritative', 'chain': [block.to_dict() for block in blockchain.chain]}
    return jsonify(response), 200
    
# node_main.py 파일의 announce_block 함수를 아래 코드로 교체해주세요.

@app.route('/blocks/announce', methods=['POST'])
def announce_block():
    values = request.get_json()
    if not values:
        return "Missing block data", 400
    
    source_node = request.remote_addr
    
    try:
        block = blockchain.dict_to_block(values)
    except Exception as e:
        return f"Invalid block data format: {e}", 400

    # --- [수정됨] add_block의 다양한 반환 값을 처리하도록 로직 개선 ---
    result, message = blockchain.add_block(block)
    
    # Case 1: 블록이 성공적으로 추가됨
    if result is True:
        print(f"\n[ACCEPTED] Block #{block.index} added to the chain via announcement.")
        # 내가 받은 블록이므로, 나에게 보내준 노드를 제외하고 다시 전파
        broadcast_block(block, source_node=source_node)
        return "Block added", 201
        
    # Case 2: 내가 놓친 블록이 있음을 감지하고 즉시 동기화 실행
    elif result == 'sync_needed':
        print(f"\n[SYNC-TRIGGER] Received block #{block.index} from a longer chain. Triggering immediate sync...")
        # 백그라운드에서 즉시 동기화 실행
        threading.Thread(target=blockchain.resolve_conflicts).start()
        return "Sync triggered", 202 # 202 Accepted: 요청은 받았지만 처리는 나중에 함
        
    # Case 3: 이미 있는 블록이거나, 기타 거절 사유
    else:
        # 이미 받은 블록이라는 메시지는 정상적인 상황이므로 200 OK로 응답
        if message == "Received block is old or a duplicate":
            return message, 200
        # 그 외의 경우는 거절
        return f"Block rejected: {message}", 400

def broadcast_block(block, source_node=None):
    for peer_netloc in list(blockchain.nodes.keys()):
        if source_node and peer_netloc.startswith(source_node):
            continue
        try:
            url = f"http://{peer_netloc}/blocks/announce"
            threading.Thread(target=requests.post, args=(url,), kwargs={'json': block.to_dict(), 'timeout': 5}).start()
        except Exception as e:
            print(f"[BROADCAST] Failed to broadcast block to {peer_netloc}: {e}")

def periodic_chain_sync():
    while True:
        time.sleep(60)
        print("\n[CHAIN-SYNC] Running conflict resolution...")
        replaced = blockchain.resolve_conflicts()
        if replaced:
            print("[CHAIN-SYNC] Chain was updated by a longer chain from a peer.")
        else:
            print("[CHAIN-SYNC] Our chain is up to date.")

def periodic_peer_discovery():
    while True:
        time.sleep(180)
        print(f"\n[PEER-DISCOVERY] Searching for new peers from {len(blockchain.nodes)} known peers...")
        all_peers = list(blockchain.nodes.keys())
        for peer_netloc in all_peers:
            try:
                url = f"http://{peer_netloc}/nodes/get_peers"
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    blockchain.update_node_status(peer_netloc, successful=True)
                    newly_discovered_peers = response.json().get('peers', [])
                    for new_peer in newly_discovered_peers:
                        blockchain.register_node(new_peer, MY_NODE_ADDRESS)
                else:
                    blockchain.update_node_status(peer_netloc, successful=False)
            except requests.exceptions.RequestException:
                blockchain.update_node_status(peer_netloc, successful=False)
                print(f"[PEER-DISCOVERY] Could not connect to peer: {peer_netloc}")
        print(f"[PEER-DISCOVERY] Peer list updated. Total known peers: {len(blockchain.nodes)}")

def periodic_prune_nodes():
    while True:
        time.sleep(600)
        print("\n[NODE-PRUNING] Checking for dead nodes...")
        pruned_count = blockchain.prune_nodes()
        if pruned_count > 0:
            print(f"[NODE-PRUNING] {pruned_count} dead nodes removed from the peer list.")
        else:
            print("[NODE-PRUNING] No dead nodes found.")

def announce_self_to_peers():
    for peer_url in PEER_NODES:
        try:
            url = f"{peer_url}/nodes/add_peer"
            requests.post(url, json={'node': MY_NODE_ADDRESS}, timeout=5)
            print(f"[ANNOUNCE] Successfully announced self to {peer_url}")
        except requests.exceptions.RequestException:
            print(f"[ANNOUNCE] Failed to announce self to {peer_url}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run a CMXP blockchain node.')
    parser.add_argument('--host', default='0.0.0.0', type=str, help='Host to bind to.')
    parser.add_argument('-p', '--port', default=5000, type=int, help='Port to listen on for node.')
    parser.add_argument('--public-ip', type=str, required=True, help='Your public IP address or domain (e.g., 58.234.16.95)')
    args = parser.parse_args()

    MY_NODE_ADDRESS = f"http://{args.public_ip}:{args.port}"
    print(f"[SYSTEM] This node's public address is set to: {MY_NODE_ADDRESS}")

    for node in PEER_NODES:
        blockchain.register_node(node, MY_NODE_ADDRESS)

    print("\n[SYSTEM] Announcing this node to the network...")
    announce_self_to_peers()

    print("\n[SYNC] Starting initial conflict resolution...")
    blockchain.resolve_conflicts()

    chain_sync_thread = threading.Thread(target=periodic_chain_sync, daemon=True)
    chain_sync_thread.start()
    print("[SYSTEM] Periodic chain synchronization thread started (60s interval).")

    peer_discovery_thread = threading.Thread(target=periodic_peer_discovery, daemon=True)
    peer_discovery_thread.start()
    print("[SYSTEM] Periodic peer discovery thread started (180s interval).")

    pruning_thread = threading.Thread(target=periodic_prune_nodes, daemon=True)
    pruning_thread.start()
    print("[SYSTEM] Periodic node pruning thread started (600s interval).")

    print(f"\nCMXP Node (Argon2id) starting on {args.host}:{args.port}...")
    app.run(host=args.host, port=args.port, threaded=True)
# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
# (Argon2id Version)
# Modified by Eric Trump of the CMXP community on October 14, 2025
#
# All rights reserved
#
# This software is provided "as is", without warranty of any kind, express or
# implied, including but not to the warranties of merchantability,
# fitness for a particular purpose and noninfringement. In no event shall the
# authors or copyright holders be liable for any claim, damages or other
# liability, whether in an action of contract, tort or otherwise, arising from,
# out of or in connection with the software or the use or other dealings in the
# software.

from flask import Flask, jsonify, request
from core import Blockchain, Transaction, Block
import time, argparse, ecdsa, requests, threading
from pymongo import ASCENDING

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
    
    latest_block = blockchain.get_latest_block()
    work_data['work_id'] = latest_block.hash if latest_block else "0"
    
    return jsonify(work_data), 200

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

@app.route('/chain/latest', methods=['GET'])
def get_latest_block_info_for_sync():
    latest_block = blockchain.get_latest_block()
    if latest_block:
        return jsonify({
            'index': latest_block.index,
            'hash': latest_block.hash,
            'timestamp': latest_block.timestamp
        }), 200
    return jsonify({'index': -1}), 200

@app.route('/blocks/since/<int:index>', methods=['GET'])
def get_blocks_since(index):
    latest_index = blockchain.get_latest_block().index if blockchain.chain else -1
    if index < 0 or index > latest_index:
        return jsonify({'message': 'Invalid index'}), 400
    
    blocks_data = list(blockchain.blocks_collection.find(
        {'index': {'$gt': index}},
        {'_id': 0}
    ).sort("index", ASCENDING))
    
    return jsonify({'blocks': blocks_data}), 200

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

@app.route('/blocks/announce', methods=['POST'])
def announce_block():
    values = request.get_json()
    if not values:
        return "Missing block data", 400
    
    # --- [수정됨] 블록을 보낸 노드의 순수 IP 주소를 기록 ---
    source_ip = request.remote_addr
    
    try:
        block = blockchain.dict_to_block(values)
    except Exception as e:
        return f"Invalid block data format: {e}", 400

    result, message = blockchain.add_block(block)
    
    if result is True:
        print(f"\n[ACCEPTED] Block #{block.index} added to the chain via announcement.")
        # --- [수정됨] broadcast_block에 source_ip 전달 ---
        broadcast_block(block, source_ip=source_ip)
        return "Block added", 201
        
    elif result == 'sync_needed':
        print(f"\n[SYNC-TRIGGER] Received block #{block.index} from a longer chain. Triggering immediate sync...")
        threading.Thread(target=blockchain.resolve_conflicts).start()
        return "Sync triggered", 202
        
    else:
        if message == "Received block is old or a duplicate":
            return message, 200
        return f"Block rejected: {message}", 400

# --- [수정됨] 전파 시작 노드의 IP를 받아 정확하게 비교 ---
def broadcast_block(block, source_ip=None):
    for peer_netloc in list(blockchain.nodes.keys()):
        # peer_netloc (예: '123.45.67.89:5000')에서 IP 부분만 추출
        peer_ip = peer_netloc.split(':')[0]
        if source_ip and peer_ip == source_ip:
            continue
        try:
            # http 스키마를 명시하여 요청
            url = f"http://{peer_netloc}/blocks/announce"
            threading.Thread(target=requests.post, args=(url,), kwargs={'json': block.to_dict(), 'timeout': 5}).start()
        except Exception as e:
            print(f"[BROADCAST] Failed to broadcast block to {peer_netloc}: {e}")

def periodic_chain_sync():
    while True:
        time.sleep(60)
        print("\n[CHAIN-SYNC] Running conflict resolution...")
        replaced = blockchain.resolve_conflicts()
        if not replaced:
            print("[CHAIN-SYNC] Our chain is up to date.")

def periodic_peer_discovery():
    while True:
        time.sleep(60) 
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
        time.sleep(120) 
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

    def delayed_initial_sync():
        time.sleep(5)
        print("\n[SYNC] Starting initial conflict resolution...")
        blockchain.resolve_conflicts()

    initial_sync_thread = threading.Thread(target=delayed_initial_sync)
    initial_sync_thread.start()

    chain_sync_thread = threading.Thread(target=periodic_chain_sync, daemon=True)
    chain_sync_thread.start()
    print("[SYSTEM] Periodic chain synchronization thread started (60s interval).")

    peer_discovery_thread = threading.Thread(target=periodic_peer_discovery, daemon=True)
    peer_discovery_thread.start()
    print("[SYSTEM] Periodic peer discovery thread started (60s interval).")

    pruning_thread = threading.Thread(target=periodic_prune_nodes, daemon=True)
    pruning_thread.start()
    print("[SYSTEM] Periodic node pruning thread started (120s interval).")

    print(f"\nCMXP Node (Argon2id) starting on {args.host}:{args.port}...")
    app.run(host=args.host, port=args.port, threaded=True)
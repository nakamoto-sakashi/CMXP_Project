# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
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
from core import Blockchain, Transaction
import time, argparse, ecdsa

app = Flask(__name__)
blockchain = Blockchain()

def is_valid_address(address_hex):
    if not isinstance(address_hex, str) or len(address_hex) != 66:
        return False
    try:
        ecdsa.VerifyingKey.from_string(bytes.fromhex(address_hex), curve=ecdsa.SECP256k1)
        return True
    except (ValueError, ecdsa.errors.MalformedPointError):
        return False

print("\n+------------------------------------------------------+")
print("|            ⚠️ IMPORTANT WARNING ⚠️                   |")
print("+------------------------------------------------------+")
print("| CMXP coin is intended for learning and experimental  |")
print("| purposes only. This coin holds NO monetary value and |")
print("| should NEVER be traded for money or other assets.    |")
print("+------------------------------------------------------+\n")

@app.route('/mining/get-work', methods=['GET'])
def get_work():
    miner_address = request.args.get('miner_address')
    if not miner_address: return "Missing miner_address parameter", 400
    work_data = blockchain.get_work_data(miner_address)
    return jsonify(work_data), 200

@app.route('/mining/submit-block', methods=['POST'])
def submit_block():
    values = request.get_json()
    if not values: return "Missing block data", 400
    block_data, submitter_address = values.get('block_data'), values.get('miner_address')
    if not all([block_data, submitter_address]): return "Missing values", 400
    block = blockchain.dict_to_block(block_data)
    if blockchain.add_block(block, submitter_address):
        print(f"\nBlock #{block.index} (mined by: ...{submitter_address[-10:]}) was added to the chain.")
        return jsonify({'message': f'Block #{block.index} accepted'}), 201
    else: return jsonify({'message': 'Block was rejected'}), 400

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'signature', 'timestamp']
    if not all(k in values for k in required): return jsonify({'message': 'Missing values'}), 400

    if not is_valid_address(values['sender']) or not is_valid_address(values['recipient']):
        return jsonify({'message': 'Invalid wallet address format'}), 400

    tx = Transaction(values['sender'], values['recipient'], values['amount'], bytes.fromhex(values['signature']), timestamp=values['timestamp'])
    
    if blockchain.add_transaction(tx):
        return jsonify({'message': 'Transaction will be added to the next block'}), 201
    else:
        return jsonify({'message': 'Invalid transaction'}), 400
        
@app.route('/chain', methods=['GET'])
def full_chain():
    response = {'chain': [block.__dict__ for block in blockchain.chain], 'length': len(blockchain.chain)}
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    nodes = request.get_json().get('nodes')
    if nodes is None: return "Error: Please supply a valid list of nodes", 400
    for node in nodes: blockchain.register_node(node)
    return jsonify({'message': 'New nodes have been added', 'total_nodes': list(blockchain.nodes)}), 201

@app.route('/nodes/resolve', methods=['GET'])
def consensus():
    replaced = blockchain.resolve_conflicts()
    response = {'message': 'Our chain was replaced' if replaced else 'Our chain is authoritative', 'chain': [block.__dict__ for block in blockchain.chain]}
    return jsonify(response), 200

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run a CMXP blockchain node.')
    parser.add_argument('-p', '--port', default=5000, type=int, help='port to listen on for node')
    parser.add_argument('--bootstrap', type=str, help='bootstrap node address to connect to')
    args = parser.parse_args()
    if args.bootstrap:
        print(f"Attempting to connect to bootstrap node: {args.bootstrap}...")
        blockchain.register_node(args.bootstrap)
        time.sleep(1)
        if blockchain.resolve_conflicts(): print("Synchronization complete: The chain was replaced.")
        else: print("Synchronization complete: The current chain is authoritative.")
    print(f"\nStarting CMXP node on port {args.port}...")
    app.run(host='0.0.0.0', port=args.port, threaded=False)
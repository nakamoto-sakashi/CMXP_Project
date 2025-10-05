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

import time, hashlib, json, requests, os, randomx, ecdsa
from urllib.parse import urlparse

INITIAL_MINING_REWARD = 1000
HALVING_INTERVAL = 900000
BLOCK_GENERATION_INTERVAL = 120
DIFFICULTY_ADJUSTMENT_INTERVAL = 10
MAX_TARGET = (2**256) - 1
INITIAL_DIFFICULTY_BITS = 4
INITIAL_TARGET = MAX_TARGET >> INITIAL_DIFFICULTY_BITS

class Block:
    def __init__(self, index, timestamp, data, previous_hash, target, nonce=0):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.target = target
        self.nonce = nonce
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        block_dict = self.__dict__.copy()
        block_dict.pop("hash", None)
        block_string = json.dumps(block_dict, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

class Transaction:
    def __init__(self, sender, recipient, amount, signature=None, timestamp=None):
        self.sender = sender
        self.recipient = recipient
        self.amount = amount
        self.timestamp = timestamp or time.time()
        self.signature = signature

    def calculate_hash(self):
        tx_info = { "sender": self.sender, "recipient": self.recipient, "amount": self.amount, "timestamp": self.timestamp }
        tx_string = json.dumps(tx_info, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).hexdigest()

    def to_dict(self):
        d = self.__dict__.copy()
        if self.signature:
            d['signature'] = self.signature.hex()
        return d

class Blockchain:
    def __init__(self):
        self.pending_transactions = []
        self.chain = []
        self.chain_file = "cmxp_blockchain.dat"
        self.nodes = set()
        self.load_chain()
        if not self.chain:
            self.chain = [self.create_genesis_block(INITIAL_TARGET)]
            self.save_chain()

    def create_genesis_block(self, target):
        genesis_data = {
            "name": "CPU Mining eXPerience", "ticker": "CMXP",
            "purpose": "A non-commercial coin built from scratch for pure learning and experimentation in blockchain technology.",
            "disclaimer": ["This coin (CMXP) holds NO monetary value and is intended for educational purposes only.", "DO NOT trade this coin for money or other assets."],
            "goals": ["To provide a hands-on learning experience in cryptocurrency development.", "To explore CPU-friendly mining algorithms like RandomX.", "To understand the fundamentals of blockchain, consensus, and peer-to-peer networking."],
            "pre_mine_distribution": [
                {"recipient": "034191875b04d89064c4089854820a5b7dca22f84adbc7241e7d54ab8d96db12fd", "amount": 100000000},
                {"recipient": "02a31d7bfd71d2017e04d494185ff748b89cce0ddce786f71fe5716c0026b44fde", "amount": 200000000},
            ]
        }
        return Block(0, time.time(), genesis_data, "0", target=target)

    def get_next_target(self):
        latest_block = self.get_latest_block()
        new_index = latest_block.index + 1
        if new_index % DIFFICULTY_ADJUSTMENT_INTERVAL != 0: return latest_block.target
        if new_index < DIFFICULTY_ADJUSTMENT_INTERVAL: return latest_block.target
        prev_adjustment_block = self.chain[-DIFFICULTY_ADJUSTMENT_INTERVAL]
        expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL * BLOCK_GENERATION_INTERVAL
        actual_time = latest_block.timestamp - prev_adjustment_block.timestamp
        ratio = actual_time / expected_time
        ratio = max(0.25, min(4.0, ratio))
        new_target = int(latest_block.target * ratio)
        return min(new_target, MAX_TARGET)

    def add_block(self, block, submitter_address):
        last_block = self.get_latest_block()
        if block.previous_hash != last_block.hash: return False
        if not self.valid_proof(block): return False
        if len(block.data) > 0:
            reward_tx = block.data[0]
            if reward_tx['sender'] != '0' or reward_tx['recipient'] != submitter_address: return False
        self.chain.append(block)
        if len(block.data) > 1:
            tx_in_block_timestamps = {tx['timestamp'] for tx in block.data[1:]}
            self.pending_transactions = [tx for tx in self.pending_transactions if tx.to_dict()['timestamp'] not in tx_in_block_timestamps]
        return True

    @staticmethod
    def valid_proof(block):
        key = b'CMXP-is-a-cpu-mineable-coin!'
        hashing_blob = (str(block.index) + str(block.timestamp) + str(block.data) + str(block.previous_hash) + str(block.target) + str(block.nonce)).encode()
        try:
            rx = randomx.RandomX(key=key)
            work_hash_bytes = rx.calculate_hash(hashing_blob)
            return int.from_bytes(work_hash_bytes, 'big') < block.target
        except Exception:
            return False

    def get_work_data(self, miner_address):
        reward_amount = self.get_current_mining_reward()
        reward_tx = Transaction(sender="0", recipient=miner_address, amount=reward_amount)
        transactions_to_mine = [reward_tx] + self.pending_transactions
        work_data = {
            "index": len(self.chain), "data": [tx.to_dict() for tx in transactions_to_mine],
            "previous_hash": self.get_latest_block().hash, "target": self.get_next_target()
        }
        return work_data

    def load_chain(self):
        if os.path.exists(self.chain_file):
            with open(self.chain_file, 'r') as f:
                chain_data = json.load(f)
                self.chain = [self.dict_to_block(b) for b in chain_data]
            print("Loaded CMXP blockchain from file.")

    def save_chain(self):
        with open(self.chain_file, 'w') as f:
            chain_data = [block.__dict__ for block in self.chain]
            json.dump(chain_data, f, indent=4)
        print("CMXP blockchain saved to file.")

    def add_transaction(self, transaction):
        if not all([transaction.sender, transaction.recipient, transaction.amount, transaction.signature]): return False
        if not self.verify_transaction(transaction): return False
        self.pending_transactions.append(transaction)
        return True

    def verify_transaction(self, transaction):
        if transaction.sender == "0": return True
        try:
            pk_bytes = bytes.fromhex(transaction.sender)
            vk = ecdsa.VerifyingKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
            tx_hash = transaction.calculate_hash()
            return vk.verify(transaction.signature, tx_hash.encode())
        except Exception:
            return False

    def get_latest_block(self):
        return self.chain[-1]
        
    def dict_to_block(self, block_data):
        return Block(
            index=block_data['index'], timestamp=block_data['timestamp'], data=block_data['data'],
            previous_hash=block_data['previous_hash'], target=block_data.get('target', MAX_TARGET),
            nonce=block_data.get('nonce', 0)
        )
    
    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc: self.nodes.add(parsed_url.netloc)
        elif parsed_url.path: self.nodes.add(parsed_url.path)
        else: raise ValueError('Invalid URL')

    def resolve_conflicts(self):
        neighbours = self.nodes
        new_chain = None
        max_length = len(self.chain)
        for node in neighbours:
            try:
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    length, chain = response.json()['length'], response.json()['chain']
                    if length > max_length: max_length, new_chain = length, chain
            except requests.exceptions.ConnectionError: continue
        if new_chain:
            self.chain = [self.dict_to_block(b) for b in new_chain]
            return True
        return False
    
    def get_current_mining_reward(self):
        halving_count = len(self.chain) // HALVING_INTERVAL
        reward = INITIAL_MINING_REWARD / (2 ** halving_count)
        return reward
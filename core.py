# Copyright (c) 2025 Nakamoto Sakashi
# CMXP - The Cpu Mining eXPerience Project
# (Algorithm changed from RandomX to Argon2id)
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

import time, hashlib, json, requests, os, ecdsa, threading # <<<< [수정] threading 라이브러리 임포트
import argon2.low_level
from urllib.parse import urlparse
from pymongo import MongoClient, DESCENDING, ASCENDING

# --- Blockchain Parameters ---
INITIAL_MINING_REWARD = 1000
HALVING_INTERVAL = 900000
BLOCK_GENERATION_INTERVAL = 120 # 2 minutes
DIFFICULTY_ADJUSTMENT_INTERVAL = 10
MAX_TARGET = (2**256) - 1

# --- PoW Algorithm: Argon2id Parameters (Consensus Critical) ---
ARGON2_TIME_COST = 2
ARGON2_MEMORY_COST = 65536   # 64 MiB (in KiB)
ARGON2_PARALLELISM = 1       # Keep 1 for consistent verification
ARGON2_HASH_LEN = 32         # 256 bits
ARGON2_TYPE = argon2.low_level.Type.ID # Use Argon2id
CMXP_ARGON2_SALT = b'CMXP_PoW_Argon2id_v1.0' # Fixed network salt

# --- Initial Difficulty Adjustment for Argon2id ---
INITIAL_DIFFICULTY_BITS = 1
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

    def get_normalized_hashing_blob(self):
        """
        PoW 계산을 위해 정규화된 해싱 데이터를 반환합니다. (일관성 확보)
        """
        # sort_keys=True: 딕셔너리 키 정렬 보장, separators=(',', ':'): 공백 제거
        data_str = json.dumps(self.data, sort_keys=True, separators=(',', ':'))
        
        blob = (str(self.index) + str(self.timestamp) + data_str + 
                str(self.previous_hash) + str(self.target) + str(self.nonce))
        return blob.encode()

    def calculate_hash(self):
        # 블록 자체의 식별 해시(SHA256). PoW와는 다름.
        block_dict = self.__dict__.copy()
        block_dict.pop("hash", None)
        block_dict['target'] = str(block_dict['target'])
        block_string = json.dumps(block_dict, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self):
        d = self.__dict__.copy()
        d['target'] = str(self.target)
        return d

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
            # Ensure signature is hex string if it's bytes
            if isinstance(self.signature, bytes):
                 d['signature'] = self.signature.hex()
            else:
                 d['signature'] = self.signature
        return d

class Blockchain:
    def __init__(self):
        mongo_uri = os.getenv("MONGODB_URI", "mongodb://localhost:27017/")
        self.client = MongoClient(mongo_uri)
        self.db = self.client.cmxp_db
        self.blocks_collection = self.db.blocks
        
        self.pending_transactions = []
        self.nodes = set()
        self.lock = threading.Lock() # <<<< [추가] 잠금장치 초기화
        self.chain = self.load_chain()
        
        if not self.chain:
            genesis_block = self.create_genesis_block(INITIAL_TARGET)
            self.blocks_collection.insert_one(genesis_block.to_dict())
            self.chain = [genesis_block]

    def create_genesis_block(self, target):
        genesis_data = {
            "name": "CPU Mining eXPerience (Argon2id)",
            "ticker": "CMXP",
            "purpose": "A non-commercial coin built from scratch for pure learning and experimentation.",
            "disclaimer": ["This coin (CMXP) holds NO monetary value.", "DO NOT trade this coin for money or other assets."],
            "goals": ["To explore CPU-friendly mining algorithms like Argon2id."],
            "pre_mine_distribution": [
                {"recipient": "034191875b04d89064c4089854820a5b7dca22f84adbc7241e7d54ab8d96db12fd", "amount": 100000000},
                {"recipient": "02a31d7bfd71d2017e04d494185ff748b89cce0ddce786f71fe5716c0026b44fde", "amount": 200000000},
            ]
        }
        return Block(0, time.time(), genesis_data, "0", target=target)

    def load_chain(self):
        chain_data = list(self.blocks_collection.find({}, {'_id': 0}).sort("index", ASCENDING))
        if not chain_data:
            print("No blockchain found in DB.")
            return []
        return [self.dict_to_block(b) for b in chain_data]

    def get_next_target(self):
        with self.lock: # <<<< [수정] 잠금 적용
            return self._get_next_target_unsafe()

    def add_block(self, block, submitter_address):
        with self.lock: # <<<< [수정] 잠금 적용
            last_block = self._get_latest_block_unsafe()
            
            if last_block is None and block.index == 0:
                 pass
            elif last_block is None:
                return False

            if block.index != 0:
                if block.previous_hash != last_block.hash:
                    print(f"Block rejected: Invalid previous hash.")
                    return False
            
            if not self.valid_proof(block):
                print("Block rejected: Invalid proof of work (Argon2id).")
                return False
            
            if block.index != 0:
                if not isinstance(block.data, list) or len(block.data) == 0:
                    return False
                
                reward_tx_data = block.data[0]
                if not isinstance(reward_tx_data, dict) or reward_tx_data.get('sender') != '0' or reward_tx_data.get('recipient') != submitter_address:
                    print(f"Block rejected: Invalid coinbase transaction.")
                    return False

                temp_block_expenses = {}
                for tx_data in block.data[1:]:
                    if not isinstance(tx_data, dict): return False
                    try: tx = Transaction(sender=tx_data['sender'], recipient=tx_data['recipient'], amount=tx_data['amount'], signature=tx_data.get('signature'), timestamp=tx_data['timestamp'])
                    except KeyError: return False

                    if not self._verify_transaction_unsafe(tx):
                        print(f"Block rejected: Invalid signature in tx.")
                        return False
                    
                    sender_balance = self._get_balance_unsafe(tx.sender, include_pending=False)
                    balance = sender_balance - temp_block_expenses.get(tx.sender, 0)

                    if balance < tx.amount:
                        print(f"Block rejected: Insufficient funds for tx. Balance: {balance}, Amount: {tx.amount}")
                        return False
                    
                    temp_block_expenses[tx.sender] = temp_block_expenses.get(tx.sender, 0) + tx.amount

            self.blocks_collection.insert_one(block.to_dict())
            self.chain.append(block)

            if isinstance(block.data, list) and len(block.data) > 1:
                tx_in_block_ts = {tx['timestamp'] for tx in block.data[1:] if isinstance(tx, dict) and 'timestamp' in tx}
                self.pending_transactions = [tx for tx in self.pending_transactions if tx.to_dict().get('timestamp') not in tx_in_block_ts]
            return True

    @staticmethod
    def valid_proof(block):
        hashing_blob = block.get_normalized_hashing_blob()
        try:
            work_hash_bytes = argon2.low_level.hash_secret_raw( secret=hashing_blob, salt=CMXP_ARGON2_SALT, time_cost=ARGON2_TIME_COST, memory_cost=ARGON2_MEMORY_COST, parallelism=ARGON2_PARALLELISM, hash_len=ARGON2_HASH_LEN, type=ARGON2_TYPE )
            return int.from_bytes(work_hash_bytes, 'big') < block.target
        except Exception as e:
            print(f"Error during Argon2id validation: {e}")
            return False

    def get_work_data(self, miner_address):
        with self.lock: # <<<< [수정] 잠금 적용
            reward_amount = self._get_current_mining_reward_unsafe()
            reward_tx = Transaction(sender="0", recipient=miner_address, amount=reward_amount)
            
            transactions_to_mine = [reward_tx]
            temp_balances = {}

            for tx in self.pending_transactions:
                sender = tx.sender
                current_balance = self._get_balance_unsafe(sender, include_pending=False)
                balance = current_balance - temp_balances.get(sender, 0)
                if balance >= tx.amount:
                    transactions_to_mine.append(tx)
                    temp_balances[sender] = temp_balances.get(sender, 0) + tx.amount
                else:
                    print(f"Skipping transaction due to insufficient funds in mempool: {tx.calculate_hash()}")

            latest_block = self._get_latest_block_unsafe()
            if latest_block:
                index = latest_block.index + 1
                previous_hash = latest_block.hash
            else:
                index = 0
                previous_hash = "0"

            work_data = {
                "index": index, "data": [tx.to_dict() for tx in transactions_to_mine], "previous_hash": previous_hash, 
                "target": self._get_next_target_unsafe() # <<<< [수정] 교착 상태 해결
            }
            return work_data

    def add_transaction(self, transaction):
        with self.lock: # <<<< [수정] 잠금 적용
            if not all([transaction.sender, transaction.recipient, transaction.amount, transaction.signature]): return False
            if not isinstance(transaction.amount, (int, float)) or transaction.amount <= 0: return False
            if transaction.sender != "0":
                sender_balance = self._get_balance_unsafe(transaction.sender, include_pending=True)
                if sender_balance < transaction.amount:
                    print(f"Transaction rejected: Insufficient funds. Available: {sender_balance}, Amount: {transaction.amount}")
                    return False
            if not self._verify_transaction_unsafe(transaction): return False
            self.pending_transactions.append(transaction)
            return True

    def verify_transaction(self, transaction):
        with self.lock: # <<<< [수정] 잠금 적용
            return self._verify_transaction_unsafe(transaction)

    def _verify_transaction_unsafe(self, transaction): # <<<< [수정] _unsafe 내부 함수
        if transaction.sender == "0": return True
        try:
            pk_bytes = bytes.fromhex(transaction.sender)
            vk = ecdsa.VerifyingKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
            tx_hash = transaction.calculate_hash()
            signature = transaction.signature
            if isinstance(signature, str): signature = bytes.fromhex(signature)
            return vk.verify(signature, tx_hash.encode())
        except Exception: return False

    def get_balance(self, address, include_pending=True):
        with self.lock: # <<<< [수정] 잠금 적용
            return self._get_balance_unsafe(address, include_pending)

    def _get_balance_unsafe(self, address, include_pending=True): # <<<< [수정] _unsafe 내부 함수
        pipeline = [
            {"$match": {"index": {"$gt": 0}}}, {"$unwind": "$data"},
            {"$project": { "income": {"$cond": [{"$eq": ["$data.recipient", address]}, "$data.amount", 0]}, "expense": {"$cond": [{"$and": [{"$eq": ["$data.sender", address]}, {"$ne": ["$data.sender", "0"]}]}, "$data.amount", 0]} }},
            {"$group": { "_id": None, "total_income": {"$sum": "$income"}, "total_expense": {"$sum": "$expense"} }}
        ]
        result = list(self.blocks_collection.aggregate(pipeline))
        balance = result[0]['total_income'] - result[0]['total_expense'] if result else 0
        if self.chain and self.chain[0].index == 0:
            genesis_data = self.chain[0].data
            if isinstance(genesis_data, dict) and "pre_mine_distribution" in genesis_data:
                 distributions = genesis_data.get("pre_mine_distribution", [])
                 if isinstance(distributions, list):
                    for dist in distributions:
                        if dist.get("recipient") == address: balance += dist.get("amount", 0)
        if include_pending:
            pending_expense = sum(tx.amount for tx in self.pending_transactions if tx.sender == address)
            balance -= pending_expense
        return max(0, balance)

    def get_latest_block(self):
        with self.lock: # <<<< [수정] 잠금 적용
            return self._get_latest_block_unsafe()

    def _get_latest_block_unsafe(self): # <<<< [수정] _unsafe 내부 함수
        if not self.chain:
            latest_block_data = self.blocks_collection.find_one({}, {'_id': 0}, sort=[("index", DESCENDING)])
            if latest_block_data: return self.dict_to_block(latest_block_data)
            return None
        return self.chain[-1]
        
    def dict_to_block(self, block_data):
        target_val = block_data.get('target', str(MAX_TARGET))
        try: target = int(target_val)
        except ValueError: target = MAX_TARGET
        return Block( index=block_data['index'], timestamp=block_data['timestamp'], data=block_data['data'], previous_hash=block_data['previous_hash'], target=target, nonce=block_data.get('nonce', 0) )
    
    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc: self.nodes.add(parsed_url.netloc)
        elif parsed_url.path: self.nodes.add(parsed_url.path)
        else: raise ValueError('Invalid URL')

    def resolve_conflicts(self):
        with self.lock: # <<<< [수정] 잠금 적용
            neighbours = self.nodes; new_chain_data = None; max_length = len(self.chain)
            for node in neighbours:
                try:
                    if not node.startswith('http'): url = f'http://{node}/chain'
                    else: url = f'{node}/chain'
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        data = response.json(); length = data.get('length'); chain_data = data.get('chain')
                        if length and chain_data and length > max_length:
                            max_length = length; new_chain_data = chain_data
                except requests.exceptions.RequestException:
                    print(f"Warning: Could not connect to node {node}"); continue
            if new_chain_data:
                self.chain = [self.dict_to_block(b) for b in new_chain_data]
                self.blocks_collection.delete_many({})
                if self.chain: self.blocks_collection.insert_many([block.to_dict() for block in self.chain])
                return True
            return False
    
    def get_current_mining_reward(self):
        with self.lock: # <<<< [수정] 잠금 적용
            return self._get_current_mining_reward_unsafe()

    def _get_current_mining_reward_unsafe(self): # <<<< [수정] _unsafe 내부 함수
        halving_count = len(self.chain) // HALVING_INTERVAL
        if halving_count >= 64: return 0
        reward = INITIAL_MINING_REWARD / (2 ** halving_count)
        return reward

    def _get_next_target_unsafe(self): # <<<< [추가] get_next_target의 _unsafe 버전
        latest_block = self._get_latest_block_unsafe()
        if latest_block is None: return INITIAL_TARGET
        new_index = latest_block.index + 1
        if new_index % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 or new_index < DIFFICULTY_ADJUSTMENT_INTERVAL: 
            return latest_block.target
        if len(self.chain) < DIFFICULTY_ADJUSTMENT_INTERVAL:
            return latest_block.target
        prev_adjustment_block = self.chain[-DIFFICULTY_ADJUSTMENT_INTERVAL]
        expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL * BLOCK_GENERATION_INTERVAL
        actual_time = latest_block.timestamp - prev_adjustment_block.timestamp
        if actual_time < 1: actual_time = 1
        ratio = actual_time / expected_time
        ratio = max(0.25, min(4.0, ratio))
        new_target = int(latest_block.target * ratio)
        return min(new_target, MAX_TARGET)
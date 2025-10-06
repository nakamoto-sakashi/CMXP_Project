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

import time, hashlib, json, requests, os, ecdsa
# import randomx # Removed
import argon2.low_level # Added
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
ARGON2_MEMORY_COST = 65536   # 64 MiB (in KiB) - 접근성을 고려한 설정
ARGON2_PARALLELISM = 1       # Keep 1 for consistent verification
ARGON2_HASH_LEN = 32         # 256 bits
ARGON2_TYPE = argon2.low_level.Type.ID # Use Argon2id
CMXP_ARGON2_SALT = b'CMXP_PoW_Argon2id_v1.0' # Fixed network salt

# --- Initial Difficulty Adjustment for Argon2id ---
# Argon2는 느리므로 초기 난이도를 낮게 설정합니다.
INITIAL_DIFFICULTY_BITS = 1 # Reduced from 4.
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
    # (Transaction class remains the same)
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
        self.chain = self.load_chain()
        
        if not self.chain:
            genesis_block = self.create_genesis_block(INITIAL_TARGET)
            self.blocks_collection.insert_one(genesis_block.to_dict())
            self.chain = [genesis_block]

    def create_genesis_block(self, target):
        # 제네시스 블록 데이터 수정 (알고리즘명 변경)
        genesis_data = {
            "name": "CPU Mining eXPerience (Argon2id)", # Updated
            "ticker": "CMXP",
            "purpose": "A non-commercial coin built from scratch for pure learning and experimentation in blockchain technology.",
            "disclaimer": ["This coin (CMXP) holds NO monetary value and is intended for educational purposes only.", "DO NOT trade this coin for money or other assets."],
            "goals": ["To provide a hands-on learning experience in cryptocurrency development.", "To explore CPU-friendly mining algorithms like Argon2id.", "To understand the fundamentals of blockchain, consensus, and peer-to-peer networking."],
            "pre_mine_distribution": [
                {"recipient": "034191875b04d89064c4089854820a5b7dca22f84adbc7241e7d54ab8d96db12fd", "amount": 100000000},
                {"recipient": "02a31d7bfd71d2017e04d494185ff748b89cce0ddce786f71fe5716c0026b44fde", "amount": 200000000},
            ]
        }
        return Block(0, time.time(), genesis_data, "0", target=target)

    def load_chain(self):
        chain_data = list(self.blocks_collection.find({}, {'_id': 0}).sort("index", ASCENDING))
        if not chain_data:
            print("No blockchain found in DB. A new one will be created.")
            return []
        print(f"Loaded {len(chain_data)} blocks from the database.")
        return [self.dict_to_block(b) for b in chain_data]

    def get_next_target(self):
        latest_block = self.get_latest_block()
        if latest_block is None: return INITIAL_TARGET

        new_index = latest_block.index + 1
        if new_index % DIFFICULTY_ADJUSTMENT_INTERVAL != 0 or new_index < DIFFICULTY_ADJUSTMENT_INTERVAL: 
            return latest_block.target
        
        if len(self.chain) < DIFFICULTY_ADJUSTMENT_INTERVAL:
            return latest_block.target

        prev_adjustment_block = self.chain[-DIFFICULTY_ADJUSTMENT_INTERVAL]
        expected_time = DIFFICULTY_ADJUSTMENT_INTERVAL * BLOCK_GENERATION_INTERVAL
        actual_time = latest_block.timestamp - prev_adjustment_block.timestamp
        
        if actual_time < 1: actual_time = 1 # 0으로 나누기 방지

        ratio = actual_time / expected_time
        ratio = max(0.25, min(4.0, ratio)) # 조정폭 제한 (4배수)
        
        new_target = int(latest_block.target * ratio)
        return min(new_target, MAX_TARGET)

    def add_block(self, block, submitter_address):
        last_block = self.get_latest_block()
        
        if last_block is None and block.index == 0:
             pass # Allow genesis if empty
        elif last_block is None:
            return False

        if block.index != 0:
            if block.previous_hash != last_block.hash:
                print(f"Block rejected: Invalid previous hash.")
                return False
        
        # PoW Validation (Argon2id)
        if not self.valid_proof(block):
            print("Block rejected: Invalid proof of work (Argon2id).")
            return False
        
        # Coinbase transaction validation
        if block.index != 0:
            if not isinstance(block.data, list) or len(block.data) == 0:
                return False
            reward_tx = block.data[0]
            if not isinstance(reward_tx, dict) or reward_tx.get('sender') != '0' or reward_tx.get('recipient') != submitter_address:
                print(f"Block rejected: Invalid coinbase transaction.")
                return False
        
        # Insert block
        self.blocks_collection.insert_one(block.to_dict())
        self.chain.append(block)

        # Remove mined transactions from pending pool
        if isinstance(block.data, list) and len(block.data) > 1:
            tx_in_block_ts = {tx['timestamp'] for tx in block.data[1:] if isinstance(tx, dict) and 'timestamp' in tx}
            self.pending_transactions = [tx for tx in self.pending_transactions if tx.to_dict().get('timestamp') not in tx_in_block_ts]
        return True

    # --- 핵심 수정 사항: RandomX를 Argon2id 검증 로직으로 교체 ---
    @staticmethod
    def valid_proof(block):
        # 1. 정규화된 해싱 데이터 준비
        hashing_blob = block.get_normalized_hashing_blob()
        
        try:
            # 2. Argon2id 해시 계산 (저수준 API 사용)
            work_hash_bytes = argon2.low_level.hash_secret_raw(
                secret=hashing_blob,
                salt=CMXP_ARGON2_SALT,
                time_cost=ARGON2_TIME_COST,
                memory_cost=ARGON2_MEMORY_COST,
                parallelism=ARGON2_PARALLELISM,
                hash_len=ARGON2_HASH_LEN,
                type=ARGON2_TYPE
            )
            
            # 3. 결과값을 정수로 변환하여 목표값과 비교
            return int.from_bytes(work_hash_bytes, 'big') < block.target
        except Exception as e:
            print(f"Error during Argon2id validation: {e}")
            return False
    # --------------------------------------------------------------------

    def get_work_data(self, miner_address):
        reward_amount = self.get_current_mining_reward()
        reward_tx = Transaction(sender="0", recipient=miner_address, amount=reward_amount)
        transactions_to_mine = [reward_tx] + self.pending_transactions
        
        latest_block = self.get_latest_block()
        if latest_block:
            index = latest_block.index + 1
            previous_hash = latest_block.hash
        else:
            index = 0
            previous_hash = "0"

        work_data = {
            "index": index, 
            "data": [tx.to_dict() for tx in transactions_to_mine],
            "previous_hash": previous_hash, 
            "target": self.get_next_target()
        }
        return work_data

    def add_transaction(self, transaction):
        if not all([transaction.sender, transaction.recipient, transaction.amount, transaction.signature]): return False
        if not self.verify_transaction(transaction): return False
        self.pending_transactions.append(transaction)
        return True

    def verify_transaction(self, transaction):
        if transaction.sender == "0": return True # Coinbase
        try:
            pk_bytes = bytes.fromhex(transaction.sender)
            vk = ecdsa.VerifyingKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
            tx_hash = transaction.calculate_hash()
            
            signature = transaction.signature
            if isinstance(signature, str):
                signature = bytes.fromhex(signature)

            return vk.verify(signature, tx_hash.encode())
        except Exception:
            return False

    def get_latest_block(self):
        if not self.chain:
            latest_block_data = self.blocks_collection.find_one({}, {'_id': 0}, sort=[("index", DESCENDING)])
            if latest_block_data:
                return self.dict_to_block(latest_block_data)
            return None
        return self.chain[-1]
        
    def dict_to_block(self, block_data):
        target_val = block_data.get('target', str(MAX_TARGET))
        try:
            target = int(target_val)
        except ValueError:
            target = MAX_TARGET

        return Block(
            index=block_data['index'], timestamp=block_data['timestamp'], data=block_data['data'],
            previous_hash=block_data['previous_hash'], target=target,
            nonce=block_data.get('nonce', 0)
        )
    
    def register_node(self, address):
        parsed_url = urlparse(address)
        if parsed_url.netloc: self.nodes.add(parsed_url.netloc)
        elif parsed_url.path: self.nodes.add(parsed_url.path)
        else: raise ValueError('Invalid URL')

    def resolve_conflicts(self):
        # (P2P 동기화 로직은 변경 없음)
        neighbours = self.nodes
        new_chain_data = None
        max_length = len(self.chain)
        
        for node in neighbours:
            try:
                # Basic protocol handling
                if not node.startswith('http'):
                    url = f'http://{node}/chain'
                else:
                    url = f'{node}/chain'

                response = requests.get(url, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    length = data.get('length')
                    chain_data = data.get('chain')
                    
                    if length and chain_data and length > max_length:
                        max_length = length
                        new_chain_data = chain_data
            except requests.exceptions.RequestException:
                print(f"Warning: Could not connect to node {node}")
                continue
            
        if new_chain_data:
            # 체인 교체 로직 (실제 운영 시 체인 유효성 검사 필수)
            self.chain = [self.dict_to_block(b) for b in new_chain_data]
            # DB 업데이트: 기존 체인 삭제 후 새 체인 삽입
            self.blocks_collection.delete_many({})
            if self.chain:
                self.blocks_collection.insert_many([block.to_dict() for block in self.chain])
            return True
            
        return False
    
    def get_current_mining_reward(self):
        halving_count = len(self.chain) // HALVING_INTERVAL
        if halving_count >= 64: return 0
        reward = INITIAL_MINING_REWARD / (2 ** halving_count)
        return reward
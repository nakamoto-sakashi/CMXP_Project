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
from pymongo import MongoClient, DESCENDING, ASCENDING

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

    # --- 핵심 수정 사항: PoW 계산을 위한 정규화된 데이터 생성 메소드 추가 ---
    def get_normalized_hashing_blob(self):
        """
        PoW(RandomX) 계산을 위해 정규화된 해싱 데이터를 반환합니다.
        데이터(트랜잭션 등)를 JSON으로 정렬하고 공백을 제거하여 네트워크 전체의 일관성을 확보합니다.
        """
        # sort_keys=True: 딕셔너리 키 정렬 보장, separators=(',', ':'): 공백 제거
        data_str = json.dumps(self.data, sort_keys=True, separators=(',', ':'))
        
        blob = (str(self.index) + 
                str(self.timestamp) + 
                data_str + 
                str(self.previous_hash) + 
                str(self.target) + 
                str(self.nonce))
        return blob.encode()
    # --------------------------------------------------------------------

    def calculate_hash(self):
        # 이 메소드는 블록 자체의 식별 해시(SHA256)를 계산합니다. PoW와는 다릅니다.
        block_dict = self.__dict__.copy()
        block_dict.pop("hash", None)
        block_dict['target'] = str(block_dict['target'])
        # 블록 식별자 계산 시에도 sort_keys=True를 사용하여 일관성을 유지합니다.
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
        # 트랜잭션 해시 계산 시에도 sort_keys=True를 사용합니다.
        tx_string = json.dumps(tx_info, sort_keys=True)
        return hashlib.sha256(tx_string.encode()).hexdigest()

    def to_dict(self):
        d = self.__dict__.copy()
        if self.signature:
            d['signature'] = self.signature.hex()
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

    def load_chain(self):
        chain_data = list(self.blocks_collection.find({}, {'_id': 0}).sort("index", ASCENDING))
        if not chain_data:
            print("No blockchain found in DB. A new one will be created.")
            return []
        print(f"Loaded {len(chain_data)} blocks from the database.")
        return [self.dict_to_block(b) for b in chain_data]

    def get_next_target(self):
        latest_block = self.get_latest_block()
        new_index = latest_block.index + 1
        if new_index % DIFFICULTY_ADJUSTMENT_INTERVAL != 0: return latest_block.target
        if new_index < DIFFICULTY_ADJUSTMENT_INTERVAL: return latest_block.target
        
        # In-memory chain is sufficient here as it's kept in sync
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
        
        # 코인베이스 트랜잭션 검증 (제네시스 블록 예외 처리 포함)
        if block.index != 0:
            if not isinstance(block.data, list) or len(block.data) == 0:
                return False # 트랜잭션이 없으면 안됨
            reward_tx = block.data[0]
            if reward_tx.get('sender') != '0' or reward_tx.get('recipient') != submitter_address:
                return False # 보상 주소가 다르면 안됨
        
        self.blocks_collection.insert_one(block.to_dict())
        self.chain.append(block)

        # 블록에 포함된 트랜잭션을 pending 목록에서 제거
        if isinstance(block.data, list) and len(block.data) > 1:
            tx_in_block_timestamps = {tx['timestamp'] for tx in block.data[1:] if isinstance(tx, dict) and 'timestamp' in tx}
            self.pending_transactions = [tx for tx in self.pending_transactions if tx.to_dict()['timestamp'] not in tx_in_block_timestamps]
        return True

    # --- 핵심 수정 사항: valid_proof가 정규화된 데이터를 사용하도록 변경 ---
    @staticmethod
    def valid_proof(block):
        key = b'CMXP-is-a-cpu-mineable-coin!'
        # 수정된 메소드 호출
        hashing_blob = block.get_normalized_hashing_blob()
        
        try:
            rx = randomx.RandomX(key=key)
            work_hash_bytes = rx.calculate_hash(hashing_blob)
            return int.from_bytes(work_hash_bytes, 'big') < block.target
        except Exception as e:
            print(f"Error during RandomX validation: {e}")
            return False
    # --------------------------------------------------------------------

    def get_work_data(self, miner_address):
        reward_amount = self.get_current_mining_reward()
        reward_tx = Transaction(sender="0", recipient=miner_address, amount=reward_amount)
        transactions_to_mine = [reward_tx] + self.pending_transactions
        work_data = {
            "index": len(self.chain), 
            "data": [tx.to_dict() for tx in transactions_to_mine],
            "previous_hash": self.get_latest_block().hash, 
            "target": self.get_next_target()
        }
        return work_data

    def add_transaction(self, transaction):
        if not all([transaction.sender, transaction.recipient, transaction.amount, transaction.signature]): return False
        if not self.verify_transaction(transaction): return False
        self.pending_transactions.append(transaction)
        return True

    def verify_transaction(self, transaction):
        if transaction.sender == "0": return True # 코인베이스 트랜잭션
        try:
            pk_bytes = bytes.fromhex(transaction.sender)
            vk = ecdsa.VerifyingKey.from_string(pk_bytes, curve=ecdsa.SECP256k1)
            tx_hash = transaction.calculate_hash()
            return vk.verify(transaction.signature, tx_hash.encode())
        except Exception:
            return False

    def get_latest_block(self):
        if not self.chain:
            # 메모리에 체인이 없을 경우 DB에서 최신 블록 조회 (안전 장치)
            latest_block_data = self.blocks_collection.find_one({}, {'_id': 0}, sort=[("index", DESCENDING)])
            if latest_block_data:
                return self.dict_to_block(latest_block_data)
            return None
        return self.chain[-1]
        
    def dict_to_block(self, block_data):
        # target 값이 문자열로 저장되어 있을 수 있으므로 int로 안전하게 변환
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
        neighbours = self.nodes
        new_chain_data = None
        max_length = len(self.chain)
        
        for node in neighbours:
            try:
                # 기본적으로 http를 사용하나, 실제 환경에서는 https 지원이 필요할 수 있습니다.
                response = requests.get(f'http://{node}/chain')
                if response.status_code == 200:
                    length = response.json()['length']
                    chain_data = response.json()['chain']
                    # TODO: 단순 길이 비교가 아닌, 누적 난이도(Work) 기반 검증 및 체인 유효성 검사 필요
                    if length > max_length:
                        max_length = length
                        new_chain_data = chain_data
            except requests.exceptions.ConnectionError:
                print(f"Warning: Could not connect to node {node}")
                continue
            
        if new_chain_data:
            # 체인 교체 로직
            self.chain = [self.dict_to_block(b) for b in new_chain_data]
            # DB 업데이트: 기존 체인 삭제 후 새 체인 삽입
            self.blocks_collection.delete_many({})
            if self.chain:
                self.blocks_collection.insert_many([block.to_dict() for block in self.chain])
            return True
            
        return False
    
    def get_current_mining_reward(self):
        halving_count = len(self.chain) // HALVING_INTERVAL
        reward = INITIAL_MINING_REWARD / (2 ** halving_count)
        return reward
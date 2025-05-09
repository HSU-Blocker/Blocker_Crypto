import base64
import os
import json
import hashlib
from ecdsa import SigningKey, VerifyingKey, NIST256p, BadSignatureError
from charm.toolbox.pairinggroup import PairingGroup
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from ecdsa.util import number_to_string, sigdecode_string, sigencode_string
from web3 import Web3
from eth_utils import keccak
from eth_abi.packed import encode_packed
from eth_account.messages import encode_defunct

# 전역적으로 PairingGroup 객체 생성
GLOBAL_GROUP = PairingGroup('SS512')

class ECDSATools:

    @staticmethod
    def generate_key_pair(private_key_path, public_key_path):
        """제조사 개인 키(SKm)와 공개 키(PKm) 생성 및 저장"""
        # 이미 키 파일이 있으면 로드, 없으면 새로 생성
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            private_key = ECDSATools.load_private_key(private_key_path)
            public_key = ECDSATools.load_public_key(public_key_path)
        else:
            private_key = SigningKey.generate(curve=NIST256p)
            public_key = private_key.get_verifying_key()

            # 키 파일 저장
            ECDSATools.save_key(private_key, private_key_path)
            ECDSATools.save_key(public_key, public_key_path)

        return private_key, public_key

    @staticmethod
    def load_private_key(private_key_path):
        """제조사 개인 키(SKm) 로드 (PEM 형식)"""
        with open(private_key_path, "rb") as f:
            return SigningKey.from_pem(f.read())

    @staticmethod
    def load_public_key(public_key_path):
        """제조사 공개 키(PKm) 로드 (PEM 형식)"""
        with open(public_key_path, "rb") as f:
            return VerifyingKey.from_pem(f.read())

    @staticmethod
    def save_key(key, key_path):
        """ 키를 PEM 형식으로 저장 """
        with open(key_path, "wb") as f:
            if isinstance(key, SigningKey):
                f.write(key.to_pem())  # 개인 키 저장
            elif isinstance(key, VerifyingKey):
                f.write(key.to_pem())  # 공개 키 저장
            else:
                raise ValueError("Invalid key type. Must be SigningKey or VerifyingKey.")

    @staticmethod
    def serialize_message(message):
        """메시지 직렬화: JSON 변환 가능하도록 변환"""
        def encode_custom(obj):
            if isinstance(obj, bytes):
                return {"__bytes__": base64.b64encode(obj).decode()}
            elif isinstance(obj, type(GLOBAL_GROUP.random())):  # PairingGroup 요소 변환
                return {"__element__": base64.b64encode(GLOBAL_GROUP.serialize(obj)).decode()}
            elif isinstance(obj, set):  # set을 list로 변환
                return list(obj)
            return obj

        return json.dumps(message, sort_keys=True, default=encode_custom).encode()

    @staticmethod
    def deserialize_message(message_json):
        """메시지 역직렬화: Base64 → bytes 및 PairingGroup 요소 변환"""
        def decode_custom(d):
            if "__bytes__" in d:
                return base64.b64decode(d["__bytes__"])
            elif "__element__" in d:
                return GLOBAL_GROUP.deserialize(base64.b64decode(d["__element__"]))
            return d

        return json.loads(message_json, object_hook=decode_custom)

    @staticmethod
    def sign_message(message_tuple, private_key_path):
        """
        message_tuple: (uid, ipfs_hash, encrypted_key, hash_of_update, description, price, version)
        Solidity와 동일하게 keccak256(abi.encodePacked(...))로 해시 생성 후, 이더리움 서명 규격 적용
        """
        uid, ipfs_hash, encrypted_key, hash_of_update, description, price, version = message_tuple
        
        # 1. 메시지 해시 생성 (솔리디티의 keccak256(abi.encodePacked(...))와 동일)
        message_bytes = encode_packed(
            ['string', 'string', 'string', 'string', 'string', 'uint256', 'string'],
            [uid, ipfs_hash, encrypted_key, hash_of_update, description, int(price), version]
        )
        message_hash = Web3.keccak(message_bytes)
        
        # 2. 블록체인 계정의 개인 키 사용 (PEM 파일 대신 환경 변수의 키 사용)
        private_key_hex = os.environ.get("BLOCKCHAIN_PRIVATE_KEY")
        if not private_key_hex:
            # 환경 변수가 없으면 PEM 파일에서 로드
            with open(private_key_path, "rb") as f:
                sk_pem = f.read()
                sk = SigningKey.from_pem(sk_pem)
                private_key_bytes = sk.to_string()
                private_key_hex = "0x" + private_key_bytes.hex()
            print("경고: BLOCKCHAIN_PRIVATE_KEY 환경 변수가 설정되지 않아 PEM 파일을 사용합니다. 서명 검증에 문제가 생길 수 있습니다.")
        
        # 3. 웹3 객체 생성 및 메시지 서명
        web3 = Web3()
        
        # Web3.py 버전에 따라 호환되는 방식으로 서명 생성
        # 1) 먼저 메시지 해시를 이더리움 서명 형식으로 인코딩
        signable_message = encode_defunct(primitive=message_hash)
        
        # 2) 인코딩된 메시지에 서명 (Web3.py 모든 버전과 호환)
        eth_message = web3.eth.account.sign_message(signable_message, private_key=private_key_hex)
        
        # 4. 디버그 정보 출력
        print("PYTHON message_bytes:", message_bytes.hex())
        print("PYTHON message_hash:", message_hash.hex())
        print("PYTHON signature:", eth_message.signature.hex())
        print("PYTHON v:", eth_message.v)
        print("PYTHON r:", hex(eth_message.r))
        print("PYTHON s:", hex(eth_message.s))
        
        # 서명자 주소 출력 (스마트 컨트랙트의 manufacturer 주소와 일치해야 함)
        signer_address = web3.eth.account.recover_message(signable_message, signature=eth_message.signature)
        print("PYTHON signer_address:", signer_address)
        
        return eth_message.signature

    @staticmethod
    def verify_signature(message, signature, public_key):
        """Ethereum 표준 형식(R 32B + S 32B + V 1B) 서명 검증"""
        # public_key가 VerifyingKey 객체가 아니라면 파일에서 로드
        if isinstance(public_key, str):
            public_key = ECDSATools.load_public_key(public_key)

        # Ethereum 메시지 프리픽스 적용
        eth_prefix = f"\x19Ethereum Signed Message:\n{len(message)}".encode() + message.encode()
        message_hash = hashlib.sha3_256(eth_prefix).digest()

        # 서명을 65바이트(R, S, V)로 분할
        if len(signature) != 65:
            raise ValueError(f"서명 길이가 올바르지 않습니다: {len(signature)}바이트 (예상: 65바이트)")

        r = int.from_bytes(signature[:32], byteorder="big")
        s = int.from_bytes(signature[32:64], byteorder="big")
        v = signature[64]

        # Ethereum에서 사용하는 서명 검증을 위한 V 값 확인
        if v not in [27, 28]:
            raise ValueError(f"유효하지 않은 V 값입니다. v는 27 또는 28이어야 합니다. 실제 값: {v}")

        # 서명 검증 수행
        try:
            return public_key.verify_digest(
                sigencode_string(r, s, public_key.curve.order),
                message_hash
            )
        except BadSignatureError:
            return False
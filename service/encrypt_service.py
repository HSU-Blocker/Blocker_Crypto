import os
import base64
from charm.toolbox.pairinggroup import GT
from crypto.cpabe.cpabe import CPABETools
from crypto.symmetric.symmetric import SymmetricCrypto
from crypto.hash.hash import HashTools
import pickle

class EncryptService:
    def __init__(self):
        # CP-ABE 도구 및 페어링 그룹 초기화
        self.cpabe = CPABETools()
        self.group = self.cpabe.get_group()

    def generate_keys(self):
        """
        CP-ABE 그룹(GT)에서 무작위 AES 대칭 키(kbj)와
        실제 파일 암호화에 사용할 AES 키를 생성
        """
        kbj, aes_key = SymmetricCrypto.generate_key(self.group)
        return kbj, aes_key

    def encrypt_file_with_aes(self, file_path, encrypted_file_path, aes_key):
        """
        파일을 AES 대칭키로 암호화하고,
        암호화된 파일의 경로와 SHA3 해시값을 반환
        """
        encrypted_file_path = SymmetricCrypto.encrypt_file(file_path, encrypted_file_path, aes_key)
        file_hash = HashTools.sha3_hash_file(encrypted_file_path)
        return encrypted_file_path, file_hash

    def encrypt_key_with_cpabe(self, kbj, policy, public_key_file, device_secret_key_file):
        """
        CP-ABE 공개키와 접근 정책(policy)을 기반으로
        대칭키(kbj)를 CP-ABE로 암호화
        """
        encrypted_key = self.cpabe.encrypt(kbj, policy, public_key_file)
        
        os.makedirs(os.path.dirname(device_secret_key_file), exist_ok=True)
        with open(device_secret_key_file, "wb") as f:
            pickle.dump(encrypted_key, f)
        
        if not encrypted_key:
            raise Exception("CP-ABE 암호화 실패: encrypted_key가 None입니다.")
        return encrypted_key.encode()

    def generate_device_secret_key(self, policy, public_key_file, master_key_file, device_secret_key_file):
        """
        사용자 속성에 따라 디바이스 비밀키를 생성
        - 키 파일이 없으면 setup 실행
        - 기존 키 파일이 존재하면 재생성하지 않음
        """

        user_attributes = self.extract_user_attributes(policy)

        if not (os.path.exists(public_key_file) and os.path.exists(master_key_file)):
            self.cpabe.setup(public_key_file, master_key_file)

        device_secret_key = self.cpabe.generate_device_secret_key(
            public_key_file, master_key_file, user_attributes, device_secret_key_file
        )
        return device_secret_key

    def serialize_element(self, element):
        """
        CP-ABE에서 사용하는 pairing.Element 객체를
        base64로 직렬화하여 문자열로 반환
        """
        return base64.b64encode(self.group.serialize(element)).decode()

    def extract_user_attributes(self, policy_dict):
        """
        접근 정책에 사용된 문자열에서 AND/OR, 괄호 등을 제거하여
        사용자 속성 리스트를 추출 (중복 제거 포함)
        """
        import re
        attributes = []
        for value in policy_dict.values():
            if not isinstance(value, str) or not value.strip():
                continue
            expr = value.upper().replace("AND", " ").replace("OR", " ")
            expr = re.sub(r"[()]", " ", expr)
            tokens = [token.strip() for token in expr.split() if token.strip()]
            attributes.extend(tokens)
        return list(set(attributes))  # 중복 제거

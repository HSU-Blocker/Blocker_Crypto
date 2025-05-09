import os
import logging
from hashlib import sha256
from charm.core.engine.util import objectToBytes
from crypto.cpabe.cpabe import CPABETools
from crypto.symmetric.symmetric import SymmetricCrypto
from crypto.hash.hash import HashTools

logger = logging.getLogger(__name__)

class DecryptService:
    def __init__(self, key_dir):
        self.key_dir = key_dir
        self.cpabe = CPABETools()
        self.group = self.cpabe.get_group()
        self.public_key = None
        self.device_secret_key = None
        self._load_keys()

    def _load_keys(self):
        """CP-ABE 키 로드"""
        try:
            logger.info(f"키 디렉토리: {self.key_dir}")

            public_key_file = os.path.join(self.key_dir, "public_key.bin")
            if os.path.exists(public_key_file):
                self.public_key = self.cpabe.load_public_key(public_key_file)
                logger.info("공개키 로드 완료")
            else:
                logger.warning("공개키를 찾을 수 없습니다. 제조사로부터 받아야 합니다.")

            device_secret_key_file = os.path.join(self.key_dir, "device_secret_key.bin")
            self.device_secret_key = self.cpabe.load_device_secret_key(device_secret_key_file)
            logger.info(f"SKd: {self.device_secret_key}")

        except Exception as e:
            logger.error(f"키 로드 중 오류 발생: {e}")

    def verify_file_hash(self, file_path, expected_hash):
        """파일 해시값을 계산하여 검증"""
        logger.info("암호화된 파일 해시 검증 시작")
        calculated_hash = HashTools.sha3_hash_file(file_path)
        if calculated_hash != expected_hash:
            logger.error(f"해시 검증 실패: 계산된 해시 {calculated_hash} != 기대 해시 {expected_hash}")
            return False
        logger.info("해시 검증 성공")
        return True

    def decrypt_key_with_cpabe(self, encrypted_key):
        """CP-ABE로 암호화된 대칭키 복호화 및 AES 키 파생"""
        try:
            logger.info(f"디바이스 속성 (SKd): {[s.strip() for s in self.device_secret_key['S']]}")
            decrypted_kbj = self.cpabe.decrypt(encrypted_key, self.public_key, self.device_secret_key)
            logger.info(f"복호화된 kbj: {decrypted_kbj}, 타입: {type(decrypted_kbj)}")
            aes_key = sha256(objectToBytes(decrypted_kbj, self.group)).digest()[:32]
            logger.info(f"복호화된 aes_key: {aes_key}, 타입: {type(aes_key)}")
            return aes_key
        except Exception as e:
            logger.error(f"대칭키 복호화 실패: {e}")
            raise

    def decrypt_file_with_aes(self, encrypted_path, decrypted_file_path, aes_key):
        """AES 대칭키로 암호화된 파일 복호화"""
        try:
            logger.info("대칭키로 업데이트 파일 복호화 시작")
            decrypted_data = SymmetricCrypto.decrypt_file(encrypted_path, decrypted_file_path, aes_key)
            logger.info("업데이트 파일 복호화 성공")
            return decrypted_data
        except Exception as e:
            logger.error(f"업데이트 파일 복호화 실패: {e}")
            raise

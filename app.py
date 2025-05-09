from flask import Flask, request, jsonify
from flask_restx import Api, Resource, fields
import os
import logging
import uuid
import base64
from dotenv import load_dotenv
import json

from crypto.ecdsa.ecdsa import ECDSATools
from service.encrypt_service import EncryptService
from service.decrypt_service import DecryptService
from service.policy_service import PolicyService

# 환경 변수 로드 (.env)
load_dotenv()

logger = logging.getLogger(__name__)

# Flask 애플리케이션 및 Swagger API 초기화
app = Flask(__name__)
api = Api(
    app,
    version="1.0",
    title="CP-ABE 암호화/복호화 API",
    description="AES + CP-ABE 기반 암복호화 테스트 API",
    doc="/docs" 
)

ns = api.namespace("crypto", description="암호화 / 복호화 기능")

# 기준 디렉토리
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# 파일 경로
KEY_DIR = os.path.join(BASE_DIR, os.getenv("KEY_DIR"))
ORIGINAL_FILE_PATH = os.path.join(BASE_DIR, os.getenv("ORIGINAL_FILE_PATH"))
ENCRYPTED_FILE_PATH = os.path.join(BASE_DIR, os.getenv("ENCRYPTED_FILE_PATH"))
DECRYPTED_FILE_PATH = os.path.join(BASE_DIR, os.getenv("DECRYPTED_FILE_PATH"))

# 키 파일 절대 경로
PUBLIC_KEY_FILE = os.path.join(KEY_DIR, os.getenv("PUBLIC_KEY"))
MASTER_KEY_FILE = os.path.join(KEY_DIR, os.getenv("MASTER_KEY"))
DEVICE_SECRET_KEY_FILE = os.path.join(KEY_DIR, os.getenv("DEVICE_SECRET_KEY"))
ECDSA_PRIVATE_KEY_FILE = os.path.join(KEY_DIR, os.getenv("ECDSA_PRIVATE_KEY"))
ECDSA_PUBLIC_KEY_FILE = os.path.join(KEY_DIR, os.getenv("ECDSA_PUBLIC_KEY"))
ENCRYPTED_KEY_FILE = os.path.join(KEY_DIR, os.getenv("ENCRYPTED_KEY_FILE"))

# Swagger용 입력 모델 정의
encrypt_model = api.model("EncryptRequest", {
    "policy": fields.String(
        required=True, 
        description="CP-ABE 접근 정책",
        example="(K4 OR K5) AND (123456 AND ATTR1) AND (A OR B OR C)"
    ),
    "policy_dict": fields.Raw(
        required=True,
        description="디바이스 속성 정보 (key-value)",
        example={
            "model": "K4 OR K5",
            "serial": "123456 AND ATTR1",
            "option": "A OR B OR C"
        }
    ),
    "description": fields.String(
        required=True,
        description="업데이트 설명",
        example="보안 패치 및 기능 개선"
    ),
    "price": fields.Float(
        required=True,
        description="가격 (ETH)",
        example=0.01
    ),
    "version": fields.String(
        required=True,
        description="버전 정보",
        example="1.0.3"
    )
})

decrypt_model = api.model("DecryptRequest", {
    "encrypted_key": fields.String(required=True, description="암호화된 대칭키"),
    "file_hash": fields.String(required=True, description="암호화된 파일 해시")
})

@ns.route("/encrypt")
class EncryptAPI(Resource):
    @ns.expect(encrypt_model)
    def post(self):
        """AES + CP-ABE 암호화"""
        try:
            # 1. 암호화 서비스 인스턴스 생성
            encryptor = EncryptService()

            # 2. 요청 데이터 추출
            policy_dict = request.json.get("policy_dict")
            policy = request.json.get("policy")
            description = request.json.get("description")
            price = request.json.get("price")
            version = request.json.get("version")

            # 고유 UID 생성
            update_uid = f"update_{uuid.uuid4().hex}"

            # 3. AES용 대칭 키(kbj, aes_key) 생성
            kbj, aes_key = encryptor.generate_keys()

            # 4. 원본 파일을 AES 키로 암호화 → 암호화된 파일 및 SHA3 해시 획득
            encrypted_path, file_hash = encryptor.encrypt_file_with_aes(ORIGINAL_FILE_PATH, ENCRYPTED_FILE_PATH, aes_key)

            # 5. CP-ABE로 대칭 키(kbj)를 암호화 (접근 정책 기반)
            encrypted_key = encryptor.encrypt_key_with_cpabe(kbj, policy, PUBLIC_KEY_FILE, DEVICE_SECRET_KEY_FILE)
            logger.info(
                f"CP-ABE로 대칭키 암호화 완료, encrypted_key: {encrypted_key} ... (type={type(encrypted_key)})"
            ) 
            
            if not encrypted_key:
                raise Exception("CP-ABE 암호화 실패: encrypted_key가 None입니다.")
            
            # 암호화된 키를 바이너리 파일로 저장
            with open(ENCRYPTED_KEY_FILE, "wb") as f:
                f.write(encrypted_key)  # 이미 bytes 타입

            # 6. 디바이스용 속성 기반 개인키(SKd) 생성
            encryptor.generate_device_secret_key(policy_dict, PUBLIC_KEY_FILE, MASTER_KEY_FILE, DEVICE_SECRET_KEY_FILE)

            # 7. 서명 생성
            ecdsa_private_key_path = os.path.join(KEY_DIR, "ecdsa_private_key.pem")
            ecdsa_public_key_path = os.path.join(KEY_DIR, "ecdsa_public_key.pem")

            # 키가 있으면 로드하고, 없으면 생성 (매번 새로 생성하지 않음)
            if os.path.exists(ecdsa_private_key_path) and os.path.exists(
                ecdsa_public_key_path
            ):
                ecdsa_private_key = ECDSATools.load_private_key(ecdsa_private_key_path)
                ecdsa_public_key = ECDSATools.load_public_key(ecdsa_public_key_path)
                logger.info("기존 ECDSA 키 로드 완료")
            else:
                ecdsa_private_key, ecdsa_public_key = ECDSATools.generate_key_pair(
                    ecdsa_private_key_path, ecdsa_public_key_path
                )
                logger.info("새 ECDSA 키 생성 완료")

            # # 서명 생성
            # signature_message = (
            #     update_uid,
            #     file_hash, # 원래는 ipfs_hash
            #     encrypted_key,
            #     file_hash,
            #     description,
            #     price,
            #     version,
            # )
            # signature = ECDSATools.sign_message(signature_message, ecdsa_private_key_path)

            # 8. 응답 반환
            return {
                "uid": update_uid,
                "encrypted_key": base64.b64encode(encrypted_key).decode("utf-8"),
                "file_hash": file_hash,
                "version": version,
                # "signature": base64.b64encode(signature).decode(),
                "message": "암호화 성공"
            }
        except Exception as e:
            return {"error": str(e)}, 500

@ns.route("/decrypt")
class DecryptAPI(Resource):
    @ns.expect(decrypt_model)
    def post(self):
        """AES + CP-ABE 복호화"""
        try:
            # 1. 요청에서 해시값 추출 및 암호화된 키를 바이너리 파일에서 읽기
            with open(ENCRYPTED_KEY_FILE, "rb") as f:
                encrypted_key_bytes = f.read()

            # 1. bytes → str
            encrypted_key_str = encrypted_key_bytes.decode("utf-8")

            # 2. str → dict (json)
            encrypted_key = json.loads(encrypted_key_str)

            logger.info(f"encrypted_key (parsed): {type(encrypted_key)} keys: {list(encrypted_key.keys())}")
                
            file_hash = request.json.get("file_hash")

            # 2. 복호화 서비스 인스턴스 생성 및 키 로딩
            decryptor = DecryptService(KEY_DIR)

            # 3. 암호화된 파일의 해시 검증 (데이터 무결성 확인)
            if not decryptor.verify_file_hash(ENCRYPTED_FILE_PATH, file_hash):
                return {"error": "해시 검증 실패"}, 400

            # 4. CP-ABE로 암호화된 키를 복호화하여 AES 키 복원
            aes_key = decryptor.decrypt_key_with_cpabe(encrypted_key)

            # 5. AES 키로 파일 복호화 수행
            decrypted_data = decryptor.decrypt_file_with_aes(ENCRYPTED_FILE_PATH, DECRYPTED_FILE_PATH, aes_key)

            # 5. 성공 응답
            return {
                "message": "복호화 성공",
                "decrypted_path": DECRYPTED_FILE_PATH
            }
        except Exception as e:
            return {"error": str(e)}, 500

# 서버 실행
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

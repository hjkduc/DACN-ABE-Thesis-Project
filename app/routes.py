from collections import defaultdict
from email.policy import default
import os
from attr import has
from flask import Blueprint, Flask, request, jsonify
# -> Thư viện Charm-Crypto: Core chính để thực hiện các thuật toán toán học cho ABE
from charm.toolbox.pairinggroup import PairingGroup, GT, G1, G2, ZR
from charm.schemes.abenc.abenc_maabe_rw15 import MaabeRW15
from charm.core.engine.util import objectToBytes, bytesToObject
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction, SymmetricCryptoAbstraction
from charm.core.math.pairing import hashPair as extractor
from flask_restx import Api, Resource, fields
import hashlib
import requests
import threading

from flask import send_file, make_response
from werkzeug.datastructures import FileStorage
import io

import types

from key_manager import KeyManager
import re

from key_manager.redis import RedisKeyManager

blueprint = Blueprint('api', __name__, url_prefix='/api')
api = Api(blueprint, doc='/docs', version='1.0', title='MA-ABE API', description='A simple MA-ABE API')

# -> Kết nối Redis: Sử dụng Redis làm nơi lưu trữ khóa (Key Storage) tập trung.
key_manager: KeyManager = RedisKeyManager(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    db=int(os.getenv('REDIS_DB', 0))
)

_global_params = None

def clean_for_charm(obj):
    """
    -> Hàm tiện ích: Loại bỏ các dữ liệu không thể tuần tự hóa (serialize) trước khi lưu vào Redis.
    """
    if isinstance(obj, (str, int, float, bool, type(None), bytes)):
        return obj

    if isinstance(obj, (types.FunctionType, types.MethodType, types.BuiltinFunctionType, types.ModuleType, types.CodeType)):
        try:
            return f"<non-serializable:{getattr(obj,'__name__', type(obj))}>"
        except Exception:
            return f"<non-serializable:{type(obj)}>"

    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            try:
                key = k if isinstance(k, (str, int)) else str(k)
            except Exception:
                key = str(k)
            cleaned[key] = clean_for_charm(v)
        return cleaned

    if isinstance(obj, list):
        return [clean_for_charm(i) for i in obj]
    if isinstance(obj, tuple):
        return tuple(clean_for_charm(i) for i in obj)
    if isinstance(obj, set):
        return {clean_for_charm(i) for i in obj}

    try:
        return obj
    except Exception:
        return str(obj)


def get_maabe():
    global _global_params

    # -> Khởi tạo nhóm Pairing trên đường cong Elliptic MNT224 (an toàn và hỗ trợ Pairing).
    group = PairingGroup('MNT224')
    # -> Sử dụng lược đồ mã hóa Multi-Authority ABE của Rouselakis-Waters 2015 (RW15).
    maabe = MaabeRW15(group)

    if _global_params is not None:
        return maabe, group, _global_params

    try:
        # -> Kiểm tra xem tham số toàn cục (Global Params) đã có trong Redis chưa.
        stored_params = key_manager.retrieve_key('global_params')
        if stored_params:
            global_params = bytesToObject(stored_params, group)
            setup_with_lambdas = maabe.setup()
            global_params['H'] = setup_with_lambdas['H']
            global_params['F'] = setup_with_lambdas['F']
            _global_params = global_params
            print("✅ Loaded global_params from Redis")
            return maabe, group, global_params
    except Exception as e:
        print("❌ Redis error:", str(e))

    # -> Nếu chưa có, hệ thống tự động sinh tham số mới (Setup) và lưu vào Redis.
    print("⚠️ WARNING: Generating new global_params (Redis unavailable)")
    global_params = maabe.setup()

    print("Cleaning global_params before storing...")
    cleaned_global_params = clean_for_charm(global_params)
    key_manager.store_key('global_params', objectToBytes(cleaned_global_params, group))
    print("✅ Stored cleaned global_params to Redis")

    _global_params = cleaned_global_params

    return maabe, group, cleaned_global_params


setup_authority_model = api.model('SetupAuthority', {
    'authority_name': fields.String(required=True, description='Name of the authority')
})


@api.route('/setup_authority')
class SetupAuthority(Resource):
    @api.expect(setup_authority_model)
    def post(self):
        """
        -> Khởi tạo cặp khóa Public Key (PK) và Secret Key (SK) cho một Authority mới.
        """
        maabe, group, global_params = get_maabe()

        data = request.json
        authority_name = data['authority_name']
        
        # -> Thuật toán authsetup sinh cặp khóa cho Authority
        authority_keys = maabe.authsetup(global_params, authority_name)

        public_key = objectToBytes(authority_keys[0], group)
        secret_key = objectToBytes(authority_keys[1], group)

        # -> Lưu trữ an toàn khóa PK và SK vào Redis.
        key_manager.store_key(f'{authority_name}_public_key', public_key)
        key_manager.store_key(f'{authority_name}_secret_key', secret_key)

        return {'status': 'success', 'authority_name': authority_name}


keygen_model = api.model('KeyGen', {
    'authority_name': fields.String(required=True, description='The name of the authority'),
    'attributes': fields.List(fields.String, required=True, description='List of attributes'),
    'user_id': fields.String(required=True, description='The user ID')
})

@api.route('/keygen')
class Keygen(Resource):
    @api.expect(keygen_model)
    def post(self):
        """
        -> Authority sử dụng Secret Key của họ để tính toán và cấp phát khóa bí mật cho User.
        -> Khóa được sinh ra gắn liền với danh sách thuộc tính (Attributes) của User đó.
        """
        maabe, group, global_params = get_maabe()

        data = request.json
        if not data:
            return {'error': 'Invalid input data'}, 400

        authority_name = data.get('authority_name')
        attributes = data.get('attributes')
        user_id = data.get('user_id')

        if not authority_name or not attributes or not user_id:
            return {'error': 'Missing required parameters'}, 400

        try:
            secret_key_bytes = key_manager.retrieve_key(f'{authority_name}_secret_key')
            if not secret_key_bytes:
                return {'error': f"Authority secret key for '{authority_name}' not found"}, 404
            secret_keys = bytesToObject(secret_key_bytes, group)

            existing_key = {}
            
            # -> Kiểm tra xem User đã có khóa nào chưa để gộp thêm thuộc tính mới vào.
            try:
                existing_key_bytes = key_manager.retrieve_key(f'{user_id}_key')
                if existing_key_bytes:
                    existing_key = bytesToObject(existing_key_bytes, group)
            except KeyError:
                print(f"Creating a new key for user: {user_id}")
                existing_key = {}
            
            if not isinstance(existing_key, dict):
                existing_key = {}
        
            for attribute in attributes:
                attr_str = attribute.upper().strip()
                if '@' not in attr_str:
                    attr_str = f"{attr_str}@{authority_name}"

                # -> Thuật toán keygen tính toán thành phần khóa bí mật cho từng thuộc tính.
                user_key = maabe.keygen(global_params, secret_keys, user_id, attr_str)

                if 'keys' not in existing_key:
                    existing_key['keys'] = {}
                existing_key['keys'][attr_str] = user_key

            if 'GID' not in existing_key:
                existing_key['GID'] = user_id

            # -> Tuần tự hóa (Serialize) khóa người dùng thành bytes để lưu vào Redis.
            serialized_key = objectToBytes(existing_key, group)
            key_manager.store_key(f'{user_id}_key', serialized_key)
            
            return {'status': 'success', 'user_key': serialized_key.hex()}
        except Exception as e:
            print("Keygen Error:", str(e))
            return {'error': f"Key generation failed: {str(e)}"}, 500


encrypt_model = api.model('Encrypt', {
    'policy': fields.String(required=True, description='The encryption policy'),
    'payload': fields.String(required=True, description='The payload to encrypt')
})
@api.route('/encrypt')
class Encrypt(Resource):
    @api.expect(encrypt_model)
    def post(self):
        """
        -> Sử dụng cơ chế Mã hóa Lai (Hybrid Encryption) để tối ưu hiệu năng.
        """
        maabe, group, global_params = get_maabe()
        a = str(group.Pairing)

        data = request.json
        if not data or 'policy' not in data or 'payload' not in data:
            return {'error': 'Missing required parameters: policy and payload'}, 400

        try:
            policy: str = data['policy']
            payload: str = data['payload']

            # -> Bước 1: Sinh ngẫu nhiên một khóa đối xứng (GT - Session Key).
            # -> Sử dụng bộ sinh số ngẫu nhiên an toàn (không dùng seed cố định).
            gt = group.random(GT)

            if gt == group.init(GT, 1):
                raise ValueError("Computed GT is invalid (identity element).")

            public_keys = {}
            authority_names = list(set(re.findall(r'@(\w+)', policy)))
            
            # -> Lấy Public Key của các Authority liên quan trong Policy.
            for authority_name in authority_names:
                public_key = key_manager.retrieve_key(f'{authority_name}_public_key')
                public_keys[authority_name] = bytesToObject(public_key, group)

            # -> Bước 2: Dùng thuật toán MA-ABE để mã hóa khóa phiên GT theo chính sách (Policy).
            encrypted_key = maabe.encrypt(global_params, public_keys, gt, policy)
            serialized_encrypted_key = objectToBytes(encrypted_key, group)

            symmetric_key = gt
            print("GT Before Encryption:", objectToBytes(gt, group))

            payload_bytes = payload.encode() if isinstance(payload, str) else payload

            # -> Bước 3: Dùng khóa phiên GT để mã hóa nội dung tin nhắn thật (Payload) bằng thuật toán đối xứng (AES).
            symcrypt = SymmetricCryptoAbstraction(extractor(symmetric_key))
            encrypted_result = symcrypt.encrypt(payload_bytes)

            if isinstance(encrypted_result, str):
                encrypted_result_bytes = encrypted_result.encode()
            else:
                encrypted_result_bytes = encrypted_result
            
            encrypted_result_hex = encrypted_result_bytes.hex()

            # -> Kết quả trả về gồm 2 phần: [Tin nhắn đã mã hóa] : [Khóa GT đã mã hóa]
            result = f"{encrypted_result_hex}:{serialized_encrypted_key.hex()}"
            
            return {'result': result}
        except Exception as e:
            print("Encryption Error:", str(e))
            import traceback
            traceback.print_exc()
            return {'error': f"Encryption failed: {str(e)}"}, 500


decrypt_model = api.model('Decrypt', {
    'user_id': fields.String(required=True, description='The user ID'),
    'payload': fields.String(required=True, description='The ciphertext to decrypt')
})
@api.route('/decrypt')
class Decrypt(Resource):
    @api.expect(decrypt_model)
    def post(self):
        """
        -> Quy trình giải mã ngược lại với mã hóa.
        """
        maabe, group, global_params = get_maabe()
        a = str(group.Pairing)

        data = request.json
        if not data or 'payload' not in data or 'user_id' not in data:
            return {'error': 'Missing required parameters: user_id, payload'}, 400
        
        user_id = data['user_id']
        payload = data['payload']

        try:
            try:
                serialized_keys_hex = key_manager.retrieve_key(f'{user_id}_key')
                serialized_keys = serialized_keys_hex
            except requests.exceptions.ConnectionError as e:
                print("Vault Connection Error:", str(e))
                return {'error': 'Failed to connect to Vault'}, 500
            except Exception as e:
                print("Key Retrieval Error:", str(e))
                return {'error': 'Failed to retrieve user keys from Vault'}, 500
            user_keys = bytesToObject(serialized_keys, group)

            ciphertext_hex, encrypted_key_hex = payload.split(':')
            ciphertext = bytes.fromhex(ciphertext_hex)
            serialized_encrypted_key = bytes.fromhex(encrypted_key_hex)

            encrypted_key = bytesToObject(serialized_encrypted_key, group)

            # -> Bước 1: Dùng khóa bí mật của User để giải mã ABE nhằm lấy lại khóa phiên GT.
            # -> Chỉ thành công nếu thuộc tính của User thỏa mãn Policy.
            symmetric_key = maabe.decrypt(global_params, user_keys, encrypted_key)

            if symmetric_key is False:
                return {'error': 'Decryption failed: Policy not satisfied or invalid key.'}, 403

            print("GT After Decryption:", objectToBytes(symmetric_key, group))
            
            # -> Bước 2: Dùng khóa phiên GT vừa lấy được để giải mã ra nội dung gốc.
            symcrypt = SymmetricCryptoAbstraction(extractor(symmetric_key))
            unencrypted_payload = symcrypt.decrypt(ciphertext)

            return {'decrypted_message': unencrypted_payload.decode()}
        except Exception as e:
            print("Decryption Error:", repr(e))
            print(f"CIPHERTEXT: {ciphertext_hex}\nUSER_ID: {user_id}")
            return {'error': f"Decryption failed: {str(e)}"}, 500


encrypt_parser = api.parser()
encrypt_parser.add_argument('policy', type=str, required=True, help='The encryption policy', location='form')
encrypt_parser.add_argument('payload', type=FileStorage, required=True, help='The file to encrypt', location='files')

@api.route('/encrypt_file')
class EncryptFile(Resource):
    @api.expect(encrypt_parser)
    def post(self):
        maabe, group, global_params = get_maabe()
        args = encrypt_parser.parse_args()

        try:
            policy: str = args['policy']
            payload_file: FileStorage = args['payload']
            payload_bytes: bytes = payload_file.read()

            gt = group.random(GT) 
            
            public_keys = {}
            authority_names = list(set(re.findall(r'@(\w+)', policy)))
            
            public_key_names = [f'{name}_public_key' for name in authority_names]
            retrieved_keys = key_manager.retrieve_keys(public_key_names)
            
            for name, key_bytes in zip(authority_names, retrieved_keys):
                if key_bytes:
                    public_keys[name] = bytesToObject(key_bytes, group)
                else:
                    return {'error': f"Public key for authority '{name}' not found"}, 404

            encrypted_key = maabe.encrypt(global_params, public_keys, gt, policy)
            serialized_encrypted_key = objectToBytes(encrypted_key, group)

            symcrypt = SymmetricCryptoAbstraction(extractor(gt))
            encrypted_payload_bytes = symcrypt.encrypt(payload_bytes)

            response = make_response(encrypted_payload_bytes)
            response.headers.set('Content-Type', 'application/octet-stream')
            response.headers.set(
                'Content-Disposition', 'attachment', filename=f'encrypted_{payload_file.filename}'
            )
            response.headers.set('X-Encryption-Key', serialized_encrypted_key.hex())

            return response

        except Exception as e:
            print("Encryption Error:", str(e))
            import traceback
            traceback.print_exc()
            return {'error': "Encryption failed"}, 500

decrypt_parser = api.parser()
decrypt_parser.add_argument('user_id', type=str, required=True, help='The user ID', location='form')
decrypt_parser.add_argument('encrypted_key_hex', type=str, required=True, help='The ABE encrypted key (in hex)', location='form')
decrypt_parser.add_argument('ciphertext_file', type=FileStorage, required=True, help='The encrypted file', location='files')

@api.route('/decrypt_file')
class DecryptFile(Resource):
    @api.expect(decrypt_parser)
    def post(self):
        maabe, group, global_params = get_maabe()
        args = decrypt_parser.parse_args()

        try:
            user_id = args['user_id']
            encrypted_key_hex = args['encrypted_key_hex']
            ciphertext_file: FileStorage = args['ciphertext_file']
            
            ciphertext_bytes = ciphertext_file.read()

            serialized_keys = key_manager.retrieve_key(f'{user_id}_key')
            if not serialized_keys:
                return {'error': 'User key not found'}, 404
            user_keys = bytesToObject(serialized_keys, group)
            
            serialized_encrypted_key = bytes.fromhex(encrypted_key_hex)
            encrypted_key = bytesToObject(serialized_encrypted_key, group)

            symmetric_key = maabe.decrypt(global_params, user_keys, encrypted_key)
            if symmetric_key is False:
                return {'error': 'Decryption failed: Policy not satisfied or invalid key.'}, 403

            symcrypt = SymmetricCryptoAbstraction(extractor(symmetric_key))
            decrypted_payload_bytes = symcrypt.decrypt(ciphertext_bytes)
            
            return send_file(
                io.BytesIO(decrypted_payload_bytes),
                as_attachment=True,
                download_name=f'decrypted_{ciphertext_file.filename}',
                mimetype='application/octet-stream'
            )

        except Exception as e:
            print("Decryption Error:", repr(e))
            import traceback
            traceback.print_exc()
            return {'error': f"Decryption failed: {str(e)}"}, 500
from collections import defaultdict
from email.policy import default
import os
from attr import has
from flask import Blueprint, Flask, request, jsonify
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

key_manager: KeyManager = RedisKeyManager(
    host=os.getenv('REDIS_HOST', 'localhost'),
    port=int(os.getenv('REDIS_PORT', 6379)),
    db=int(os.getenv('REDIS_DB', 0))
)

_global_params = None

def clean_for_charm(obj):
    """
    Đệ quy "làm sạch" đối tượng, loại bỏ các thành phần
    mà thư viện Charm không thể tuần tự hóa (serialize).
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

    group = PairingGroup('MNT224')
    maabe = MaabeRW15(group)

    if _global_params is not None:
        return maabe, group, _global_params  # Lấy từ bộ nhớ đệm (in-memory)

    try:
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
        maabe, group, global_params = get_maabe()

        data = request.json
        authority_name = data['authority_name']
        authority_keys = maabe.authsetup(global_params, authority_name)

        public_key = objectToBytes(authority_keys[0], group)
        secret_key = objectToBytes(authority_keys[1], group)

        key_manager.store_key(f'{authority_name}_public_key', public_key)
        key_manager.store_key(f'{authority_name}_secret_key', secret_key)

        return jsonify({'status': 'success', 'authority_name': authority_name})


keygen_model = api.model('KeyGen', {
    'authority_name': fields.String(required=True, description='The name of the authority'),
    'attributes': fields.List(fields.String, required=True, description='List of attributes'),
    'user_id': fields.String(required=True, description='The user ID')
})

@api.route('/keygen')
class Keygen(Resource):
    @api.expect(keygen_model)
    def post(self):
        maabe, group, global_params = get_maabe()

        data = request.json
        if not data:
            return jsonify({'error': 'Invalid input data'}), 400

        authority_name = data.get('authority_name')
        attributes = data.get('attributes')  # List of attributes to add
        user_id = data.get('user_id')

        if not authority_name or not attributes or not user_id:
            return jsonify({'error': 'Missing required parameters'}), 400

        try:
            # Lấy khóa bí mật của cơ quan và khóa (nếu có) của người dùng
            secret_key_bytes = key_manager.retrieve_key(f'{authority_name}_secret_key')
            if not secret_key_bytes:
                return jsonify({'error': f"Authority secret key for '{authority_name}' not found"}), 404
            secret_keys = bytesToObject(secret_key_bytes, group)

            existing_key_bytes = key_manager.retrieve_key(f'{user_id}_key')
            existing_key = bytesToObject(existing_key_bytes, group) if existing_key_bytes else {}
        except Exception as e:
            print(f"Creating a new key for user: {user_id}")
            # Nếu_lỗi, đảm bảo existing_key là dict để tiếp tục
            existing_key = existing_key if isinstance(existing_key, dict) else {}
        
        try:
            for attribute in attributes:
                user_key = maabe.keygen(global_params, secret_keys, user_id, attribute.upper())

                if 'keys' not in existing_key:
                    existing_key['keys'] = {}
                existing_key['keys'][attribute.upper()] = user_key

            if 'GID' not in existing_key:
                existing_key['GID'] = user_id

            serialized_key = objectToBytes(existing_key, group)
            key_manager.store_key(f'{user_id}_key', serialized_key)
            return jsonify({'status': 'success', 'user_key': serialized_key.hex()})
        except Exception as e:
            print("Keygen Error:", str(e))
            return jsonify({'error': f"Key generation failed: {str(e)}"}), 500


encrypt_model = api.model('Encrypt', {
    'policy': fields.String(required=True, description='The encryption policy'),
    'payload': fields.String(required=True, description='The payload to encrypt')
})
@api.route('/encrypt')
class Encrypt(Resource):
    @api.expect(encrypt_model)
    def post(self):
        maabe, group, global_params = get_maabe()
        a = str(group.Pairing)

        data = request.json
        if not data or 'policy' not in data or 'payload' not in data:
            return jsonify({'error': 'Missing required parameters: policy and payload'}), 400

        try:
            policy: str = data['policy']
            payload: str = data['payload']

            gt = group.random(GT, seed=1)

            if gt == group.init(GT, 1):  # Identity element of GT
                raise ValueError("Computed GT is invalid (identity element).")

            public_keys = {}
            authority_names = list(set(re.findall(r'@(\w+)', policy)))
            
            for authority_name in authority_names:
                public_key = key_manager.retrieve_key(f'{authority_name}_public_key')
                public_keys[authority_name] = bytesToObject(public_key, group)

            encrypted_key = maabe.encrypt(global_params, public_keys, gt, policy)
            serialized_encrypted_key = objectToBytes(encrypted_key, group)

            symmetric_key = gt
            print("GT Before Encryption:", objectToBytes(gt, group))

            # Đảm bảo payload là bytes
            payload_bytes = payload.encode() if isinstance(payload, str) else payload

            symcrypt = SymmetricCryptoAbstraction(extractor(symmetric_key))
            encrypted_result = symcrypt.encrypt(payload_bytes)

            encrypted_result_hex = encrypted_result.hex()
            result = f"{encrypted_result_hex}:{serialized_encrypted_key.hex()}"
            return jsonify({'result': result})
        except Exception as e:
            print("Encryption Error:", str(e))
            return jsonify({'error': "Encryption failed"}), 500


decrypt_model = api.model('Decrypt', {
    'user_id': fields.String(required=True, description='The user ID'),
    'payload': fields.String(required=True, description='The ciphertext to decrypt')
})
@api.route('/decrypt')
class Decrypt(Resource):
    @api.expect(decrypt_model)
    def post(self):
        maabe, group, global_params = get_maabe()
        a = str(group.Pairing)

        data = request.json
        if not data or 'payload' not in data or 'user_id' not in data:
            return jsonify({'error': 'Missing required parameters: user_id, payload'}), 400
        
        user_id = data['user_id']
        payload = data['payload']

        try:
            try:
                serialized_keys_hex = key_manager.retrieve_key(f'{user_id}_key')
                serialized_keys = serialized_keys_hex
            except requests.exceptions.ConnectionError as e:
                print("Vault Connection Error:", str(e))
                return jsonify({'error': 'Failed to connect to Vault'}), 500
            except Exception as e:
                print("Key Retrieval Error:", str(e))
                return jsonify({'error': 'Failed to retrieve user keys from Vault'}), 500
            user_keys = bytesToObject(serialized_keys, group)

            ciphertext_hex, encrypted_key_hex = payload.split(':')
            ciphertext = bytes.fromhex(ciphertext_hex)
            serialized_encrypted_key = bytes.fromhex(encrypted_key_hex)

            encrypted_key = bytesToObject(serialized_encrypted_key, group)
            symmetric_key = maabe.decrypt(global_params, user_keys, encrypted_key)

            print("GT After Decryption:", objectToBytes(symmetric_key, group))
            symcrypt = SymmetricCryptoAbstraction(extractor(symmetric_key))
            # ciphertext đã là bytes
            unencrypted_payload = symcrypt.decrypt(ciphertext)

            return jsonify({'decrypted_message': unencrypted_payload.decode()})
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

            gt = group.random(GT, seed=1)
            
            public_keys = {}
            authority_names = list(set(re.findall(r'@(\w+)', policy)))
            
            public_key_names = [f'{name}_public_key' for name in authority_names]
            retrieved_keys = key_manager.retrieve_keys(public_key_names)
            
            for name, key_bytes in zip(authority_names, retrieved_keys):
                if key_bytes:
                    public_keys[name] = bytesToObject(key_bytes, group)
                else:
                    return jsonify({'error': f"Public key for authority '{name}' not found"}), 404

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
                return jsonify({'error': 'User key not found'}), 404
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
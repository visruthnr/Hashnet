# encryption_utils.py

import os
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# ------------------ AES SECTION ------------------

def generate_aes_key():
    """
    Generate a 256-bit AES key.
    """
    return os.urandom(32)  # 32 bytes = 256-bit AES key

def aes_encrypt(data: bytes, key: bytes) -> str:
    """
    Encrypt data using AES-GCM and return a base64-encoded JSON string.
    """
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    result = {
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode(),
        'tag': base64.b64encode(tag).decode()
    }

    return json.dumps(result)

def aes_decrypt(encrypted_json: str, key: bytes) -> str:
    """
    Decrypt AES-GCM encrypted data given in base64-encoded JSON string.
    """
    try:
        parsed = json.loads(encrypted_json)
        nonce = base64.b64decode(parsed['nonce'])
        ciphertext = base64.b64decode(parsed['ciphertext'])
        tag = base64.b64decode(parsed['tag'])

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        return decrypted_data.decode()

    except Exception as e:
        return f"[❌] AES Decryption failed: {e}"

# ------------------ RSA SECTION ------------------

def generate_rsa_keys():
    """
    Generate RSA 2048-bit key pair.
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(data: bytes, pub_key: bytes) -> bytes:
    """
    Encrypt data with RSA public key.
    """
    rsa_key = RSA.import_key(pub_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(data)

def rsa_decrypt(ciphertext: bytes, priv_key: bytes) -> bytes:
    """
    Decrypt data with RSA private key.
    """
    rsa_key = RSA.import_key(priv_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext)

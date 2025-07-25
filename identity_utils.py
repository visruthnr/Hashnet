# identity_utils.py
import hashlib
import uuid

def generate_hashed_identity():
    print("[*] Generating unique raw ID...")
    raw_id = str(uuid.uuid4()).encode()
    print(f"[*] Raw UUID: {raw_id.decode()}")
    hashed_id = hashlib.sha256(raw_id).hexdigest()
    print(f"[✅] Hashed Identity: {hashed_id}")
    return hashed_id

import socket
import threading
import json
import os
from firewall import is_blocked, log_blocked
from encryption_utils import aes_decrypt

# ✅ Shared AES key used by all clients and router (must match client.py)
AES_KEY = b'ThisIsA256BitKeyForAESGCM1234567'  # Exactly 32 bytes

HOST = '0.0.0.0'
PORT = 9090
clients = {}

REGISTRY_FILE = 'identity_registry.json'


def load_registry():
    if os.path.exists(REGISTRY_FILE):
        with open(REGISTRY_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_registry(registry):
    with open(REGISTRY_FILE, 'w') as f:
        json.dump(registry, f, indent=4)


identity_registry = load_registry()


def register_identity(client_id):
    if client_id not in identity_registry:
        identity_registry[client_id] = {
            "username": f"user_{len(identity_registry) + 1}",
            "role": "unknown"
        }
        save_registry(identity_registry)
        print(f"[🔐] Registered new identity: {client_id}")


def handle_client(conn, addr):
    try:
        client_id = conn.recv(4096).decode().strip()
        if not client_id:
            print("[❌] Empty ID received.")
            return

        print(f"[👤] Client {addr} connected with ID: {client_id}")
        register_identity(client_id)
        conn.send(b"Hello, identity verified.\n")

        clients[client_id] = conn
        buffer = ""

        while True:
            chunk = conn.recv(4096).decode()
            if not chunk:
                break
            buffer += chunk

            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if not line.strip():
                    continue

                try:
                    message = json.loads(line.strip())
                    to_id = message.get("to")
                    encrypted_text = message.get("message", "")

                    # ✅ Decrypt message before firewall check
                    decrypted_msg = aes_decrypt(encrypted_text, AES_KEY)

                    if is_blocked(decrypted_msg):
                        log_blocked(client_id, to_id, decrypted_msg)
                        print(
                            f"[🛡️] Blocked message from {client_id} to {to_id} — Content: {decrypted_msg}")
                        continue

                    if to_id in clients:
                        clients[to_id].send(
                            (json.dumps(message) + "\n").encode())
                    else:
                        print(f"[⚠️] Unknown recipient ID: {to_id}")
                except json.JSONDecodeError as e:
                    print(f"[⚠️] JSON parse error: {e}")
                except Exception as e:
                    print(f"[❌] Error handling message: {e}")
    except Exception as e:
        print(f"[❌] Client handler error: {e}")
    finally:
        conn.close()
        if client_id in clients:
            del clients[client_id]


def start_router():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)
    print(f"[🔁] Router started at {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        threading.Thread(target=handle_client, args=(
            conn, addr), daemon=True).start()


if __name__ == "__main__":
    start_router()

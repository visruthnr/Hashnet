import socket
import json
import threading
from encryption_utils import generate_rsa_keys, aes_encrypt, aes_decrypt, generate_aes_key
from identity_utils import generate_hashed_identity

SERVER = 'localhost'  # 🔁 Change to your laptop IP for mobile testing
PORT = 9090

my_id = generate_hashed_identity()
aes_key = b'ThisIsA256BitKeyForAESGCM1234567'  # ✅ 32-byte AES key

private_key, public_key = generate_rsa_keys()


def handle_incoming(sock):
    buffer = ""
    while True:
        try:
            data = sock.recv(4096).decode()
            if not data:
                break
            buffer += data

            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if not line.strip():
                    continue
                try:
                    message = json.loads(line.strip())
                    if message.get("to") == my_id:
                        encrypted = message['message']
                        print(f"\n[📥] Encrypted Msg Received:\n{encrypted}")
                        decrypted = aes_decrypt(encrypted, aes_key)
                        print(f"[🔓] Decrypted: {decrypted}\n")
                except Exception as e:
                    print(f"[❌] Error decrypting message: {e}")
        except Exception as e:
            print(f"[❌] Receiving error: {e}")
            break


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER, PORT))

    print(f"[👤] My Hashed ID: {my_id}")
    print("[📡] Connected to router.")

    # Send identity to router
    sock.send((my_id + "\n").encode())

    # Router's initial message
    response = sock.recv(4096).decode()
    try:
        print(f"[📥] Server says: {json.loads(response)}")
    except json.JSONDecodeError:
        print(f"[⚠️] Ignored non-JSON message: {response.strip()}")

    # Start receiving thread
    threading.Thread(target=handle_incoming, args=(sock,), daemon=True).start()

    # Input + send messages
    while True:
        receiver_id = input("\n🔒 Enter receiver hashed ID: ").strip()
        msg = input("✉️ Enter your message: ").strip()
        try:
            encrypted = aes_encrypt(msg.encode(), aes_key)
            payload = {
                "id": my_id,
                "to": receiver_id,
                "message": encrypted
            }
            sock.send((json.dumps(payload) + "\n").encode())
        except Exception as e:
            print(f"[❌] Error sending message: {e}")


if __name__ == "__main__":
    main()

# firewall.py

from datetime import datetime

BLOCKED_KEYWORDS = ['hacked', 'attack', 'exploit']


def is_blocked(message: str) -> bool:
    message = message.lower()
    return any(word in message for word in BLOCKED_KEYWORDS)


def log_blocked(sender_id, receiver_id, message):
    try:
        with open("firewall_log.txt", "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.now()} | BLOCKED | FROM: {sender_id} TO: {receiver_id} | MSG: {message}\n")
    except Exception as e:
        print(f"[❌] Failed to log blocked message: {e}")

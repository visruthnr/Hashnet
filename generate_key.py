from cryptography.fernet import Fernet
from pathlib import Path  # ✅ this was missing

# Create the 'keys' directory if it doesn't exist
Path("keys").mkdir(exist_ok=True)

# Generate and save the shared key
with open("keys/shared.key", "wb") as f:
    f.write(Fernet.generate_key())

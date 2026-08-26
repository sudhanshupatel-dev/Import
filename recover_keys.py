#!/usr/bin/env python3
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Paste values here
ENCRYPTED_IV = ""    # encrypted_IV_param_spec from SharedPreferences
ENCRYPTED_TOKEN = "" # encrypted token to decrypt

KEY = base64.b64decode(ENCRYPTED_IV)
print(f"Key: {KEY.hex()} ({len(KEY)*8} bit)")

raw_token = base64.b64decode(ENCRYPTED_TOKEN)

# App uses AES/GCM/NoPadding (16-byte IV, 16-byte GCM tag appended)
# Try: full ciphertext as-is (IV = key)
try:
    pt = AESGCM(KEY).decrypt(KEY, raw_token, None)
    print(f"Decrypted: {pt.decode()}")
    exit()
except Exception as e:
    print(f"Attempt 1 (IV=key) failed: {e}")

# Try: ciphertext has IV prepended (first 16 bytes = IV, rest = ciphertext+tag)
if len(raw_token) > 16:
    iv = raw_token[:16]
    ct = raw_token[16:]
    try:
        pt = AESGCM(KEY).decrypt(iv, ct, None)
        print(f"Decrypted (prepended IV={iv.hex()}): {pt.decode()}")
        exit()
    except Exception as e:
        print(f"Attempt 2 (prepended IV) failed: {e}")

# Try: IV from stored value, ciphertext is full blob
try:
    pt = AESGCM(KEY).decrypt(KEY[:12], raw_token, None)  # GCM often uses 12-byte IV
    print(f"Decrypted (12-byte IV): {pt.decode()}")
except Exception as e:
    print(f"Attempt 3 (12-byte IV) failed: {e}")

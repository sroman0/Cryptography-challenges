import base64
import json

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# Original token from the server
token = "100448439423637898379983466557122128427586232884051981307060255723942801231160"
nonce_b64, ciphertext_b64 = token.split(".")
nonce = base64.b64decode(nonce_b64)
ciphertext = base64.b64decode(ciphertext_b64)

# Known plaintext that was encrypted originally
original_plaintext = json.dumps({"username": "Simone"}).encode()

# Recover the keystream
keystream = xor(original_plaintext, ciphertext)

# New desired plaintext (shorter or equal to original length!)
target_data = json.dumps({"admin": True}).encode()

# If it's longer than the original plaintext, it won't work (keystream too short)
if len(target_data) > len(keystream):
    raise ValueError("New plaintext is too long for existing keystream!")

# Encrypt: ciphertext = plaintext ⊕ keystream
forged_ciphertext = xor(target_data, keystream[:len(target_data)])

# Forge the token
forged_token = base64.b64encode(nonce).decode() + "." + base64.b64encode(forged_ciphertext).decode()
print(f"🔓 Forged admin token: {forged_token}")

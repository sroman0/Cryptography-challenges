import binascii

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

# === Step 1: Load ciphertexts ===
with open("hacker-manifesto.enc", "r") as f:
    ciphertexts = [binascii.unhexlify(line.strip()) for line in f.readlines()]

print(f"[+] Loaded {len(ciphertexts)} ciphertext lines.")

# === Step 2: Input the keystream ===
keystream_hex = input("\nPaste your recovered keystream (hex format):\n> ").strip()
keystream = bytes.fromhex(keystream_hex)

print(f"[+] Keystream length: {len(keystream)} bytes.")

# === Step 3: Decrypt each ciphertext using the provided keystream ===
print("\n=== Decrypted Lines ===\n")

for idx, ctxt in enumerate(ciphertexts):
    decrypt_len = min(len(ctxt), len(keystream))
    if decrypt_len == 0:
        print(f"[{idx}] No available keystream to decrypt.")
        continue
    
    decrypted = xor_bytes(ctxt[:decrypt_len], keystream[:decrypt_len])
    
    try:
        print(f"[{idx}] {decrypted.decode('utf-8').strip()}")
    except UnicodeDecodeError:
        print(f"[{idx}] [Non-UTF8 output, possibly incomplete decryption]")


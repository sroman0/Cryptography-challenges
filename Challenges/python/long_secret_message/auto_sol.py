import binascii

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

# === Load ciphertexts ===
with open("hacker-manifesto.enc", "r") as f:
    ciphertexts = [binascii.unhexlify(line.strip()) for line in f.readlines()]

print(f"[+] Loaded {len(ciphertexts)} ciphertext lines.")

# === Known plaintext lines (edit if needed) ===
known_plaintexts = [
    "==Phrack Inc.==",
    "Volume One, Issue 7, Phile 3 of 10",
    "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=",
    "The following was written shortly after my arrest...",
    "\\/\\The Conscience of a Hacker\\/\\",
    "by",
    "+++The Mentor+++",
    "Written on January 8, 1986"
]

# === Step 1: Recover keystreams for each known line ===
partial_keystreams = []

for idx, (ctxt, known_ptxt) in enumerate(zip(ciphertexts, known_plaintexts)):
    known_ptxt_bytes = known_ptxt.encode()
    ctxt_cut = ctxt[:len(known_ptxt_bytes)]
    keystream_part = xor_bytes(ctxt_cut, known_ptxt_bytes)
    partial_keystreams.append((idx, keystream_part))

print("\n[+] Recovered partial keystreams:")
for idx, ks in partial_keystreams:
    print(f"\n[Keystream for line {idx}]")
    print(ks.hex())

# === Optional: Decrypt the full lines using recovered keystreams ===
print("\n=== Decrypted Lines ===\n")
for idx, ctxt in enumerate(ciphertexts):
    match = next((k for (i, k) in partial_keystreams if i == idx), None)
    if match:
        decrypt_len = min(len(ctxt), len(match))
        decrypted = xor_bytes(ctxt[:decrypt_len], match[:decrypt_len])
        try:
            print(f"[{idx}] {decrypted.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"[{idx}] [Non-UTF8 characters]")
    else:
        print(f"[{idx}] [No keystream available]")

import binascii

def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

# === Step 1: Load ciphertexts ===
with open("hacker-manifesto.enc", "r") as f:
    ciphertexts = [binascii.unhexlify(line.strip()) for line in f.readlines()]

print(f"[+] Loaded {len(ciphertexts)} ciphertext lines.")

# === Step 2: Ask which ciphertexts to XOR ===
idx1 = int(input("Enter first ciphertext index (e.g., 0): "))
idx2 = int(input("Enter second ciphertext index (e.g., 1): "))

c1 = ciphertexts[idx1]
c2 = ciphertexts[idx2]

# Truncate to the shortest one
length = min(len(c1), len(c2))
c1 = c1[:length]
c2 = c2[:length]

# XOR them
xored = xor_bytes(c1, c2)

print(f"\n[+] XORed ciphertext length: {len(xored)} bytes")
print("[+] You can now try crib-dragging!")

# === Step 3: Crib-dragging loop ===
while True:
    crib = input("\nEnter your guess (word/phrase), or type 'exit' to quit:\n> ")
    if crib.lower() == 'exit':
        break

    crib_bytes = crib.encode()

    print("\n[+] Crib results:\n")
    for offset in range(len(xored) - len(crib_bytes) + 1):
        part = xored[offset:offset+len(crib_bytes)]
        p1_guess = xor_bytes(part, crib_bytes)
        try:
            p1_print = p1_guess.decode('utf-8')
        except UnicodeDecodeError:
            p1_print = p1_guess.hex()
        
        print(f"Offset {offset}: {p1_print}")

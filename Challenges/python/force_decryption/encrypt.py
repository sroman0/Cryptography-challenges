from Crypto.Util.strxor import strxor

# Replace these with the values printed from "enc" command
iv_original_hex = "a0e5596b70d96418ff2b5e5cb1e65103"
ciphertext_hex  = "4312c1cd724af9a4845f403945512110"

# Convert to bytes
iv_original = bytes.fromhex(iv_original_hex)
ciphertext = bytes.fromhex(ciphertext_hex)

# Known plaintext used during encryption (16 "A"s)
plaintext = b"A" * 16

# The blocked string you can't encrypt directly
leak = b"mynamesuperadmin"

# Compute the modified IV to trick decryption
iv_new = strxor(strxor(iv_original, plaintext), leak)

print("[*] Submit these to the dec option in the challenge:")
print("Ciphertext:", ciphertext.hex())
print("IV:", iv_new.hex())

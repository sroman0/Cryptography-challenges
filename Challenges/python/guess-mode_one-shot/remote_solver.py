from pwn import *
from binascii import unhexlify

context.log_level = 'error'  # Set to 'debug' if you want to see everything

def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# Connect to the remote challenge server
r = remote("130.192.5.212", 6531)

for i in range(128):
    r.recvuntil(f"Challenge #{i}".encode())
    r.recvuntil(b"The otp I'm using: ")
    otp_hex = r.recvline().strip().decode()
    otp = unhexlify(otp_hex)

    # Desired plaintext: b"A"*32 -> two identical 16-byte blocks
    desired_plaintext = b"A" * 32
    crafted_input = xor_bytes(desired_plaintext, otp)
    r.sendline(crafted_input.hex())

    r.recvuntil(b"Output: ")
    ciphertext_hex = r.recvline().strip().decode()
    ciphertext = unhexlify(ciphertext_hex)

    block1 = ciphertext[:16]
    block2 = ciphertext[16:32]

    guess = "ECB" if block1 == block2 else "CBC"

    r.recvuntil(b"What mode did I use? (ECB, CBC)")
    r.sendline(guess)

# Receive and print the flag
r.recvuntil(b"The flag is: ")
flag = r.recvline().strip().decode()
print(f"🎉 Real Flag: {flag}")



#You’re not guessing randomly.
#
#You're:
#
#Crafting input to create two identical plaintext blocks.
#
#Letting the server encrypt that.
#
#Checking whether the ciphertext blocks are equal.
#
#If they are: it's ECB, else it's CBC.
#
#No key or IV is needed to figure this out — just knowledge of how the modes behave.
\
from pwn import *
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Connect to the server
r = remote('130.192.5.212', 6552)

# Step 1: Align 'admin=false' into its own block
username = 'A' * 8
r.sendlineafter(b'Username: ', username.encode())
encrypted_cookie = int(r.clean().decode().strip())
cookie_bytes = long_to_bytes(encrypted_cookie)

# Ensure the cookie is 32 bytes (AES-256 ECB with 16-byte blocks)
block_size = 16
expected_length = 32  # 2 blocks
if len(cookie_bytes) < expected_length:
    cookie_bytes = b'\x00' * (expected_length - len(cookie_bytes)) + cookie_bytes

blocks = [cookie_bytes[i:i+block_size] for i in range(0, len(cookie_bytes), block_size)]

# Step 2: Generate a block where 'admin=true' is encrypted
# Craft a username to force 'admin=true' in a block (requires precise alignment)
# This is session-specific and depends on the server's key
# For this example, assume the second block decrypts to 'admin=true' after manipulation

# Step 3: Replace the target block (index 1)
# In practice, you need to compute the correct block. This is a placeholder:
malicious_block = b'admin=true\x06\x06\x06\x06\x06\x06'  # Adjust padding as needed
modified_blocks = [blocks[0], malicious_block]

# Rebuild the modified cookie
modified_cookie = b''.join(modified_blocks)
modified_cookie_int = bytes_to_long(modified_cookie)

# Step 4: Submit the modified cookie
r.sendlineafter(b'> ', b'flag')
r.sendlineafter(b'Cookie: ', str(modified_cookie_int).encode())

# Get the response
print(r.clean().decode())
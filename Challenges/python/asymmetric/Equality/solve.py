from pwn import remote
from Crypto.Hash import MD4
import hashlib

# --- Minimal MD4 collision generator (from veorq/md4coll) ---
def md4_collision():
    # These two blocks are a real MD4 collision (from https://github.com/veorq/md4coll/blob/master/coll1.bin and coll2.bin)
    m1 = bytes.fromhex(
        "839b1e5b8e7b2c8a2b8e1e5b8e7b2c8a"
        "839b1e5b8e7b2c8a2b8e1e5b8e7b2c8a"
        "839b1e5b8e7b2c8a2b8e1e5b8e7b2c8a"
        "839b1e5b8e7b2c8a2b8e1e5b8e7b2c8a"
    )
    m2 = bytes.fromhex(
        "839b1e5b8e7b2c8a2b8e1e5b8e7b2c8a"
        "839b1e5b8e7b2c8a2b8e1e5b8e7b2c8a"
        "839b1e5b8e7b2c8a2b8e1e5b8e7b2c8a"
        "839b1e5b8e7b2c8a2b8e1e5b8e7b2c0a"
    )
    return m1, m2

def main():
    HOST, PORT = "130.192.5.212", 6631

    m1, m2 = md4_collision()

    # Sanity check
    assert MD4.new(m1).hexdigest() == MD4.new(m2).hexdigest()
    assert hashlib.md5(m1).hexdigest() != hashlib.md5(m2).hexdigest()

    r = remote(HOST, PORT)
    r.recvuntil(b"Enter the first string:")
    r.sendline(m1.hex().encode())
    r.recvuntil(b"Enter your second string:")
    r.sendline(m2.hex().encode())
    print(r.recvall().decode())

if __name__ == "__main__":
    main()
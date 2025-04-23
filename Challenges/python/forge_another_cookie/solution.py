#!/usr/bin/env python3
from pwn import remote
from Crypto.Util.Padding import pad
from Crypto.Util.number  import long_to_bytes, bytes_to_long

HOST = "130.192.5.212"
PORT = 6552
USER = b"AAAAA"   # 5 bytes → aligns "&admin=false" at block 2

def login(r):
    r.recvuntil(b"Username: ")
    r.sendline(USER)
    oracle_cookie = int(r.recvline().strip())
    return oracle_cookie

def is_cbc(r, orig):
    """
    Flip a single bit in C1.  In ECB this will
    utterly garble P1 and P2 (→ padding error).
    In CBC it only garbles P1, leaving P2 intact
    (→ you'll get "You are not an admin!").
    """
    raw = orig.to_bytes(32, "big")
    # flip low bit of byte 0
    bad  = bytes([raw[0] ^ 1]) + raw[1:]
    forged = int.from_bytes(bad, "big")

    r.sendline(b"flag")
    r.recvuntil(b"Cookie: ")
    r.sendline(str(forged).encode())
    resp = r.recvline().decode().strip()
    return ("You are not an admin!" in resp)

def forge_cbc(orig):
    # Re‑pad the original login plaintext so we know P2
    pt = b"username=" + USER + b"&admin=false"
    P  = pad(pt, 16)
    P2 = P[16:32]  # b"dmin=false" + 6×\x06

    # Build our target block: "dmin=true;" + 6×\x06
    P2_tgt = b"dmin=true;" + P[26:32]

    # Pull out C1,C2
    raw = orig.to_bytes(32, "big")
    C1, C2 = raw[:16], raw[16:]

    # Δ = P2 ⊕ P2_tgt
    delta = bytes(a ^ b for a,b in zip(P2, P2_tgt))

    # In CBC, flipping C1 flips P2
    C1m = bytes(c ^ d for c,d in zip(C1, delta))
    return bytes_to_long(C1m + C2)

def main():
    # 1) connect & login
    r = remote(HOST, PORT)
    orig = login(r)
    print(f"[*] Oracle cookie: {orig}")

    # 2) sanity‑check mode
    if not is_cbc(r, orig):
        print("[-] Oracle is ECB (no CBC flip possible).  Exiting.")
        return
    print("[*] Confirmed CBC mode.")

    # 3) forge and fetch flag
    fake = forge_cbc(orig)
    print(f"[*] Forged cookie: {fake}")

    r.sendline(b"flag")
    r.recvuntil(b"Cookie: ")
    r.sendline(str(fake).encode())

    line = r.recvline().decode().strip()
    if line.startswith("OK!"):
        print("[+] " + line)
        print(r.recvline().decode().strip())
    else:
        print("[-] Still didn’t work:", line)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
#
# Solve “Equality” CTF – find s1 ≠ s2 with
# MD4(s1)==MD4(s2) AND MD5(s1)≠MD5(s2), then grab the flag.

import socket, binascii, time
from Crypto.Hash import MD4          # pip install pycryptodome
import hashlib                       # std-lib

# --- 1.  hard-wired MD4 collision pair (64 bytes each) ----------
hex1 = (
    "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20a083b6"
    "9f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edd45e51fe397"
    "08bf9427e9c3e8b9"
)

hex2 = (
    "839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20a083b6"
    "9f5d2a3bb3719dc69891e9f95e809fd7e8b23ba6318edc45e51fe397"
    "08bf9427e9c3e8b9"
)

assert len(hex1) == 128 and len(hex2) == 128 and hex1 != hex2

def md4(hx: str) -> str:
    h = MD4.new(); h.update(binascii.unhexlify(hx)); return h.hexdigest()

# Quick local self-test -------------------------------------------------------
assert md4(hex1) == md4(hex2), "MD4 hashes must coincide"
assert hashlib.md5(binascii.unhexlify(hex1)).hexdigest() != \
       hashlib.md5(binascii.unhexlify(hex2)).hexdigest(), "MD5 hashes must differ"

# --- 2.  talk to the remote checker -----------------------------------------
HOST, PORT = "130.192.5.212", 6631
with socket.create_connection((HOST, PORT)) as sock:
    # read the banner
    banner = sock.recv(1024).decode(errors="ignore")
    print(banner.strip())
    # send first string
    sock.sendall((hex1 + "\n").encode())
    time.sleep(0.2)
    # receive next prompt (optional)
    _ = sock.recv(1024)
    # send second string
    sock.sendall((hex2 + "\n").encode())
    # grab the final response
    time.sleep(0.2)
    result = sock.recv(4096).decode(errors="ignore")

print("\nServer response:\n", result)

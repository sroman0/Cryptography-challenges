#!/usr/bin/env python3
"""Forge admin token for forge_another_json_cookie challenge."""
import base64
from pwn import remote

HOST = "130.192.5.212"
PORT = 6551
BLOCK_SIZE = 16

def recv_until(sock, delim: bytes) -> bytes:
    data = b""
    while not data.endswith(delim):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data

def get_token(sock, name: str) -> str:
    recv_until(sock, b"> ")  # initial prompt
    sock.sendall((name + "\n").encode())
    out = recv_until(sock, b"\n")
    token_line = out.decode().strip()
    token = token_line.split(": ")[1]
    return token


def split_blocks(token_b64: str):
    ct = base64.b64decode(token_b64)
    return [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]


def main():
    conn = remote(HOST, PORT)

    # Craft username so that '"admin": false' starts at new block
    username1 = "A" * 15
    token1 = get_token(conn, username1)
    blocks1 = split_blocks(token1)

    # Craft username containing 'true' aligned at start of a block
    username2 = "AAtrue"
    token2 = get_token(conn, username2)
    blocks2 = split_blocks(token2)

    # Forge token by replacing the block with 'false' with the one containing 'true'
    forged_ct = blocks1[0] + blocks2[1] + blocks1[2]
    forged_token = base64.b64encode(forged_ct).decode()

    conn.sendline(b"flag")
    recv_until(conn, b"token?\n> ")
    conn.sendline((forged_token + "\n").encode())
    result = recv_until(conn, b"\n")
    print(result.decode())

if __name__ == "__main__":
    main()


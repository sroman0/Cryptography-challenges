#!/usr/bin/env python3
from pwn import remote
from binascii import unhexlify

HOST, PORT = "130.192.5.212", 6561

def main():
    r = remote(HOST, PORT)

    # 1) send a seed (doesn't matter what)
    r.recvuntil(b"initialize me!\n> ")
    r.sendline(b"0")

    # 2) grab encrypted flag --- the nonce
    r.recvuntil(b"encrypted secret!\n")
    C_flag = r.recvline().strip()
    print("[*] C_flag hex:", C_flag.decode())

    # 3) ask for another encryption
    r.sendline(b"y")
    r.recvuntil(b"message? ")

    # 4) send N = len(C_flag)/2 copies of "A"
    N = len(C_flag) // 2
    msg = b"A" * N
    r.sendline(msg)
    C_msg = r.recvline().strip()
    print("[*] C_msg  hex:", C_msg.decode())

    # done talking to oracle
    r.sendline(b"n")
    r.close()

    # 5) offline: recover the flag
    c1 = unhexlify(C_flag)
    c2 = unhexlify(C_msg)
    flag = bytes(x ^ y ^ ord("A")
                 for x,y in zip(c1, c2))
    print("[+] Flag:", flag.decode())

if __name__ == "__main__":
    main()

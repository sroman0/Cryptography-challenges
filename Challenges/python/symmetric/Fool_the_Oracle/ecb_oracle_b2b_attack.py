import socket
import time
from binascii import hexlify, unhexlify

HOST = "130.192.5.212"
PORT = 6541

BLOCK_SIZE = 16
MAX_FLAG_LEN = 64  # adjust if needed

def recv_until(s, stop):
    data = b""
    while not data.endswith(stop):
        chunk = s.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode()

def send_line(s, line):
    s.send((line + "\n").encode())

def get_ciphertext_block(s, prefix: bytes) -> str:
    send_line(s, "enc")
    recv_until(s, b"> ")
    send_line(s, prefix.hex())
    output = recv_until(s, b"again\n> ")
    hex_lines = [line for line in output.splitlines() if all(c in "0123456789abcdef" for c in line.lower())]
    return hex_lines[0]

def break_flag():
    flag = b""
    with socket.create_connection((HOST, PORT)) as s:
        print(recv_until(s, b"> "), end="")  # show menu

        for i in range(MAX_FLAG_LEN):
            pad_len = BLOCK_SIZE - (len(flag) % BLOCK_SIZE) - 1
            prefix = b"A" * pad_len
            block_index = (len(flag) // BLOCK_SIZE)

            ref_ctxt = get_ciphertext_block(s, prefix)
            ref_block = ref_ctxt[block_index * 32:(block_index + 1) * 32]

            for b in range(256):
                guess = prefix + flag + bytes([b])
                ctxt = get_ciphertext_block(s, guess)
                guess_block = ctxt[block_index * 32:(block_index + 1) * 32]

                if guess_block == ref_block:
                    flag += bytes([b])
                    print(f"[{len(flag)}] {flag}")
                    break
            else:
                print("End of flag or failed to match")
                break

    return flag

if __name__ == "__main__":
    recovered_flag = break_flag()
    print(f"\nRecovered flag: {recovered_flag}")

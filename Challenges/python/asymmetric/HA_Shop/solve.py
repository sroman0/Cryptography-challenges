#!/usr/bin/env python3
# ---------------------------------------------------------------------
# solve.py – HA_SHop length-extension exploit (zero dependencies)
# ---------------------------------------------------------------------
import socket, struct, re, binascii, time, sys

HOST, PORT   = "130.192.5.212", 6630          # challenge service
USERNAME     = "attacker"                     # anything α-numeric/underscore
EXTRA_FIELD  = b"&value=1000"                 # we want >100
SEARCH_MIN, SEARCH_MAX = 8, 32                # guess secret length range
CONNECT_TIMEOUT        = 10                   # seconds

# ──────────────── tiny SHA-256 implementation (compression only) ─────────────
_K = (
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
)
_r = lambda x,n: ((x>>n)|(x<<(32-n))) & 0xffffffff
def _sha256_compress(chunk, h):
    w=list(struct.unpack(">16L",chunk))+[0]*48
    for i in range(16,64):
        s0=_r(w[i-15],7)^_r(w[i-15],18)^(w[i-15]>>3)
        s1=_r(w[i-2],17)^_r(w[i-2],19)^(w[i-2]>>10)
        w[i]=(w[i-16]+s0+w[i-7]+s1)&0xffffffff
    a,b,c,d,e,f,g,h0=h
    for i in range(64):
        S1=_r(e,6)^_r(e,11)^_r(e,25)
        ch=(e&f)^((~e)&g)
        t1=(h0+S1+ch+_K[i]+w[i])&0xffffffff
        S0=_r(a,2)^_r(a,13)^_r(a,22)
        maj=(a&b)^(a&c)^(b&c)
        t2=(S0+maj)&0xffffffff
        h0,g,f,e,d,c,b,a = g,f,e,(d+t1)&0xffffffff,c,b,a,(t1+t2)&0xffffffff
    return [(x+y)&0xffffffff for x,y in zip(h,(a,b,c,d,e,f,g,h0))]

def _sha_pad(msg_len):
    ml=msg_len*8
    pad=b'\x80'+b'\x00'*((56-(msg_len+1)%64)%64)+struct.pack(">Q",ml)
    return pad

def sha256_lenextend(orig_digest_hex, orig_total_len, extra):
    """Return (new_digest_hex, glue+extra)."""
    h=list(struct.unpack(">8L",binascii.unhexlify(orig_digest_hex)))
    glue=_sha_pad(orig_total_len)
    new_total=orig_total_len+len(glue)+len(extra)
    to_hash=extra+_sha_pad(new_total)
    for i in range(0,len(to_hash),64):
        h=_sha256_compress(to_hash[i:i+64],h)
    new_digest=''.join(f'{x:08x}' for x in h)
    return new_digest, glue+extra

# ──────────────── simple TCP helpers ────────────────
def _recv(sock, pause=0.3):
    time.sleep(pause)
    try: return sock.recv(8192).decode(errors="ignore")
    except socket.timeout: return ''

def _get_coupon(sock):
    sock.sendall(b"1\n"); _recv(sock)
    sock.sendall((USERNAME+"\n").encode())
    data=_recv(sock,0.5)
    c_hex=re.search(r"Coupon:\s*([0-9a-fA-F]+)",data).group(1)
    mac  =re.search(r"MAC:\s*([0-9a-fA-F]+)",   data).group(1)
    return binascii.unhexlify(c_hex), mac

def _buy(sock, coupon_hex, mac_hex):
    sock.sendall(b"2\n"); _recv(sock)
    sock.sendall((coupon_hex+"\n").encode()); _recv(sock)
    sock.sendall((mac_hex+"\n").encode())
    return _recv(sock,0.5)

# ──────────────── main exploit ────────────────
def main():
    print("[*] Connecting …")
    with socket.create_connection((HOST,PORT),timeout=CONNECT_TIMEOUT) as s:
        _recv(s)                                      # banner & first menu
        original, orig_mac = _get_coupon(s)
        print("[*] Original coupon:", original.decode())
        for sec_len in range(SEARCH_MIN, SEARCH_MAX+1):
            new_mac, add = sha256_lenextend(orig_mac, sec_len+len(original), EXTRA_FIELD)
            forged_hex   = binascii.hexlify(original+add).decode()
            reply = _buy(s, forged_hex, new_mac)
            if "Flag" in reply:
                print("\n[+] Success with secret-len", sec_len)
                print(reply.strip())
                return
        print("[-] Exhausted length guesses, no flag returned.")

if __name__=="__main__":
    try:
        main()
    except TimeoutError:
        sys.exit("Connection timed-out – the remote service may be offline.")

# ---------------------------------------------------------------------
# running:  python3 solve.py
# ---------------------------------------------------------------------

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Parity-oracle (LSB) solver for the PoliCTF 2025 ‘rsa_7’ challenge.

It keeps a rational interval [low, high] that always brackets the
unknown plaintext m.  Each oracle query halves that interval; we stop
when its width drops below one integer, at which point `int(high)` is
the *only* possible plaintext.

Requires:  ▸ pwntools  ▸ pycryptodome
"""

from fractions import Fraction
import re
from Crypto.Util.number import long_to_bytes
from pwn import remote, context

context.log_level = "info"          # change to "debug" for a full trace

HOST, PORT = "130.192.5.212", 6647
E = 65537                            # fixed in chall.py

FLAG_RE = re.compile(r"CRYPTO25\{[^}]+\}")

# ----------------------------------------------------------------------


def main() -> None:
    r = remote(HOST, PORT)

    n = int(r.recvline().strip())    # modulus
    c = int(r.recvline().strip())    # ciphertext (m^e mod n)

    two_e = pow(2, E, n)             # 2^e (mod n) — used every round

    low, high = Fraction(0), Fraction(n)
    original_cipher = c              # keep it for a sanity-check later

    # worst-case: n.bit_length() + a handful of extra rounds
    for _ in range(n.bit_length() + 2):
        # shift the *plaintext* left by one bit (multiply by 2 in the
        # encrypted domain) *before* asking for its LSB
        c = (c * two_e) % n
        r.sendline(str(c).encode())
        parity = int(r.recvline().strip())  # 0 = even, 1 = odd

        mid = (low + high) / 2
        if parity == 0:
            high = mid
        else:
            low = mid

        # We’re done when the interval can contain only one integer
        if high - low <= 1:
            break

    m = int(high)                    # the unique integer in (low, high)

    # Optional safety net: verify that we really recovered m
    assert pow(m, E, n) == original_cipher, "recovered plaintext is wrong"

    # Turn it into text, throw away any non-ASCII padding, and fish out
    # the flag
    ascii_text = long_to_bytes(m).decode("ascii", errors="ignore")
    flag_match = FLAG_RE.search(ascii_text)

    if not flag_match:
        print("[!] Could not find a flag in the plaintext:")
        print(ascii_text)
    else:
        print(f"[+] Flag: {flag_match.group(0)}")

    r.close()


if __name__ == "__main__":
    main()

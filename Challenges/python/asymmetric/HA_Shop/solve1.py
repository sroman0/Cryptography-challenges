#!/usr/bin/env python3
"""
HA_Shop – length-extension exploit (hashpumpy-only version)
Author:  you
Requires:  working hashpumpy / hashpumpy_changed C-extension
"""

import socket, re, binascii, time, logging, sys
from hashpumpy import hashpump          # ← native length-extension helper

HOST, PORT   = "130.192.5.212", 6630
USERNAME     = "attacker"               # alnum/underscore only
EXTRA        = "&value=1000"            # overwrites value=10
MIN_LEN, MAX_LEN = 8, 32                # brute-force secret-key size range
SOCK_TIMEOUT = 8                        # seconds

# ---------- noisy logger ----------------------------------------------------
logging.basicConfig(format="%(asctime)s  %(levelname)s  %(message)s",
                    datefmt="%H:%M:%S", level=logging.DEBUG)

def _recv(sock, pause=0.35):
    time.sleep(pause)
    data = sock.recv(8192)
    logging.debug("RECV %d bytes:\n%s", len(data), data.decode(errors="ignore"))
    return data.decode(errors="ignore")

def _send(sock, text):
    logging.debug("SEND %d bytes:\n%s", len(text), text.strip())
    sock.sendall(text.encode())

# ---------- protocol helpers ------------------------------------------------
def get_coupon(sock):
    _send(sock, "1\n"); _recv(sock)                     # choose menu item 1
    _send(sock, USERNAME + "\n")
    page = _recv(sock, 0.45)
    coup_hex = re.search(r"Coupon:\s*([0-9a-fA-F]+)", page)[1]
    mac_hex  = re.search(r"MAC:\s*([0-9a-fA-F]+)",    page)[1]
    return coup_hex, mac_hex

def buy(sock, coup_hex, mac_hex):
    _send(sock, "2\n");                _recv(sock)
    _send(sock, coup_hex + "\n");      _recv(sock)
    _send(sock, mac_hex  + "\n");      return _recv(sock, 0.45)

# ---------- exploit ---------------------------------------------------------
def main():
    logging.info("Connecting to %s:%d …", HOST, PORT)
    with socket.create_connection((HOST, PORT), timeout=SOCK_TIMEOUT) as s:
        _recv(s)                                            # banner + menu
        orig_hex, orig_mac = get_coupon(s)
        orig_msg = binascii.unhexlify(orig_hex).decode('latin1')
        logging.info("Got coupon (%d bytes) and MAC.", len(orig_msg))

        # brute-force secret length  → first hit stops loop
        for key_len in range(MIN_LEN, MAX_LEN + 1):
            new_mac, new_msg = hashpump(orig_mac, orig_msg, EXTRA, key_len)
            forged_hex = binascii.hexlify(new_msg.encode('latin1')).decode()
            logging.info("Trying key_len=%d  forged_hex_len=%d",
                         key_len, len(forged_hex))
            reply = buy(s, forged_hex, new_mac)
            if "Flag" in reply:
                print("\n=== SUCCESS with key_len=%d ===\n%s" % (key_len, reply))
                return
            logging.debug("key_len=%d failed (no flag).", key_len)

        logging.error("All %d key-length guesses failed.", MAX_LEN - MIN_LEN + 1)

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        logging.critical("Fatal: %s", exc)
        sys.exit(1)

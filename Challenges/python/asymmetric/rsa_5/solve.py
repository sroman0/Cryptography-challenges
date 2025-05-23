from pwn import remote
from Crypto.Util.number import long_to_bytes, inverse

# Connessione al server
HOST = "130.192.5.212"
PORT = 6645

# 1. Ricevi n e c
conn = remote(HOST, PORT)
n = int(conn.recvline().decode().strip())
c = int(conn.recvline().decode().strip())

# 2. Scegli s e calcola c'
s = 2
c_prime = (c * pow(s, 65537, n)) % n

# 3. Chiedi la decifratura di c'
conn.sendline(f"d{c_prime}")
m_prime = int(conn.recvline().decode().strip())

# 4. Calcola la flag
m = (m_prime * inverse(s, n)) % n
flag = long_to_bytes(m).decode(errors='ignore').strip()

print(flag)
conn.close()
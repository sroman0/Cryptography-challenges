from Crypto.Util.number import long_to_bytes
from sympy.ntheory import factorint

# CRYPTO25{X5a.7}

# Dati forniti dal challenge
n = 176278749487742942508568320862050211633  # Modulo RSA
c = 46228309104141229075992607107041922411   # Cifrato
e = 65537                                    # Esponente pubblico

# 1. Fattorizzazione di n per ottenere p e q
# Poiché n è piccolo, possiamo fattorizzarlo facilmente
factors = factorint(n)
p, q = list(factors.keys())

# 2. Calcolo di phi(n) = (p-1)*(q-1)
phi = (p - 1) * (q - 1)

# 3. Calcolo dell'esponente privato d come inverso di e modulo phi(n)
d = pow(e, -1, phi) #d = e^-1 mod phi

# 4. Decifrazione del messaggio cifrato c usando la chiave privata
m = pow(c, d, n) #m = c^d mod n

# 5. Conversione del messaggio decifrato da intero a bytes
flag_bytes = long_to_bytes(m)

# 6. Decodifica dei bytes in stringa e rimozione di eventuali caratteri non stampabili
# Si assume che la flag sia in formato ASCII stampabile e terminata da un carattere di nuova linea o caratteri extra
flag = flag_bytes.decode(errors='ignore').strip()

# 7. Stampa della flag in formato corretto
print(flag)


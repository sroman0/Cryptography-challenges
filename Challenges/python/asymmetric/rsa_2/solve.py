from Crypto.Util.number import long_to_bytes
from sympy.ntheory import isprime, nextprime
from math import isqrt

# Inserisci qui i valori stampati dal challenge
n = 60509355275518728792864353034381323203712352065221533863094540755630035742080855136016830887120470658395455751858380183285852786807229077435165810022519265154399424311072791755790585544921699474779996198610853766677088209156457859301755313246598035577293799853256065979074343370064111263698164125580000165237
c = 44695558076372490838321125335259117268430036823123326565653896322404966549742986308988778274388721345811255801305658387179978736924822440382730114598169989281210266972874387657989210875921956705640740514819089546339431934001119998309992280196600672180116219966257003764871670107271245284636072817194316693323
e = 65537

# 1. Calcoliamo la radice quadrata di n come punto di partenza per p
start = isqrt(n)

# 2. Cerchiamo p tra i numeri primi vicini a sqrt(n)
# Proviamo una finestra di ricerca ragionevole (es: 100000 numeri)
found = False
for delta in range(-100000, 100000):
    candidate_p = start + delta
    if isprime(candidate_p):
        candidate_q = nextprime(candidate_p)
        if candidate_p * candidate_q == n:
            p = candidate_p
            q = candidate_q
            found = True
            break

if not found:
    raise Exception("Fattorizzazione fallita: p e q non trovati.")

# 3. Calcoliamo phi(n)
phi = (p - 1) * (q - 1)

# 4. Calcoliamo d, l'inverso di e modulo phi(n)
d = pow(e, -1, phi)

# 5. Decifriamo il messaggio cifrato
m = pow(c, d, n)

# 6. Convertiamo il messaggio in bytes e poi in stringa
flag_bytes = long_to_bytes(m)
flag = flag_bytes.decode(errors='ignore').strip()

# 7. Stampiamo la flag
print(flag)
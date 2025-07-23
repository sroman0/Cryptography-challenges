# Cryptography Challenges - Politecnico di Torino

A comprehensive collection of Capture The Flag (CTF) challenges and exercises for the **Cryptography** course at Politecnico di Torino, Master's Degree program.

## 📋 Overview

This repository contains solutions and implementations for various cryptographic challenges, covering both theoretical concepts and practical implementations. The challenges are organized into two main categories: **Exercises** (educational implementations) and **Challenges** (CTF-style problems).

## 🏗️ Repository Structure

```
├── Challenges/          # CTF-style challenges
│   ├── OpenSSL/        # OpenSSL-based cryptographic challenges
│   └── python/         # Python-based cryptographic challenges
│       ├── asymmetric/ # RSA, key exchange, digital signatures
│       └── symmetric/  # AES, stream ciphers, padding oracles
├── Exercises/          # Educational exercises and examples
│   └── OpenSSL/        # OpenSSL learning exercises
└── LICENSE             # GNU GPL v3 License
```

## 🔐 Challenge Categories

### OpenSSL Challenges

#### Core Cryptographic Operations
- **`bytewise_operation/`** - Bitwise operations (OR, AND, XOR) for key generation
- **`changeDGST/`** - Hash function manipulation and analysis
- **`First_decryption/`** - ChaCha20 stream cipher decryption
- **`firstHMAC/`** - Hash-based Message Authentication Code implementation
- **`Keyed_digest/`** - SHA-512 keyed digest computation
- **`padding/`** - Padding attack techniques and mitigations

#### Advanced Techniques
- **`guess_algo/`** - Cipher algorithm identification through brute force
- **`guess_what/`** - Parameter discovery in cryptographic functions
- **`in_the_name_of_cipher/`** - Dynamic cipher selection using `EVP_get_cipherbyname()`

### Python Asymmetric Cryptography

#### RSA Challenges
- **`rsa_1/` - `rsa_9/`** - Progressive RSA attack techniques:
  - Small exponent attacks
  - Common modulus attacks
  - Wiener's attack (small private exponent)
  - Factorization of weak moduli
  - Parity oracle attacks (LSB oracle)
  - Blinding attacks on RSA signatures

#### Advanced Asymmetric Attacks
- **`Inferious_prime_CryptoHack/`** - Weak prime generation exploitation
- **`HA_Shop/`** - Hash length extension attacks on HMAC
- **`Equality/`** - MD4/MD5 collision attacks

### Python Symmetric Cryptography

#### AES and Block Cipher Attacks
- **`Fool_the_Oracle/`** - ECB oracle byte-at-a-time attack
- **`Foll_the_oracle_2/`** - Advanced ECB oracle with prefix
- **`Foll_the_oracle_3/`** - ECB oracle with unknown padding
- **`Foll_the_oracle_4/`** - ECB oracle with double padding

#### Stream Cipher and Authentication Attacks
- **`back_to_the_future/`** - ChaCha20 keystream reuse attacks
- **`decrypt_it,_if_you_are_fast_enough/`** - Time-based cryptographic attacks
- **`forge_a_cookie/`** - Stream cipher authentication bypass
- **`forge_another_cookie/`** - Advanced cookie forgery techniques
- **`forge_another_json_cookie/`** - JSON Web Token (JWT) manipulation

#### Cryptanalysis Techniques
- **`force_decryption/`** - Brute force and cryptanalytic attacks
- **`guess-mode_one-shot/`** & **`guess-mode_double-shot/`** - Cipher mode identification
- **`long_file/`** & **`long_secret_message/`** - Large data cryptanalysis

## 🛠️ Technologies Used

### Programming Languages & Libraries
- **C** with OpenSSL library for low-level cryptographic operations
- **Python 3** with cryptographic libraries:
  - `pycryptodome` - Modern cryptographic library
  - `pwntools` - CTF exploitation framework
  - `hashlib` - Standard hash functions
  - `socket` - Network communication for remote challenges

### Cryptographic Algorithms Covered
- **Symmetric Encryption**: AES (ECB, CBC), ChaCha20, DES
- **Asymmetric Encryption**: RSA with various attack vectors
- **Hash Functions**: SHA-256, SHA-512, MD4, MD5
- **Message Authentication**: HMAC, digital signatures
- **Key Exchange**: Diffie-Hellman variants

## 🎯 Learning Objectives

### Symmetric Cryptography
- Understanding block cipher modes of operation
- Padding oracle attacks and mitigation strategies
- Stream cipher security and keystream reuse vulnerabilities
- Authentication bypass techniques

### Asymmetric Cryptography
- RSA security analysis and common attack vectors
- Prime factorization techniques
- Side-channel attacks (timing, parity oracles)
- Digital signature forgery methods

### Cryptanalysis Skills
- Frequency analysis and pattern recognition
- Brute force optimization techniques
- Protocol weakness identification
- Implementation vulnerability exploitation

## 🚀 Getting Started

### Prerequisites
```bash
# Install OpenSSL development libraries (Ubuntu/Debian)
sudo apt-get install libssl-dev

# Install Python cryptographic libraries
pip install pycryptodome pwntools
```

### Compilation Examples
```bash
# Compile OpenSSL-based challenges
gcc -o challenge challenge.c -lssl -lcrypto

# For specific exercises
cd Exercises/OpenSSL/02_enc/
gcc -o enc enc.c -lssl -lcrypto
```

### Running Python Challenges
```bash
# Navigate to challenge directory
cd Challenges/python/symmetric/Fool_the_Oracle/

# Run the challenge server
python3 chall.py

# Execute the solution
python3 solve.py
```

## 🏆 Notable Solutions

### Advanced Attack Implementations
- **ECB Byte-at-a-time Attack**: Complete implementation of adaptive chosen plaintext attacks
- **RSA Parity Oracle**: Binary search implementation for LSB oracle attacks
- **Hash Length Extension**: Custom SHA-256 implementation for length extension attacks
- **Stream Cipher Keystream Recovery**: ChaCha20 keystream exploitation techniques

### Cryptographic Tools Developed
- Base64 encoding/decoding utilities
- Custom hash function implementations
- Network communication wrappers for remote challenges
- Automated brute force frameworks

## 📚 Educational Value

This repository serves as a comprehensive learning resource for:
- **Cryptography Students**: Practical implementation of theoretical concepts
- **Security Researchers**: Real-world attack vector demonstrations
- **CTF Enthusiasts**: Advanced challenge-solving techniques
- **Software Developers**: Secure coding practices and vulnerability awareness

## 🔒 Security Considerations

**⚠️ Educational Purpose Only**
- All code is intended for educational and authorized testing purposes
- Techniques demonstrated should only be used in controlled environments
- Responsible disclosure principles apply to any discovered vulnerabilities

## 📖 Course Context

This repository supports the Cryptography course curriculum at Politecnico di Torino, covering:
- Mathematical foundations of modern cryptography
- Practical cryptographic implementations
- Security analysis and vulnerability assessment
- Industry-standard cryptographic protocols

## 🤝 Contributing

Contributions are welcome for:
- Additional challenge solutions
- Code optimization and improvements
- Documentation enhancements
- New educational content

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 👨‍🎓 Author

**Simone** - Master's Degree Student  
Politecnico di Torino - Cryptography Course  
Academic Year: 2024-2025

---

*This repository represents practical work completed as part of the Cryptography course requirements and demonstrates proficiency in both theoretical cryptographic concepts and practical security analysis techniques.*
import random
from Crypto.Cipher import ChaCha20
from Crypto.Util.number import long_to_bytes
from secret import flag, randkey

# Initialize the nonce (global variable)
nonce = -1

# Function to encrypt a message using ChaCha20 and update the nonce
def encrypt_and_update(msg, nonce):
    # Create a ChaCha20 cipher with the given key and nonce
    cipher = ChaCha20.new(key=randkey, nonce=long_to_bytes(nonce))
    # Update the nonce with a new random 96-bit value
    nonce = random.getrandbits(12 * 8)
    # Encrypt the message and return the ciphertext
    return cipher.encrypt(msg.encode())

# Main function to interact with the user
def main():
    # Prompt the user to provide a seed for initializing the random generator
    seed = int(input(
        "Hi, our system doesn't support analogic entropy... so please give a value to initialize me!\n> "))
    random.seed(seed)
    # Generate an initial random 96-bit nonce
    nonce = random.getrandbits(12 * 8)  # 96 bits

    # Encrypt and display the secret flag
    print("OK! I can now give you the encrypted secret!")
    print(encrypt_and_update(flag, nonce).hex())

    # Allow the user to encrypt additional messages
    confirm = input("Do you want to encrypt something else? (y/n)")
    while confirm.lower() != 'n':
        if confirm.lower() == 'y':
            # Prompt the user for a message and encrypt it
            msg = input("What is the message? ")
            print(encrypt_and_update(msg, nonce).hex())
        confirm = input("Do you want to encrypt something else? (y/n)")

# Entry point of the script
if __name__ == '__main__':
    main()

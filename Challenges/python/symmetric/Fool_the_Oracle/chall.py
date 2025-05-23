from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from secret import flag

# Ensure the flag length matches the expected format
assert (len(flag) == len("CRYPTO25{}") + 36)

# Generate a random 24-byte key for AES encryption
key = get_random_bytes(24)
# Encode the flag as bytes
flag = flag.encode()

# Function to encrypt user-provided data concatenated with the flag
def encrypt() -> bytes:
    # Get user input as a hexadecimal string and convert it to bytes
    data = bytes.fromhex(input("> "))
    # Append the flag to the user-provided data
    payload = data + flag

    # Initialize the AES cipher in ECB mode
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    # Encrypt the padded payload and print it as a hexadecimal string
    print(cipher.encrypt(pad(payload, AES.block_size)).hex())

# Main function to interact with the user
def main():
    # Display the menu and handle user commands
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "enc - encrypt something\n" + \
        "help - show this menu again\n" + \
        "> "

    while True:
        cmd = input(menu).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "enc":
            encrypt()

# Entry point of the script
if __name__ == '__main__':
    main()

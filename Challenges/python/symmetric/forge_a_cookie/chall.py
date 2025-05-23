from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from secret import flag
import json
import base64

# Generate a random 32-byte key for ChaCha20 encryption
key = get_random_bytes(32)

# Function to create a ChaCha20 cipher with a random nonce
def make_cipher():
    # Generate a random 12-byte nonce
    nonce = get_random_bytes(12)
    # Initialize the ChaCha20 cipher with the key and nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return nonce, cipher

# Function to generate a user token for a given username
def get_user_token(name):
    # Create a new cipher with a random nonce
    nonce, cipher = make_cipher()
    # Create a JSON object containing the username
    token = json.dumps({
        "username": name
    })
    print(token)
    # Encrypt the JSON object
    enc_token = cipher.encrypt(token.encode())
    # Return the token as a base64-encoded string (nonce + encrypted token)
    return f"{base64.b64encode(nonce).decode()}.{base64.b64encode(enc_token).decode()}"

# Function to check if a given token is valid and if the user is an admin
def check_user_token(token):
    # Split the token into nonce and encrypted token
    nonce, token = token.split(".")
    # Decode the nonce from base64
    nonce = base64.b64decode(nonce)
    # Initialize the ChaCha20 cipher with the key and nonce
    cipher = ChaCha20.new(key=key, nonce=nonce)
    # Decrypt the token
    dec_token = cipher.decrypt(base64.b64decode(token))

    # Parse the decrypted token as JSON
    user = json.loads(dec_token)

    # Check if the user has admin privileges
    if user.get("admin", False) == True:
        return True
    else:
        return False

# Function to retrieve the flag if the user is an admin
def get_flag():
    # Prompt the user for their token
    token = input("What is your token?\n> ").strip()
    # Check if the token is valid and if the user is an admin
    if check_user_token(token):
        print("You are admin!")
        print(f"This is your flag!\n{flag}")
    else:
        print("HEY! WHAT ARE YOU DOING!?")
        exit(1)

# Main function to interact with the user
if __name__ == "__main__":
    # Prompt the user for their name
    name = input("Hi, please tell me your name!\n> ").strip()
    # Generate a token for the user
    token = get_user_token(name)
    print("This is your token: " + token)

    # Display the menu and handle user commands
    menu = \
        "What do you want to do?\n" + \
        "quit - quit the program\n" + \
        "help - show this menu again\n" + \
        "flag - get the flag\n" + \
        "> "
    while True:
        cmd = input(menu).strip()

        if cmd == "quit":
            break
        elif cmd == "help":
            continue
        elif cmd == "flag":
            get_flag()

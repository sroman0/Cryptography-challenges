from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.number import long_to_bytes, bytes_to_long
from secret import flag

# Generate a random 32-byte key for AES encryption
key = get_random_bytes(32)

# Function to sanitize input fields by removing or replacing unsafe characters
def sanitize_field(field: str):
    return field \
        .replace("/", "_") \
        .replace("&", "") \
        .replace(":", "") \
        .replace(";", "") \
        .replace("<", "") \
        .replace(">", "") \
        .replace('"', "") \
        .replace("'", "") \
        .replace("(", "") \
        .replace(")", "") \
        .replace("[", "") \
        .replace("]", "") \
        .replace("{", "") \
        .replace("}", "") \
        .replace("=", "")

# Function to parse a cookie string into a dictionary
def parse_cookie(cookie: str) -> dict:
    parsed = {}
    # Split the cookie string into fields and process each field
    for field in cookie.split("&"):
        key, value = field.strip().split("=")
        # Sanitize both the key and value
        key = sanitize_field(key.strip())
        value = sanitize_field(value.strip())
        parsed[key] = value

    return parsed

# Function to handle user login and generate an encrypted cookie
def login():
    # Prompt the user for a username and sanitize it
    username = input("Username: ")
    username = sanitize_field(username)

    # Initialize the AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)

    # Create a cookie string with the username and admin status
    cookie = f"username={username}&admin=false"

    # Encrypt the cookie and display it as a long integer
    print(bytes_to_long(cipher.encrypt(pad(cookie.encode(), AES.block_size))))

# Function to retrieve the flag if the user provides a valid admin cookie
def get_flag():
    # Prompt the user for their encrypted cookie as an integer
    cookie = int(input("Cookie: "))

    # Initialize the AES cipher in ECB mode
    cipher = AES.new(key=key, mode=AES.MODE_ECB)

    try:
        # Decrypt and unpad the cookie, then decode it as a string
        dec_cookie = unpad(cipher.decrypt(
            long_to_bytes(cookie)), AES.block_size).decode()
        # Parse the decrypted cookie into a dictionary
        token = parse_cookie(dec_cookie)

        # Check if the user has admin privileges
        if token["admin"] != 'true':
            print("You are not an admin!")
            return

        # If the user is an admin, display the flag
        print(f"OK! Your flag: {flag}")
    except:
        # Handle any errors during decryption or parsing
        print("Something didn't work :C")

# Main function to interact with the user
if __name__ == "__main__":
    # Call the login function to generate a cookie for the user
    login()

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

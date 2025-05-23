# see note info on smartphone

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from secret import flag
import random

# Mapping of mode names to AES mode constants
modes_mapping = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC
}

# Class to create a random AES cipher with a random mode (ECB or CBC)
class RandomCipherRandomMode():
    def __init__(self):
        # List of supported modes
        modes = [AES.MODE_ECB, AES.MODE_CBC]
        # Randomly select a mode
        self.mode = random.choice(modes)
        # Generate a random 32-byte key
        self.key = get_random_bytes(32) 
        if self.mode == AES.MODE_ECB:
            # ECB mode does not use an IV
            self.iv = None
            # Initialize the cipher in ECB mode
            self.cipher = AES.new(key=self.key, mode=self.mode)
        else:
            # CBC mode requires a random 16-byte IV
            self.iv = get_random_bytes(16)
            # Initialize the cipher in CBC mode with the IV
            self.cipher = AES.new(key=self.key, iv=self.iv, mode=self.mode)

    # Encrypt the given data using the initialized cipher
    def encrypt(self, data):
        return self.cipher.encrypt(data)

    # Decrypt the given data using the initialized cipher
    def decrypt(self, data):
        return self.cipher.decrypt(data)

# Main function to run the challenge
def main():

    # Loop through 128 challenges
    for i in range(128):
        # Create a new random cipher for each challenge
        cipher = RandomCipherRandomMode()

        print(f"Challenge #{i}")

        # Generate a random 32-byte OTP (one-time pad)
        otp = get_random_bytes(32)
        print(f"The otp I'm using: {otp.hex()}")
        
        # Get user input and ensure it is 32 bytes long
        data = bytes.fromhex(input("Input: ").strip())
        if len(data) != 32:
            print("Data must be 32 bytes long")
            return

        # XOR the input data with the OTP
        data = bytes([d ^ o for d, o in zip(data, otp)])
        # Encrypt the XORed data and display the output
        print(f"Output: {cipher.encrypt(data).hex()}")

        # Ask the user to guess the mode used
        mode_test = input(f"What mode did I use? (ECB, CBC)\n")
        # Check if the user's guess matches the actual mode
        if mode_test in modes_mapping.keys() and modes_mapping[mode_test] == cipher.mode:
            print("OK, next")
        else:
            print("Wrong, sorry")
            return

    # If all challenges are passed, reveal the flag
    print(f"The flag is: {flag}")


# Entry point of the script
if __name__ == "__main__":
    main()

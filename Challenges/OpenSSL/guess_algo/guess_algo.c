/*You sniffed the following Base64 string

ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=

You know it is an encrypted payload that has been ciphered with these parameters: key = "0123456789ABCDEF" iv = "0123456789ABCDEF" (Note: key and iv are not to be taken as hex strings)

Write a program (based for instance on dec1.c or a modification of enc4.c) to decrypt it and obtain decryptedcontent.

Then, take note of the following instruction in your decryption program if(!EVP_CipherInit(ctx,algorithm_name(), key, iv, ENCRYPT))

When you succeed, build the flag in this way (Python-style string concatenation)

"CRYPTO25{" + decryptedcontent + algorithm_name + "}"*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

#define MAXBUF 1024 // Define the maximum buffer size for plaintext

// Function to handle OpenSSL errors
void handle_errors() {
    ERR_print_errors_fp(stderr); // Print OpenSSL error messages to stderr
    abort(); // Terminate the program
}

// Function to decode a Base64-encoded string
int base64_decode(const char *b64_input, unsigned char **output) {
    BIO *b64, *bio;
    int length = strlen(b64_input); // Get the length of the Base64 input
    *output = malloc(length); // Allocate memory for the decoded output
    memset(*output, 0, length); // Initialize the allocated memory to zero

    bio = BIO_new_mem_buf(b64_input, -1); // Create a memory BIO with the Base64 input
    b64 = BIO_new(BIO_f_base64()); // Create a Base64 filter BIO
    bio = BIO_push(b64, bio); // Push the Base64 filter onto the memory BIO
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Disable newlines in Base64 decoding

    int decoded_length = BIO_read(bio, *output, length); // Decode the Base64 input
    BIO_free_all(bio); // Free all BIOs
    return decoded_length; // Return the length of the decoded data
}

// Function to print data in hexadecimal format
void print_hex(const unsigned char *data, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]); // Print each byte as a two-digit hexadecimal number
}

int main() {
    const char *base64_input = "ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg="; // Base64-encoded ciphertext
    const unsigned char *key = (unsigned char *)"0123456789ABCDEF"; // Encryption key (16 bytes)
    const unsigned char *iv  = (unsigned char *)"0123456789ABCDEF"; // Initialization vector (16 bytes)

    unsigned char *ciphertext; // Pointer to hold the decoded ciphertext
    int ciphertext_len = base64_decode(base64_input, &ciphertext); // Decode the Base64 input

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Create a new cipher context
    const EVP_CIPHER *cipher = EVP_aria_128_cbc(); // Specify the ARIA-128-CBC encryption algorithm

    unsigned char plaintext[MAXBUF]; // Buffer to hold the decrypted plaintext
    int len, plaintext_len = 0; // Variables to track lengths of decrypted data

    // Initialize the decryption operation
    if (!EVP_CipherInit(ctx, cipher, key, iv, 0)) // 0 indicates decryption mode
        handle_errors(); // Handle error if initialization fails

    // Decrypt the ciphertext in chunks
    if (!EVP_CipherUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_errors(); // Handle error if decryption fails
    plaintext_len = len; // Update the plaintext length

    // Finalize the decryption process
    if (!EVP_CipherFinal_ex(ctx, plaintext + len, &len))
        handle_errors(); // Handle error if finalization fails
    plaintext_len += len; // Add the final decrypted data length

    plaintext[plaintext_len] = '\0'; // Null-terminate the plaintext string

    // Print the decrypted content
    printf("Decrypted content: %s\n", plaintext);

    // Print the flag in the required format
    printf("CRYPTO25{%s%s}\n", plaintext, EVP_CIPHER_name(cipher)); // Concatenate plaintext and algorithm name

    // Clean up resources
    EVP_CIPHER_CTX_free(ctx); // Free the cipher context
    free(ciphertext); // Free the allocated memory for the ciphertext
    return 0; // Exit successfully
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <ctype.h>

// Base64-encoded ciphertext, key, and IV for decryption
#define BASE64_STRING "ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg="
#define KEY "0123456789ABCDEF"
#define IV "0123456789ABCDEF"

// Prints the decrypted plaintext and algorithm name in a specific format
void print_flag(const char *plaintext, const char *algo_name) {
    printf("CRYPTO25{%s%s}\n", plaintext, algo_name);
}

// Checks if a string contains only printable characters or whitespace
int is_printable(const char *str, int len) {
    for (int i = 0; i < len; i++) {
        if (!isprint(str[i]) && !isspace(str[i]))
            return 0; // Return false if any character is non-printable
    }
    return 1; // Return true if all characters are printable
}

// Decodes a Base64-encoded string and returns the decoded data
unsigned char *base64_decode(const char *base64, int *out_len) {
    BIO *bio, *b64;
    int len = strlen(base64);
    unsigned char *buffer = (unsigned char *)malloc(len); // Allocate memory for decoded data

    bio = BIO_new_mem_buf((void *)base64, -1); // Create a BIO for the Base64 string
    b64 = BIO_new(BIO_f_base64()); // Create a Base64 filter
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL); // Disable newlines in Base64 decoding
    bio = BIO_push(b64, bio); // Push the Base64 filter onto the BIO

    *out_len = BIO_read(bio, buffer, len); // Decode the Base64 string
    BIO_free_all(bio); // Free the BIO chain
    return buffer; // Return the decoded data
}

// Attempts to decrypt the ciphertext using the specified cipher
void try_decrypt_with_cipher(const EVP_CIPHER *cipher, unsigned char *ciphertext, int ciphertext_len) {
    EVP_CIPHER_CTX *ctx;
    unsigned char plaintext[128]; // Buffer for decrypted plaintext
    int len, plaintext_len;

    ctx = EVP_CIPHER_CTX_new(); // Create a new cipher context
    if (!ctx)
        return;

    // Initialize the cipher context with the specified cipher, key, and IV
    if (EVP_CipherInit_ex(ctx, cipher, NULL, (unsigned char *)KEY, (unsigned char *)IV, 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Check if the key and IV lengths match the cipher requirements
    if (EVP_CIPHER_CTX_key_length(ctx) != strlen(KEY) || EVP_CIPHER_CTX_iv_length(ctx) != strlen(IV)) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }

    // Decrypt the ciphertext
    if (EVP_CipherUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len = len;

    // Finalize the decryption process
    if (EVP_CipherFinal_ex(ctx, plaintext + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return;
    }
    plaintext_len += len;
    plaintext[plaintext_len] = '\0'; // Null-terminate the plaintext

    // Check if the plaintext is printable and print the flag if it is
    if (is_printable((char *)plaintext, plaintext_len)) {
        print_flag((char *)plaintext, EVP_CIPHER_name(cipher));
    }

    EVP_CIPHER_CTX_free(ctx); // Free the cipher context
}

// Callback function to try decryption with all available ciphers
void cipher_callback(const EVP_CIPHER *cipher, const char *from, const char *to, void *arg) {
    unsigned char *ciphertext = ((unsigned char **)arg)[0];
    int ciphertext_len = *((int *)(((unsigned char **)arg)[1]));

    try_decrypt_with_cipher(cipher, ciphertext, ciphertext_len); // Attempt decryption
}

int main() {
    OpenSSL_add_all_algorithms(); // Load all OpenSSL algorithms
    ERR_load_crypto_strings(); // Load OpenSSL error strings

    int decoded_len;
    unsigned char *decoded = base64_decode(BASE64_STRING, &decoded_len); // Decode the Base64 string

    void *args[2] = {decoded, &decoded_len}; // Arguments for the callback function
    EVP_CIPHER_do_all(cipher_callback, args); // Iterate over all ciphers and try decryption

    free(decoded); // Free the decoded data
    EVP_cleanup(); // Clean up OpenSSL
    return 0;
}

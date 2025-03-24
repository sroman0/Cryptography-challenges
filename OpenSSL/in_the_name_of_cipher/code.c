#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 4096

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char *argv[]) {
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <input file> <key (hex)> <iv (hex)> <output file> <algorithm>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *input_filename = argv[1];
    const char *key_hex = argv[2];
    const char *iv_hex = argv[3];
    const char *output_filename = argv[4];
    const char *algorithm = argv[5];

    // Convert key and IV from hex to binary
    size_t key_len = strlen(key_hex) / 2;
    size_t iv_len = strlen(iv_hex) / 2;
    unsigned char *key = malloc(key_len);
    unsigned char *iv = malloc(iv_len);

    for (size_t i = 0; i < key_len; ++i)
        sscanf(&key_hex[i * 2], "%2hhx", &key[i]);
    for (size_t i = 0; i < iv_len; ++i)
        sscanf(&iv_hex[i * 2], "%2hhx", &iv[i]);

    // Initialize OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // Fetch the cipher
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm);
    if (!cipher) {
        fprintf(stderr, "Unknown cipher: %s\n", algorithm);
        handleErrors();
    }

    // Initialize encryption operation
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
        handleErrors();

    // Open input and output files
    FILE *input_file = fopen(input_filename, "rb");
    FILE *output_file = fopen(output_filename, "wb");
    if (!input_file || !output_file) {
        perror("File opening error");
        handleErrors();
    }

    // Encrypt the input file and write to the output file
    unsigned char buffer[BUFFER_SIZE];
    unsigned char ciphertext[BUFFER_SIZE + EVP_CIPHER_block_size(cipher)];
    int len, ciphertext_len;

    while ((len = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, len) != 1)
            handleErrors();
        fwrite(ciphertext, 1, ciphertext_len, output_file);
    }

    if (ferror(input_file)) {
        perror("File reading error");
        handleErrors();
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len) != 1)
        handleErrors();
    fwrite(ciphertext, 1, ciphertext_len, output_file);

    // Clean up
    fclose(input_file);
    fclose(output_file);
    EVP_CIPHER_CTX_free(ctx);
    EVP_cleanup();
    ERR_free_strings();
    free(key);
    free(iv);

    return EXIT_SUCCESS;
}

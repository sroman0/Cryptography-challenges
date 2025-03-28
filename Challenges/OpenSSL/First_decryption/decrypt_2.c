#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

// Hard-code your key, IV, and Base64 ciphertext here:
static const char *hexKey = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF";
static const char *hexIV  = "11111111111111112222222222222222";
static const char *b64Ciphertext = "jyS3NIBqenyCWpDI2jkSu+z93NkDbWkUMitg2Q==";

// Helper: convert a hex string (e.g. "AAFF") into its raw bytes.
unsigned char* hexstr_to_bytes(const char* hexstr, size_t* out_len) {
    if(!hexstr) return NULL;
    size_t slen = strlen(hexstr);
    // Each byte is two hex characters
    *out_len = slen / 2;
    unsigned char* out = malloc(*out_len);
    for(size_t i = 0; i < *out_len; i++) {
        sscanf(hexstr + 2*i, "%2hhx", &out[i]);
    }
    return out;
}

// Helper: base64 decode into a newly allocated buffer.
unsigned char* base64_decode(const char* input, size_t* out_len) {
    BIO *b64 = NULL, *bmem = NULL;
    size_t input_len = strlen(input);
    unsigned char *buffer = malloc(input_len); // big enough for decoded data

    b64 = BIO_new(BIO_f_base64());
    // By default, base64 BIOs expect newlines. We disable that here:
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    bmem = BIO_new_mem_buf((void*)input, input_len);
    bmem = BIO_push(b64, bmem);

    *out_len = BIO_read(bmem, buffer, input_len);
    // In practice, you might want to check for errors here or ensure *out_len > 0.

    BIO_free_all(bmem);

    return buffer;
}

int main(void) {
    // Initialize OpenSSL's error strings (optional, for debugging).
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // 1. Convert hex key and IV to raw bytes
    size_t key_len = 0, iv_len = 0;
    unsigned char* key = hexstr_to_bytes(hexKey, &key_len);
    unsigned char* iv  = hexstr_to_bytes(hexIV,  &iv_len);

    // 2. Base64-decode the ciphertext
    size_t ct_len = 0;
    unsigned char* ciphertext = base64_decode(b64Ciphertext, &ct_len);

    // 3. Set up an EVP context for chacha20 decryption
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error: could not create EVP context.\n");
        return 1;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_chacha20(), NULL, NULL, NULL)) {
        fprintf(stderr, "Error: could not init cipher.\n");
        return 1;
    }

    // Provide key and IV
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
        fprintf(stderr, "Error: could not set key/iv.\n");
        return 1;
    }

    // 4. Decrypt
    unsigned char* plaintext = malloc(ct_len + EVP_CIPHER_block_size(EVP_chacha20()));
    int len = 0, plaintext_len = 0;

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ct_len)) {
        fprintf(stderr, "Error: decrypt update failed.\n");
        return 1;
    }
    plaintext_len = len;

    // Finalize
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        // If this fails, most likely the ciphertext or key/IV are incorrect.
        fprintf(stderr, "Error: decrypt final failed (bad padding or wrong key/IV?).\n");
        return 1;
    }
    plaintext_len += len;

    // Null-terminate the plaintext string
    plaintext[plaintext_len] = '\0';

    // Print the result
    printf("Decrypted plaintext: %s\n", plaintext);

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);
    free(key);
    free(iv);
    free(ciphertext);
    free(plaintext);

    // (Optional) Clean up Open
}
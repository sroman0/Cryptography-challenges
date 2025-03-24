#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

#define MAXBUF 1024

void handle_errors() {
    ERR_print_errors_fp(stderr);
    abort();
}

int base64_decode(const char *b64_input, unsigned char **output) {
    BIO *b64, *bio;
    int length = strlen(b64_input);
    *output = malloc(length);
    memset(*output, 0, length);

    bio = BIO_new_mem_buf(b64_input, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded_length = BIO_read(bio, *output, length);
    BIO_free_all(bio);
    return decoded_length;
}

void print_hex(const unsigned char *data, int len) {
    for (int i = 0; i < len; i++)
        printf("%02x", data[i]);
}

int main() {
    const char *base64_input = "ZZJ+BKJNdpXA2jaX8Zg5ItRola18hi95MG8fA/9RPvg=";
    const unsigned char *key = (unsigned char *)"0123456789ABCDEF"; // 16 bytes
    const unsigned char *iv  = (unsigned char *)"0123456789ABCDEF"; // 16 bytes

    unsigned char *ciphertext;
    int ciphertext_len = base64_decode(base64_input, &ciphertext);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_aria_128_cbc();  // <- ARIA-128-CBC algorithm

    unsigned char plaintext[MAXBUF];
    int len, plaintext_len = 0;

    if (!EVP_CipherInit(ctx, cipher, key, iv, 0)) // 0 = decrypt mode
        handle_errors();

    if (!EVP_CipherUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handle_errors();
    plaintext_len = len;

    if (!EVP_CipherFinal_ex(ctx, plaintext + len, &len))
        handle_errors();
    plaintext_len += len;

    plaintext[plaintext_len] = '\0';

    printf("Decrypted content: %s\n", plaintext);
    printf("CRYPTO25{%s%s}\n", plaintext, EVP_CIPHER_name(cipher));

    EVP_CIPHER_CTX_free(ctx);
    free(ciphertext);
    return 0;
}

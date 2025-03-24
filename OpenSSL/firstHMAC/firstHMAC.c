#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/hmac.h>

#define KEY "keykeykeykeykeykey"

void print_hex(const unsigned char *digest, int len) {
    for (int i = 0; i < len; i++) {
        printf("%02x", digest[i]);
    }
}

unsigned char* read_file(const char* filename, size_t* length_out) {
    FILE* f = fopen(filename, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        exit(1);
    }

    fseek(f, 0, SEEK_END);
    size_t len = ftell(f);
    rewind(f);

    unsigned char* buffer = malloc(len);
    if (fread(buffer, 1, len, f) != len) {
        fprintf(stderr, "Failed to read file: %s\n", filename);
        exit(1);
    }

    fclose(f);
    *length_out = len;
    return buffer;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <file1> <file2>\n", argv[0]);
        return 1;
    }

    size_t len1, len2;
    unsigned char *data1 = read_file(argv[1], &len1);
    unsigned char *data2 = read_file(argv[2], &len2);

    // Allocate combined buffer
    size_t total_len = len1 + len2;
    unsigned char *data = malloc(total_len);
    memcpy(data, data1, len1);
    memcpy(data + len1, data2, len2);

    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;

    HMAC(EVP_sha256(), KEY, strlen(KEY), data, total_len, hmac, &hmac_len);

    printf("CRYPTO25{");
    print_hex(hmac, hmac_len);
    printf("}\n");

    free(data1);
    free(data2);
    free(data);
    return 0;
}

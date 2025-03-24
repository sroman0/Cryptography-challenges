#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

unsigned char secret[] = "this_is_my_secret";

void compute_keyed_digest(const char *input_file) {
    FILE *file = fopen(input_file, "rb");
    if (!file) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    unsigned char *file_content = malloc(file_size);
    if (!file_content) {
        perror("Failed to allocate memory");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fread(file_content, 1, file_size, file);
    fclose(file);

    size_t total_size = sizeof(secret) - 1 + file_size + sizeof(secret) - 1;
    unsigned char *buffer = malloc(total_size);
    if (!buffer) {
        perror("Failed to allocate memory");
        free(file_content);
        exit(EXIT_FAILURE);
    }

    memcpy(buffer, secret, sizeof(secret) - 1);
    memcpy(buffer + sizeof(secret) - 1, file_content, file_size);
    memcpy(buffer + sizeof(secret) - 1 + file_size, secret, sizeof(secret) - 1);

    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512(buffer, total_size, hash);

    free(file_content);
    free(buffer);

    char hex_output[SHA512_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(hex_output + i * 2, "%02x", hash[i]);
    }

    printf("CRYPTO25{%s}\n", hex_output);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    compute_keyed_digest(argv[1]);
    return EXIT_SUCCESS;
}

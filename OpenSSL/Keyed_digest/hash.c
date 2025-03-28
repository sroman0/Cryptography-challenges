/*
Given the secret (represented as a C variable)

unsigned char secret[] = "this_is_my_secret";

Write a program in C that computes the keyed digest as

kd = SHA512 ( secret || input_file || secret)

where || indicates the concatenation (without adding any space characters)
hex computes the representation as an hexstring
Surround with CRYPTO25{hex(kd)} to obtain the flag.

HINT: start from hash3.c or hash4.c*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#define MAXBUF 1024 // Define the maximum buffer size for reading the file

/* Secret key */
unsigned char secret[] = "this_is_my_secret"; // Define the secret key used for keyed digest computation

int main(int argc, char **argv) {
    // Check if the correct number of arguments is provided
    if (argc != 2) {
        fprintf(stderr, "Invalid parameters. Usage: %s filename\n", argv[0]); // Print usage instructions
        exit(1); // Exit with failure
    }

    /* Open the input file */
    FILE *f_in;
    if ((f_in = fopen(argv[1], "r")) == NULL) { // Open the input file in read mode
        fprintf(stderr, "Couldn't open the input file, try again\n"); // Print error if file cannot be opened
        exit(1); // Exit with failure
    }

    /* Create a new digest context */
    EVP_MD_CTX *md = EVP_MD_CTX_new(); // Allocate a new digest context
    if (md == NULL) {
        fprintf(stderr, "Failed to create digest context\n"); // Print error if context creation fails
        exit(1); // Exit with failure
    }

    /* Initialize the digest context with SHA512 */
    if (EVP_DigestInit(md, EVP_sha512()) != 1) { // Initialize the digest context with the SHA512 algorithm
        fprintf(stderr, "Failed to initialize digest context\n"); // Print error if initialization fails
        EVP_MD_CTX_free(md); // Free the digest context
        exit(1); // Exit with failure
    }

    /* Update the digest with the first secret */
    if (EVP_DigestUpdate(md, secret, strlen((char *)secret)) != 1) { // Add the first secret to the digest
        fprintf(stderr, "Failed to update digest with secret\n"); // Print error if update fails
        EVP_MD_CTX_free(md); // Free the digest context
        exit(1); // Exit with failure
    }

    /* Read the input file and update the digest */
    int n;
    unsigned char buffer[MAXBUF]; // Buffer to hold file data
    while ((n = fread(buffer, 1, MAXBUF, f_in)) > 0) { // Read the file in chunks
        if (EVP_DigestUpdate(md, buffer, n) != 1) { // Add the file data to the digest
            fprintf(stderr, "Failed to update digest with file content\n"); // Print error if update fails
            EVP_MD_CTX_free(md); // Free the digest context
            exit(1); // Exit with failure
        }
    }

    /* Update the digest with the second secret */
    if (EVP_DigestUpdate(md, secret, strlen((char *)secret)) != 1) { // Add the second secret to the digest
        fprintf(stderr, "Failed to update digest with secret\n"); // Print error if update fails
        EVP_MD_CTX_free(md); // Free the digest context
        exit(1); // Exit with failure
    }

    /* Finalize the digest */
    unsigned char md_value[EVP_MD_size(EVP_sha512())]; // Buffer to hold the final digest
    unsigned int md_len; // Variable to hold the length of the digest
    if (EVP_DigestFinal_ex(md, md_value, &md_len) != 1) { // Finalize the digest computation
        fprintf(stderr, "Failed to finalize digest\n"); // Print error if finalization fails
        EVP_MD_CTX_free(md); // Free the digest context
        exit(1); // Exit with failure
    }

    /* Free the digest context */
    EVP_MD_CTX_free(md); // Free the allocated digest context

    /* Print the digest as a hex string */
    printf("CRYPTO25{"); // Print the flag prefix
    for (unsigned int i = 0; i < md_len; i++) {
        printf("%02x", md_value[i]); // Print each byte of the digest as a two-digit hexadecimal number
    }
    printf("}\n"); // Close the flag

    /* Close the input file */
    fclose(f_in); // Close the file

    return 0; // Exit successfully
}
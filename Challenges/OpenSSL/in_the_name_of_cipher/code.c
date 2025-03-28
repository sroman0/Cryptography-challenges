/*Write a program in C that, using the OpenSSL library, encrypts the content of a file using a user-selected algorithm.

The input filename is passed as first parameter from the command line, key and IV are the second and third parameter, the output file is the fourth parameter, the algorithm is the last parameter.

The algorithm name must be an OpenSSL-compliant string (e.g., aes-128-cbc or aes-256-ecb). (In short, you have to extend enc4.c)

Look for the proper function here https://www.openssl.org/docs/man3.1/man3/EVP_EncryptInit.html

In doing the exercise you have found a very relevant function, build the flag as "CRYPTO25{" + relevantFunctionName + "}"*/

#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 4096 // Define the buffer size for reading and writing files

// Function to handle OpenSSL errors
void handleErrors(void) {
    ERR_print_errors_fp(stderr); // Print OpenSSL error messages to stderr
    abort(); // Terminate the program
}

int main(int argc, char *argv[]) {
    // Check if the correct number of arguments is provided
    if (argc != 6) {
        fprintf(stderr, "Usage: %s <input file> <key (hex)> <iv (hex)> <output file> <algorithm>\n", argv[0]);
        return EXIT_FAILURE; // Exit with failure if arguments are incorrect
    }

    // Parse command-line arguments
    const char *input_filename = argv[1]; // Input file name
    const char *key_hex = argv[2]; // Key in hexadecimal format
    const char *iv_hex = argv[3]; // IV (Initialization Vector) in hexadecimal format
    const char *output_filename = argv[4]; // Output file name
    const char *algorithm = argv[5]; // Encryption algorithm name

    // Convert key and IV from hexadecimal to binary
    size_t key_len = strlen(key_hex) / 2; // Calculate key length in bytes
    size_t iv_len = strlen(iv_hex) / 2; // Calculate IV length in bytes
    unsigned char *key = malloc(key_len); // Allocate memory for the binary key
    unsigned char *iv = malloc(iv_len); // Allocate memory for the binary IV

    // Convert key from hex to binary
    for (size_t i = 0; i < key_len; ++i)
        sscanf(&key_hex[i * 2], "%2hhx", &key[i]);

    // Convert IV from hex to binary
    for (size_t i = 0; i < iv_len; ++i)
        sscanf(&iv_hex[i * 2], "%2hhx", &iv[i]);

    // Initialize OpenSSL libraries
    ERR_load_crypto_strings(); // Load error strings for OpenSSL
    OpenSSL_add_all_algorithms(); // Load all available encryption algorithms

    // Fetch the cipher based on the algorithm name
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); // Create a new cipher context
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(algorithm); // Get the cipher by name
    if (!cipher) {
        fprintf(stderr, "Unknown cipher: %s\n", algorithm); // Print error if cipher is unknown
        handleErrors(); // Handle the error
    }

    // Initialize the encryption operation
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
        handleErrors(); // Handle error if initialization fails

    // Open the input and output files
    FILE *input_file = fopen(input_filename, "rb"); // Open input file in binary read mode
    FILE *output_file = fopen(output_filename, "wb"); // Open output file in binary write mode
    if (!input_file || !output_file) {
        perror("File opening error"); // Print error if file cannot be opened
        handleErrors(); // Handle the error
    }

    // Encrypt the input file and write the encrypted data to the output file
    unsigned char buffer[BUFFER_SIZE]; // Buffer to hold input data
    unsigned char ciphertext[BUFFER_SIZE + EVP_CIPHER_block_size(cipher)]; // Buffer for encrypted data
    int len, ciphertext_len;

    // Read input file in chunks and encrypt each chunk
    while ((len = fread(buffer, 1, BUFFER_SIZE, input_file)) > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, buffer, len) != 1)
            handleErrors(); // Handle error if encryption fails
        fwrite(ciphertext, 1, ciphertext_len, output_file); // Write encrypted data to output file
    }

    // Check for file reading errors
    if (ferror(input_file)) {
        perror("File reading error"); // Print error if reading fails
        handleErrors(); // Handle the error
    }

    // Finalize the encryption process
    if (EVP_EncryptFinal_ex(ctx, ciphertext, &ciphertext_len) != 1)
        handleErrors(); // Handle error if finalization fails
    fwrite(ciphertext, 1, ciphertext_len, output_file); // Write the final encrypted data to output file

    // Clean up resources
    fclose(input_file); // Close the input file
    fclose(output_file); // Close the output file
    EVP_CIPHER_CTX_free(ctx); // Free the cipher context
    EVP_cleanup(); // Clean up OpenSSL algorithms
    ERR_free_strings(); // Free OpenSSL error strings
    free(key); // Free allocated memory for the key
    free(iv); // Free allocated memory for the IV

    return EXIT_SUCCESS; // Exit successfully
}

#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0

void handle_errors(void){
    ERR_print_errors_fp(stderr);
    abort();
}
// FUNCTION TO DISABLE PADDING: EVP_CIPHER_CTX_set_padding(ctx, 0);

int main(int argc, char **argv){

    ERR_load_crypto_strings(); //what does this function do? It loads all the error strings for the crypto library
    OpenSSL_add_all_algorithms(); //what does this function do? It loads all the algorithms in the library

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //check NULL

    unsigned char key[] = "1234567890abcdef"; // ASCII characters
    unsigned char IV[] = "1234567890abcdef"; // ASCII characters

    if(!EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, IV, ENCRYPT)){
        handle_errors();
    }

    

    unsigned char plaintext[] = "This variable contains the data to encrypt"; //44 bytes
    unsigned char ciphertext[48]; //the multiple of 16 bytes nearest to 44 is 48

    int length;
    int ciphertext_len=0; //overall size of the ciphertext

    if(!EVP_CipherUpdate(ctx, ciphertext, &length, plaintext, strlen(plaintext)))
        handle_errors();


    printf("After update: %d\n", length);
    ciphertext_len += length;

    if(!EVP_CipherFinal(ctx, ciphertext+ciphertext_len, &length))
        handle_errors();

    printf("After final: %d\n", length);

    ciphertext_len += length;

    EVP_CIPHER_CTX_free(ctx);

    printf("Size of the ciphertext: %d\n", ciphertext_len);

    for(int i=0; i<ciphertext_len; i++){
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    CRYPTO_cleanup_all_ex_data(); //what does this function do? It cleans up all the data associated with the library
    ERR_free_strings(); //what does this function do? It frees all the error strings

    return 0;
}
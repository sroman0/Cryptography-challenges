#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#define ENCRYPT 1
#define DECRYPT 0


int main(int argc, char **argv){
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    unsigned char key[] = "1234567890abcdef"; // ASCII characters
    unsigned char IV[] = "1234567890abcdef"; // ASCII characters
    unsigned char ciphertext[] = "a54c303f7c85b6a753a2c02e0e1aabcf0d9e8db1b553c1aad313897655974849c0a684999b8075eaee295b1cc2c5af97";


    EVP_CipherInit(ctx, EVP_aes_128_cbc(), key, IV, DECRYPT);

    unsigned char plaintext[strlen(ciphertext)/2];  //plaintext
    //the worst case scenario 
    //why the plaintext has this length?
    //because the ciphertext has 2 characters for each byte of the plaintext
    //so the length of the plaintext is the half of the length of the ciphertext
    
    
    unsigned char ciphertext_bin[strlen(ciphertext)/2]; //ciphertext in binary

    //process of converting the ciphertext from hexadecimal to binary
    for(int i = 0; i<strlen(ciphertext); i++){
        sscanf(&ciphertext[2*i], "%2hhx", &ciphertext_bin[i]);
    }

    
    int length;  // length of the ciphertext
    int plaintext_len=0; //overall size of the plaintext

    EVP_CipherUpdate(ctx, plaintext, &length, ciphertext_bin, strlen(ciphertext)/2);
    
    printf("After update: %d\n", length);
    plaintext_len += length;

    EVP_CipherFinal(ctx, plaintext+plaintext_len, &length);
    printf("After final: %d\n", length);
    plaintext_len += length;

    EVP_CIPHER_CTX_free(ctx);

    plaintext[plaintext_len] = '\0'; //null terminator why we do this only in decryption and not in the encryption phase?
    

    printf("Size of the plaintext: %d\n", plaintext_len);

    printf("Plaintext: %s\n", plaintext);

    return 0;
}
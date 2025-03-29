#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

#include <openssl/err.h>

#define ENCRYPT 1
#define DECRYPT 0
#define MAXSIZE 1024

void handle_errors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

//argv[1] = input file
//argv[2] = key (hex string)
//argv[3] = IV (hex string)
//argv[4] = output file
//save in a buffer in a memory file the result of the encryption


int main(int argc, char **argv){

    ERR_load_crypto_strings(); //what does this function do? It loads all the error strings for the crypto library
    OpenSSL_add_all_algorithms(); //what does this function do? It loads all the algorithms in the library

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new(); //check NULL

    if(argc != 5){
        fprintf(stderr, "Invalid parameters. Usage: %s input_file key IV out_file\n", argv[0]);
        exit(1);
    }

    FILE *f_in; 
    if((f_in = fopen(argv[1], "rb")) == NULL){
        fprintf(stderr, "Errors opening the input file: %s\n", argv[1]);
        exit(1);
    }
    
    FILE *f_out;
    if((f_out = fopen(argv[4], "wb")) == NULL){
        fprintf(stderr, "Errors opening the input file: %s\n", argv[4]);
        exit(1);
    }

    if(strlen(argv[2])/2 != 32){
        fprintf(stderr, "Wrong key length.\n");
        exit(1);
    }

    unsigned char key[strlen(argv[2])/2]; //key
    for(int i = 0; i<strlen(argv[2])/2; i++){
        sscanf(&argv[2][2*i], "%2hhx", &key[i]);
    }

    if(strlen(argv[3])/2 != 32){
        fprintf(stderr, "Wrong IV length.\n");
        exit(1);
    }

    unsigned char IV[strlen(argv[3])/2]; //key
    for(int i = 0; i<strlen(argv[3])/2; i++){
        sscanf(&argv[3][2*i], "%2hhx", &IV[i]);
    }

    
    if(!EVP_CipherInit(ctx, EVP_aes_256_cbc(), key, IV, ENCRYPT)){
        handle_errors();
    }

    int n_read;
    unsigned char buffer[MAXSIZE];

    unsigned char ciphertext[MAXSIZE + 16]; 

    int len, ciphertext_len = 0;

    while((n_read = fread(buffer, 1, MAXSIZE, f_in)) > 0){

        /* // if you risk to overflow the buffer variable, you exit the before
        //n_read + 1 block > left in ciphertext (MAX - ciphertext_len)
        if(ciphertext_len > 100 * MAXSIZE - n_read - EVP_CIPHER_CTX_block_size(ctx)) { 
            fprintf(stderr, "The file to cipher is larger than expected\n");
            exit(1);
        } */

        if(!EVP_CipherUpdate(ctx, ciphertext, &len, buffer, n_read)){
            handle_errors();
        }
        ciphertext_len += len;

        if(fwrite(ciphertext, 1, len, f_out) < len){
            fprintf(stderr, "Errors writing the output file.\n");
            abort();
        }

    }

    if(!EVP_CipherFinal(ctx, ciphertext, &len)){
        handle_errors();
    }
    ciphertext_len += len;

    if(fwrite(ciphertext, 1, len, f_out) < len){
        fprintf(stderr, "Errors writing the output file.\n");
        abort();
    }

    EVP_CIPHER_CTX_free(ctx);

    printf("Ciphertext length: %d\n", ciphertext_len);
     

    CRYPTO_cleanup_all_ex_data(); //what does this function do? It cleans up all the data associated with the library
    ERR_free_strings(); //what does this function do? It frees all the error strings

    fclose(f_in);
    fclose(f_out);

    return 0;
}
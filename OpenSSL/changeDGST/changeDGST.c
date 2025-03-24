#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define MAXBUF 1024

void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(int argc, char **argv){

    if(argc != 2){
        fprintf(stderr, "Inavalid parameters. Usage %s filename\n", argv[0]);
        exit(1);
    }

    FILE *f_in;

    if((f_in = fopen(argv[1], "r"))==NULL){
        fprintf(stderr, "Couldn't open the input file, try again\n");
        exit(1);
    }

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); 

    if(!EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF];
    while((n_read = fread(buffer, 1, MAXBUF, f_in))> 0){
         if(!EVP_DigestUpdate(mdctx, buffer, n_read))
            handle_errors();
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    if(!EVP_DigestFinal_ex(mdctx, hash, &hash_len))
        handle_errors();

    EVP_MD_CTX_free(mdctx);

    printf("The hash is: ");
    for(int i = 0; i< hash_len; i++)
        printf("%02x", hash[i]);
    printf("\n");

    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}

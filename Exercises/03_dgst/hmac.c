#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>


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

    unsigned char key[] = "1234567887654321"; //16 ASCII characters
    EVP_PKEY *hmac_key = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, strlen(key)); 


    // CHECK NULL
    EVP_MD_CTX *hmac_ctx = EVP_MD_CTX_new(); 

    if(!EVP_DigestSignInit(hmac_ctx, NULL, EVP_sha1(), NULL, hmac_key))
        handle_errors();

    int n_read;
    unsigned char buffer[MAXBUF];
    while((n_read = fread(buffer, 1, MAXBUF, f_in))> 0){
         if(!EVP_DigestSignUpdate(hmac_ctx, buffer, n_read))
            handle_errors();
    }

    unsigned char hmac_value[EVP_MD_size(EVP_sha1())];
    size_t hmac_len = sizeof(hmac_value);

    if(!EVP_DigestSignFinal(hmac_ctx, hmac_value, &hmac_len))
        handle_errors();

    EVP_MD_CTX_free(hmac_ctx);

    printf("The hmac is: ");
    for(int i = 0; i< hmac_len; i++)
        printf("%02x", hmac_value[i]);
    printf("\n");


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();


    return 0;
}
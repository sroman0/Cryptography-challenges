#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

void handle_errors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    RSA *rsa_key_pair;
    BIGNUM *bne = BN_new();
    if(!BN_set_word(bne, RSA_F4))
        handle_errors();
    
    rsa_key_pair = RSA_new();
    if(!RSA_generate_key_ex(rsa_key_pair, 2048, bne, NULL))
        handle_errors();

    FILE *rsa_file;
    if((rsa_file = fopen("private.pem", "w")) == NULL){
        fprintf(stderr, "Problems creating the new file\n");
        abort();
    }

    if(!PEM_write_RSAPrivateKey(rsa_file, rsa_key_pair, NULL, NULL, 0, NULL, NULL)){
        handle_errors();
    }

    fclose(rsa_file);
    if((rsa_file = fopen("public.pem", "w")) == NULL){
        fprintf(stderr, "Problems creating the new file\n");
        abort();
    }

    if(!PEM_write_RSA_PUBKEY(rsa_file,rsa_key_pair)){
        handle_errors();
    }

    fclose(rsa_file);


    RSA_free(rsa_key_pair);


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
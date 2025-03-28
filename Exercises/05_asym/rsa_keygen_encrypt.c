#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <string.h>

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


////////////////////////////////////////////////////////////////////////////

    unsigned  char  msg[] = "This is the message to encrypt\n";
    unsigned char encrypted_msg[RSA_size(rsa_key_pair)];
    int encrypted_len;

    if((encrypted_len = RSA_public_encrypt(strlen(msg)+1, msg, encrypted_msg, rsa_key_pair, RSA_PKCS1_OAEP_PADDING)) == -1)
        handle_errors();

    FILE *out;
    if((out = fopen("encrypted.enc", "w")) == NULL){
        fprintf(stderr, "Problems creating the new file\n");
        abort();
    }

    if(fwrite(encrypted_msg, 1, encrypted_len, out) < encrypted_len){
        fprintf(stderr, "Problems saving onto the file\n");
        abort();
    }

    fclose(out);
    printf("File saved!\n");
    fclose(rsa_file);


    RSA_free(rsa_key_pair);


    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    return 0;
}
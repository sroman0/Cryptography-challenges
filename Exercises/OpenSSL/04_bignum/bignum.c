#include <stdio.h>
#include <openssl/bn.h>

int main(int argc, char **argv){

    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();

    BN_print_fp(stdout, bn1);
    printf("\n");

    BN_set_word(bn1, 12300000);

    BN_print_fp(stdout, bn1); //print the result in an hexadecimal string
    printf("\n");

    BN_set_word(bn2, 124);

    BN_print_fp(stdout, bn2); //print the result in an hexadecimal string
    printf("\n");

    BIGNUM *res = BN_new();
    BN_add(res, bn1, bn2);

    BN_print_fp(stdout, res); //print the result in an hexadecimal string
    printf("\n");

    //when we need to use more complicated operation, we also need to allocate the context

    BN_CTX *ctx = BN_CTX_new();
    BN_mod(res, bn1, bn2, ctx); //remeinder, modulus, divisor, context

    BN_print_fp(stdout, res); //print the result in an hexadecimal string
    printf("\n");

    //sometimes the program will automatically free the bignums + the context
    BN_free(bn1);
    BN_free(bn2);
    BN_free(res);
    BN_CTX_free(ctx);

    return 0;
}
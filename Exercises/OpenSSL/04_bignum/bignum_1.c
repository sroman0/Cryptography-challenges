#include <stdio.h>
#include <openssl/bn.h>

int main(int argc, char **argv){

    char num_string[] = "123451234512345123451234512345123451234512346";

    char hex_string[] = "589269269E3BFCEC1F995D9B30AD5EBBD6DD9";
 
    BIGNUM *bn1 = BN_new();
    BIGNUM *bn2 = BN_new();

    BN_dec2bn(&bn1, num_string); //converts a string containing a decimal number to a BIGNUM and stores it in 

    BN_print_fp(stdout, bn1);
    printf("\n");

    BN_hex2bn(&bn2, hex_string);

    BN_print_fp(stdout, bn2);
    printf("\n");

    if(BN_cmp(bn1, bn2) == 0){
        printf("bn1 and bn2 are equal\n");
    }else{
        printf("bn1 and bn2 are different\n");
    }

    printf("bn1 = %s\n", BN_bn2hex(bn1));

    printf("bn2 = %s\n", BN_bn2dec(bn2));


    //sometimes the program will automatically free the bignums + the context
    BN_free(bn1);
    BN_free(bn2);

    return 0;
}
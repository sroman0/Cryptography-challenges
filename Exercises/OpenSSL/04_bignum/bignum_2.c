#include <stdio.h>
#include <openssl/bn.h>

int main(int argc, char **argv){

    char num_string[] = "123451234512345123451234512345123451234512346";

    char hex_string[] = "589269269E3BFCEC1F995D9B30AD5EBBD6DD9";
 
    BIGNUM *prime1 = BN_new();
    BIGNUM *prime2 = BN_new();

    //BN_generate_prime_ex2()
    BN_generate_prime_ex(); //Generates a pseudo-random prime number of at least the specified bit length bits


    //sometimes the program will automatically free the bignums + the context
    BN_free(prime1);
    BN_free(prime2);

    return 0;
}
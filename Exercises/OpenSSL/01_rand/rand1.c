#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/err.h>

//this h file is not deprecated

#define MAX 128


void handle_errors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int main(){

    //allocate memory for the random number sequence generated
    unsigned char random_string[MAX]; //bytes

    //we need to seed the random number generator
    if(RAND_load_file("/dev/random", 64) != 64) //1 par: path to the file, 2 par: number of bytes to read from the file, optional on linux
        handle_errors();
    //    fprintf(stderr, "Error with the initialization of the PRNG\n");


    //RAND_bytes returns 1 if the generation was successful, 0 otherwise, -1 if not supported by the current RAND method    
    if(RAND_bytes(random_string, MAX) != 1)  //1 par: name of the buffer where we wanto to save the stringer, 2 par: number of bytes we want to generate
            handle_errors();
    //      fprintf(stderr, "Error with the generation\n");

    //since there are random bytes, there's no way to use the standard printf function to print them
    printf("Sequence generated: ");
    //we can use a for loop to print each byte
    for(int i = 0; i < MAX; i++){
        printf("%02x-", random_string[i]); //the correct format string is including the hexadecimal representation, but we need to print only two hexadecimal digits
    }
    printf("\n");

    return 0;
}
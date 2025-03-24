#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STRING_LENGTH 64  

void hex_to_bytes(const char *hex, unsigned char *bytes, int length) {
    for (int i = 0; i < length; i++) {
        sscanf(hex + 3 * i, "%2hhx", &bytes[i]);  
    }
}

void print_hex(const char *label, const unsigned char *str, int length) {
    printf("%s: ", label);
    for (int i = 0; i < length; i++) {
        printf("%02x", str[i]);
        if (i < length - 1) printf("-");
    }
    printf("\n");
}

void print_flag(const unsigned char *str, int length) {
    printf("Flag: ");
    for (int i = 0; i < length; i++) {
        printf("%02x", str[i]);
        if (i < length - 1) printf("-");
    }
    printf("\n");
}

int main() {

    const char *hex_rand1 = "ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08";
    const char *hex_rand2 = "4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2";

    unsigned char rand1[STRING_LENGTH];
    unsigned char rand2[STRING_LENGTH];
    unsigned char k1[STRING_LENGTH];
    unsigned char k2[STRING_LENGTH];
    unsigned char key[STRING_LENGTH];

    
    hex_to_bytes(hex_rand1, rand1, STRING_LENGTH);
    hex_to_bytes(hex_rand2, rand2, STRING_LENGTH);

    
    for (int i = 0; i < STRING_LENGTH; i++) {
        k1[i] = rand1[i] | rand2[i];
        k2[i] = rand1[i] & rand2[i];
        key[i] = k1[i] ^ k2[i];
    }

    
    print_hex("rand1", rand1, STRING_LENGTH);
    print_hex("rand2", rand2, STRING_LENGTH);
    print_hex("k1 (OR)", k1, STRING_LENGTH);
    print_hex("k2 (AND)", k2, STRING_LENGTH);
    print_hex("key (XOR)", key, STRING_LENGTH);

    
    print_flag(key, STRING_LENGTH);

    return 0;
}

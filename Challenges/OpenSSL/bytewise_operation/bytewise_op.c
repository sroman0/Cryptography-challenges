/*A program performs the following operations:

generates two random strings (rand1 and rand2)
perform the bytewise OR of rand1 and rand2 and obtains k1
perform the bytewise AND of rand1 and rand2 and obtains k2
perform the bytewise XOR of k1 and k2 and obtains key
Write the program that implements the bytewise operations.

The flag will be the result (key) when the randomly generated strings are rand1 = ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08 rand2 = 4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2

It needs to be printed exactly in the same format as the random numbers (i.e., two hexdigits then a dash) and surrounded by CRYPTO25{}.*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STRING_LENGTH 64  // Define the length of the byte arrays

// Converts a hexadecimal string (with dashes) into a byte array.
// Each pair of hex digits is converted into a single byte.
// Why do we need to convert the hexadecimal string into a byte array?
// Because the input strings are in hexadecimal format, but we need to perform bitwise operations on the byte values.
void hex_to_bytes(const char *hex, unsigned char *bytes, int length) {
    for (int i = 0; i < length; i++) {
        sscanf(hex + 3 * i, "%2hhx", &bytes[i]);  // Read two hex digits and convert to a byte
    }
}

// Prints a byte array in hexadecimal format with dashes between bytes.
// Used to display intermediate results in the same format as the input strings.
void print_hex(const char *label, const unsigned char *str, int length) {
    printf("%s: ", label);  // Print the label for the output
    for (int i = 0; i < length; i++) {
        printf("%02x", str[i]);  // Print each byte as two hex digits
        if (i < length - 1) printf("-");  // Add a dash between bytes
    }
    printf("\n");
}

// Prints the final result (key) in the required format and surrounds it with "CRYPTO25{}".
// This is the flag output of the program.
void print_flag(const unsigned char *str, int length) {
    printf("Flag: CRYPTO25{");  // Start the flag format
    for (int i = 0; i < length; i++) {
        printf("%02x", str[i]);  // Print each byte as two hex digits
        if (i < length - 1) printf("-");  // Add a dash between bytes
    }
    printf("}\n");  // Close the flag format
}

int main() {
    // Input hexadecimal strings representing two random byte arrays
    const char *hex_rand1 = "ed-8a-3b-e8-17-68-38-78-f6-b1-77-3e-73-b3-f7-97-f3-00-47-76-54-ee-8d-51-0a-2f-10-79-17-f8-ea-d8-81-83-6e-0f-0c-b8-49-5a-77-ef-2d-62-b6-5e-e2-10-69-d6-cc-d6-a0-77-a2-0a-d3-f7-9f-a7-9e-a7-c9-08";
    const char *hex_rand2 = "4c-75-82-ca-02-07-bd-1d-8d-52-f0-6c-7a-d6-b7-87-83-95-06-2f-e0-f7-d4-24-f8-03-68-97-41-4c-85-29-e5-0d-b0-e4-3c-ee-74-dc-18-8a-aa-26-f0-46-94-e8-52-91-4a-43-8f-dd-ea-bb-a8-cf-51-14-79-ec-17-c2";

    // Arrays to store the byte representations of the input strings and intermediate results
    unsigned char rand1[STRING_LENGTH];  // Byte array for the first random string
    unsigned char rand2[STRING_LENGTH];  // Byte array for the second random string
    unsigned char k1[STRING_LENGTH];  // Byte array for the result of the OR operation
    unsigned char k2[STRING_LENGTH];  // Byte array for the result of the AND operation
    unsigned char key[STRING_LENGTH];  // Byte array for the final result (key)

    // Convert the input hexadecimal strings into byte arrays
    hex_to_bytes(hex_rand1, rand1, STRING_LENGTH);
    hex_to_bytes(hex_rand2, rand2, STRING_LENGTH);

    // Perform bytewise operations on the two random byte arrays
    for (int i = 0; i < STRING_LENGTH; i++) {
        k1[i] = rand1[i] | rand2[i];  // Bytewise OR operation
        k2[i] = rand1[i] & rand2[i];  // Bytewise AND operation
        key[i] = k1[i] ^ k2[i];  // Bytewise XOR operation between k1 and k2
    }

    // Print the input byte arrays and intermediate results
    print_hex("rand1", rand1, STRING_LENGTH);  // Print the first random byte array
    print_hex("rand2", rand2, STRING_LENGTH);  // Print the second random byte array
    print_hex("k1 (OR)", k1, STRING_LENGTH);  // Print the result of the OR operation
    print_hex("k2 (AND)", k2, STRING_LENGTH);  // Print the result of the AND operation
    print_hex("key (XOR)", key, STRING_LENGTH);  // Print the result of the XOR operation

    // Print the final flag in the required format
    print_flag(key, STRING_LENGTH);

    return 0;  // Exit the program
}

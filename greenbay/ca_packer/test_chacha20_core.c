#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declare our assembly functions
extern void initialize_chacha20_state(unsigned char* key, unsigned char* nonce, unsigned int counter, unsigned char* state);
extern void chacha20_rounds(unsigned char* state);
extern void generate_chacha20_keystream(unsigned char* key, unsigned char* nonce, unsigned int counter, unsigned char* output);

int main() {
    printf("Testing ChaCha20 core implementation...\n");
    
    // Test data
    unsigned char key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    unsigned char nonce[12] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    
    unsigned int counter = 1;
    unsigned char output[64];
    
    printf("Calling generate_chacha20_keystream...\n");
    generate_chacha20_keystream(key, nonce, counter, output);
    
    printf("Keystream generated successfully!\n");
    
    // Print first 16 bytes of keystream
    printf("First 16 bytes of keystream:\n");
    for (int i = 0; i < 16; i++) {
        printf("%02x ", output[i]);
        if ((i + 1) % 8 == 0) printf("\n");
    }
    
    return 0;
}
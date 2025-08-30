#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declare our assembly functions
extern long decrypt_chacha20_poly1305(unsigned char* ciphertext, unsigned long ciphertext_size,
                                      unsigned char* key, unsigned char* nonce,
                                      unsigned char* output_buffer);

int main() {
    printf("Testing ChaCha20-Poly1305 implementation...\n");
    
    // Test data
    unsigned char ciphertext[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
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
    
    unsigned char output_buffer[32];
    
    printf("Calling decrypt_chacha20_poly1305...\n");
    long result = decrypt_chacha20_poly1305(ciphertext, sizeof(ciphertext), key, nonce, output_buffer);
    
    if (result == -1) {
        printf("Decryption failed!\n");
        return 1;
    } else {
        printf("Decryption successful! Decrypted %ld bytes.\n", result);
        
        // Print first 16 bytes of decrypted data
        printf("First 16 bytes of decrypted data:\n");
        for (int i = 0; i < 16 && i < result; i++) {
            printf("%02x ", output_buffer[i]);
            if ((i + 1) % 8 == 0) printf("\n");
        }
    }
    
    return 0;
}
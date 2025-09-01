#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declare our assembly functions
extern long generate_ca_mask(unsigned char* key_material, unsigned long block_index,
                             unsigned long ca_steps, unsigned long mask_size,
                             unsigned char* output_mask);

int main() {
    printf("Testing CA Unmasking implementation...\n");
    
    // Test data
    unsigned char key_material[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    unsigned long block_index = 0;
    unsigned long ca_steps = 100;
    unsigned long mask_size = 16;
    unsigned char output_mask[16];
    
    printf("Calling generate_ca_mask...\n");
    long result = generate_ca_mask(key_material, block_index, ca_steps, mask_size, output_mask);
    
    if (result == -1) {
        printf("CA mask generation failed!\n");
        return 1;
    } else {
        printf("CA mask generation successful!\n");
        
        // Print the generated mask
        printf("Generated mask (%lu bytes):\n", mask_size);
        for (unsigned long i = 0; i < mask_size; i++) {
            printf("%02x ", output_mask[i]);
            if ((i + 1) % 8 == 0) printf("\n");
        }
    }
    
    return 0;
}
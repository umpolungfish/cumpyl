#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declare our assembly functions
extern long initialize_ca_grid_with_key_material(unsigned char* key_material, 
                                               unsigned long block_index,
                                               unsigned long grid_size,
                                               unsigned char* grid_buffer);

int main() {
    printf("Testing CA Grid Initialization function...\n");
    
    // Test data
    unsigned char key_material[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    unsigned long block_index = 5;
    unsigned long grid_size = 64;  // 64 bytes = 512 bits
    unsigned char grid_buffer[64];
    
    printf("Calling initialize_ca_grid_with_key_material...\n");
    long result = initialize_ca_grid_with_key_material(key_material, block_index, grid_size, grid_buffer);
    
    if (result == -1) {
        printf("CA grid initialization failed!\n");
        return 1;
    } else {
        printf("CA grid initialization successful!\n");
        
        // Print the initialized grid
        printf("Initialized grid (%lu bytes):\n", grid_size);
        for (unsigned long i = 0; i < grid_size; i++) {
            printf("%02x ", grid_buffer[i]);
            if ((i + 1) % 8 == 0) printf("\n");
        }
    }
    
    return 0;
}
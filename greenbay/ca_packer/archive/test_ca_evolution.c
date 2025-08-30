#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declare our assembly functions
extern long evolve_ca_multiple_steps(unsigned char* initial_grid,
                                   unsigned char* second_grid,
                                   unsigned long grid_size,
                                   unsigned long num_steps);

extern long evolve_ca_grid_one_step(unsigned char* current_grid,
                                  unsigned char* next_grid,
                                  unsigned long grid_size);

int main() {
    printf("Testing CA Evolution functions...\n");
    
    // Test data
    unsigned long grid_size = 64;  // 64 bytes = 512 bits
    unsigned long num_steps = 10;
    unsigned char initial_grid[64];
    unsigned char second_grid[64];
    
    // Initialize grids with test data
    for (unsigned long i = 0; i < grid_size; i++) {
        initial_grid[i] = i % 256;
        second_grid[i] = 0;
    }
    
    printf("Calling evolve_ca_multiple_steps with %lu steps...\n", num_steps);
    long result = evolve_ca_multiple_steps(initial_grid, second_grid, grid_size, num_steps);
    
    if (result == -1) {
        printf("CA evolution failed!\n");
        return 1;
    } else {
        printf("CA evolution successful!\n");
        
        // Print the evolved grid
        printf("Evolved grid (%lu bytes):\n", grid_size);
        for (unsigned long i = 0; i < grid_size; i++) {
            printf("%02x ", second_grid[i]);
            if ((i + 1) % 8 == 0) printf("\n");
        }
    }
    
    return 0;
}
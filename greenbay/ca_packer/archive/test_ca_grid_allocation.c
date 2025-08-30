#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declare our assembly functions
extern long allocate_two_ca_grids(unsigned long grid_size, 
                                 unsigned char** grid1_ptr, 
                                 unsigned char** grid2_ptr);
extern long deallocate_two_ca_grids(unsigned char* grid1, 
                                   unsigned char* grid2, 
                                   unsigned long grid_size);

int main() {
    printf("Testing CA Grid Allocation functions...\n");
    
    // Test data
    unsigned long grid_size = 256;  // 256 bytes = 2048 bits
    unsigned char* grid1 = NULL;
    unsigned char* grid2 = NULL;
    
    printf("Calling allocate_two_ca_grids with grid size %lu...\n", grid_size);
    long result = allocate_two_ca_grids(grid_size, &grid1, &grid2);
    
    if (result == -1) {
        printf("CA grid allocation failed!\n");
        return 1;
    } else {
        printf("CA grid allocation successful!\n");
        printf("Grid 1 pointer: %p\n", grid1);
        printf("Grid 2 pointer: %p\n", grid2);
        
        // Check that pointers are not NULL
        if (grid1 == NULL || grid2 == NULL) {
            printf("ERROR: Grid pointers are NULL!\n");
            return 1;
        }
        
        // Fill grids with test data
        for (unsigned long i = 0; i < grid_size; i++) {
            grid1[i] = i % 256;
            grid2[i] = (i + 1) % 256;
        }
        
        // Verify test data
        printf("Verifying test data...\n");
        int success = 1;
        for (unsigned long i = 0; i < grid_size; i++) {
            if (grid1[i] != (i % 256)) {
                printf("ERROR: Grid 1 data mismatch at index %lu\n", i);
                success = 0;
                break;
            }
            if (grid2[i] != ((i + 1) % 256)) {
                printf("ERROR: Grid 2 data mismatch at index %lu\n", i);
                success = 0;
                break;
            }
        }
        
        if (success) {
            printf("Test data verification successful!\n");
        } else {
            printf("Test data verification failed!\n");
            return 1;
        }
        
        // Deallocate grids
        printf("Calling deallocate_two_ca_grids...\n");
        result = deallocate_two_ca_grids(grid1, grid2, grid_size);
        
        if (result == -1) {
            printf("CA grid deallocation failed!\n");
            return 1;
        } else {
            printf("CA grid deallocation successful!\n");
        }
    }
    
    return 0;
}
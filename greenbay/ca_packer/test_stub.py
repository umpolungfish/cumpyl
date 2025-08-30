#!/usr/bin/env python3
"""
Test script for the complete CA packer stub.
"""

import subprocess
import sys
import os

def main():
    # Get the directory of this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Define paths
    stub_binary = os.path.join(script_dir, "complete_unpacking_stub_compiled.bin")
    
    # Create a simple test program that just calls our stub
    test_program = os.path.join(script_dir, "test_stub_call")
    
    # Create a simple C program that calls our stub
    print("Creating test program that calls our stub...")
    test_program_source = os.path.join(script_dir, "test_stub_call.c")
    with open(test_program_source, "w") as f:
        f.write("""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

int main() {
    // Open our stub binary
    int fd = open("/home/mrnob0dy666/cumpyl/greenbay/ca_packer/complete_unpacking_stub_compiled.bin", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open stub binary");
        return 1;
    }
    
    // Get the size of the stub
    off_t size = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    
    // Map the stub into memory
    void *stub = mmap(NULL, size, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
    if (stub == MAP_FAILED) {
        perror("Failed to map stub into memory");
        close(fd);
        return 1;
    }
    
    // Close the file descriptor
    close(fd);
    
    // Call the stub
    printf("Calling stub...\\n");
    ((void(*)())stub)();
    
    // Unmap the stub
    munmap(stub, size);
    
    return 0;
}
""")
    
    # Compile the test program
    print("Compiling test program...")
    result = subprocess.run([
        "gcc", test_program_source, "-o", test_program
    ], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error: Failed to compile test program.")
        print(f"stderr: {result.stderr}")
        return 1
    
    # Make sure the test program is executable
    os.chmod(test_program, 0o755)
    
    # Test the stub
    print("Testing stub...")
    result = subprocess.run([test_program], capture_output=True, text=True)
    print(f"Test program exit code: {result.returncode}")
    print(f"Test program stdout: {result.stdout}")
    print(f"Test program stderr: {result.stderr}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
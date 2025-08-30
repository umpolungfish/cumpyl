
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
    printf("Calling stub...\n");
    ((void(*)())stub)();
    
    // Unmap the stub
    munmap(stub, size);
    
    return 0;
}

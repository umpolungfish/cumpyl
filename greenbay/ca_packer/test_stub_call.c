#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Declare our assembly function
extern void enhanced_error_tracking_stub();

int main() {
    printf("Calling enhanced error tracking stub...\n");
    enhanced_error_tracking_stub();
    printf("Returned from enhanced error tracking stub.\n");
    return 0;
}
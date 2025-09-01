#ifdef DEBUG
mov $1, %rax
#else
mov $0, %rax
#endif
ret
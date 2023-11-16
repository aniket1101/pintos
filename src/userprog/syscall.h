#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>

void syscall_init (void);
void *check_pointer(void *ptr);
void kernel_exit(int status) NO_RETURN; 

#endif /* userprog/syscall.h */

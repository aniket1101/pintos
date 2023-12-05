#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>

void syscall_init (void);
void *check_pointer(void *ptr);
void kernel_exit(int status) NO_RETURN; 

void lock_filesys_access(void);
void unlock_filesys_access(void);

#endif /* userprog/syscall.h */

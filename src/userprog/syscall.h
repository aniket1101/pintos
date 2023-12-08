#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include "vm/page.h"

void syscall_init (void);
void exit_process(int status) NO_RETURN; 
void munmap_all(void);

void lock_filesys_access(void);
void unlock_filesys_access(void);

#endif /* userprog/syscall.h */

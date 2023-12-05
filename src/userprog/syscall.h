#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <debug.h>
#include "vm/page.h"
#include "userprog/process.h"

void syscall_init (void);
void *check_pointer(void *ptr);
void kernel_exit(int status) NO_RETURN; 

void lock_filesys_access(void);
void unlock_filesys_access(void);

void setup_lazy(uint32_t read_bytes, uint32_t zero_bytes, void *upage, void *start, 
    bool writable, mapid_t map_id, struct file *file);

#endif /* userprog/syscall.h */

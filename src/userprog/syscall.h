#include <list.h>
#include "filesys/off_t.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);
void *check_pointer(void *ptr);

struct fd_elem {
    struct list_elem elem;
    int fd;
    off_t offset;
};

struct thread_fd_elem {
    struct list_elem elem;
    int fd;
};

#endif /* userprog/syscall.h */

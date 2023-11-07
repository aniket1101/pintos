#include <list.h>
#include "filesys/off_t.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct fd_elem {
    int fd;
    off_t offset;
    struct list_elem fd_e;
};

struct thread_fd_elem {
    int fd;
    struct list_elem fd_e;
};

#endif /* userprog/syscall.h */

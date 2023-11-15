
#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <list.h>
#include "lib/kernel/hash.h"
#include "filesys/off_t.h"
#include "threads/synch.h"
#include "threads/init.h"

void syscall_init (void);
void *check_pointer(void *ptr);
void kernel_exit(int status) NO_RETURN; 

struct fd_elem {
    struct list_elem elem;
    int fd;
    off_t offset;
};

struct thread_fd_elem {
    struct list_elem elem;
    int fd;
};

struct parent_child {
    struct hash_elem h_elem;
    int p_tid;
    int p_exit_code;
    bool p_is_alive;
    int c_tid;
    int c_exit_code;
    bool c_is_alive;
    bool is_waiting;
    struct semaphore waiter;
};


bool tid_less(const struct hash_elem *a, 
                const struct hash_elem *b, void *aux UNUSED);

unsigned tid_func(const struct hash_elem *e, void *aux UNUSED);

void free_table (struct hash_elem *e, void *aux UNUSED);

struct parent_child *get_p_c(int c_tid);

void free_parents(int p_tid);

#endif /* userprog/syscall.h */

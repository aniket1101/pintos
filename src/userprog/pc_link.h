#ifndef USERPROG_PC_LINK_H
#define USERPROG_PC_LINK_H

#include <hash.h>
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"

struct pc_link {
    tid_t parent_tid;

    tid_t child_tid;
    int child_exit_code;
    bool child_alive;

    struct hash_elem h_elem;
    struct semaphore waiter;
};

struct pc_link *pc_link_init(tid_t child_tid);
struct pc_link *pc_link_lookup(int child_tid);
void pc_link_kill_child(struct pc_link *link, struct thread *child);

bool tid_less(const struct hash_elem *a, 
                const struct hash_elem *b, void *aux UNUSED);

unsigned tid_func(const struct hash_elem *e, void *aux UNUSED);

void pc_link_free(struct pc_link *link);
void free_table (struct hash_elem *e, void *aux UNUSED);
void free_parents(int parent_tid);

#endif
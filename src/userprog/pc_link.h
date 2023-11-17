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

	struct hash_elem elem;
	struct semaphore waiter;
};

void pc_link_system_init(void);

struct pc_link *pc_link_init(tid_t child_tid);
struct pc_link *pc_link_lookup(int child_tid);

void pc_link_kill_child(struct thread *child);

struct pc_link *pc_link_remove(struct pc_link *link);
void pc_link_free(struct hash_elem *h_elem, void *aux UNUSED);
void pc_link_free_parents(int parent_tid);

void pc_link_hash_destroy(void);

#endif
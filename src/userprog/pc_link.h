#ifndef USERPROG_PC_LINK_H
#define USERPROG_PC_LINK_H

#include <hash.h>
#include "threads/init.h"
#include "threads/synch.h"
#include "threads/thread.h"

struct pc_link {
	tid_t parent_tid;		 /* tid of thread which called wait. */

	tid_t child_tid;		 /* tid of thread waited on. */
	int child_exit_code;	 /* Exit code of dead child. */
	bool child_alive;		 /* Whether child thread is dead. */

	struct hash_elem elem; 	 /* Allows for hash of pc_links. */
	struct semaphore waiter; /* Semaphore to enforce waiting for child. */
};

void pc_link_system_init(void);

struct pc_link *pc_link_init(tid_t child_tid);
struct pc_link *pc_link_lookup(int child_tid);

void pc_link_kill_child(struct thread *child);

struct pc_link *pc_link_remove(struct pc_link *link);
void pc_link_free_parents(int parent_tid);

void pc_link_hash_destroy(void);

#endif
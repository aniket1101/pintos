#include "userprog/pc_link.h"
#include <stdbool.h>
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/debug.h"
#include "threads/synch.h"

struct hash pc_link_hash_table;
struct lock pc_link_lock;

static bool pc_link_less(const struct hash_elem *a, 
	const struct hash_elem *b, void *aux UNUSED);

static unsigned pc_link_hash(const struct hash_elem *e, void *aux UNUSED);

/* Initialises the pc_link system, creating the hash to contain the
   pc links and the lock for mod*/
void pc_link_system_init(void) {
  hash_init(&pc_link_hash_table, &pc_link_hash, &pc_link_less, NULL);
  lock_init(&pc_link_lock);
}

/* Less function to compare 2 pc links on the child thread id. */
static bool pc_link_less(const struct hash_elem *a, 
    const struct hash_elem *b, void *aux UNUSED) {
  return hash_entry(a, struct pc_link, elem)->child_tid
    < hash_entry(b, struct pc_link, elem)->child_tid;
}

/* Hash function to get the key of the hash, as the child tid will 
   be unique, we can use this. */
static unsigned pc_link_hash(const struct hash_elem *e, void *aux UNUSED) {
  return hash_entry(e, struct pc_link, elem)->child_tid;
}

/* Initialises the pc_link struct, returns the link if successful,
   and exits if unsuccessful. */
struct pc_link *pc_link_init(tid_t child_tid) {
  struct pc_link *link = (struct pc_link *) malloc (sizeof(struct pc_link));

  if (link == NULL) {
    kernel_exit(-1);
  }

  link->parent_tid = thread_tid();
  link->child_tid = child_tid;
  link->child_alive = true;
  sema_init(&(link->waiter), 0);

  lock_acquire(&pc_link_lock);
  hash_insert(&pc_link_hash_table, &link->elem);
  lock_release(&pc_link_lock);
  
  return link;
}

/* Given a child tid, it will attempt to retrieve the pc_link struct 
   in the pc_link hash table which has the corresponding child tid.
   Returns the pc_link pointer if successful and NULL if unsuccessful. */
struct pc_link *pc_link_lookup(int child_tid) {
  lock_acquire(&pc_link_lock);

  struct pc_link fake_link = {.child_tid = child_tid};
  struct hash_elem *found_elem 
    = hash_find(&pc_link_hash_table, &(fake_link.elem));
  struct pc_link *link 
    = found_elem != NULL ? hash_entry(found_elem, struct pc_link, elem) : NULL;

  lock_release(&pc_link_lock);
  return link;
}

/* Given a child thread, it will attempt to find a corresponding pc_link struct
   using the threads tid, if it finds this, it then updates the pc_link struct
   with the information that the child thread is dead and supplies it's exit 
   code, sema_up is used to allow the waiting parent to continue execution. */
void pc_link_kill_child(struct thread *child) {
  struct pc_link *link = pc_link_lookup(child->tid);

  if (link != NULL) {
    link->child_exit_code = child->exit_code;
    link->child_alive = false;
    sema_up(&link->waiter);
  }
}

/* Given a pc_link struct pointer, this will attempt it from the pc_link 
   hash table. */
struct pc_link *pc_link_remove(struct pc_link *link) {
  lock_acquire(&pc_link_lock);

  struct hash_elem *removed_elem 
    = hash_delete(&pc_link_hash_table, &link->elem);
  struct pc_link *removed_link 
    = removed_elem != NULL ? 
      hash_entry (removed_elem, struct pc_link, elem) : NULL;
  
  lock_release(&pc_link_lock);
  return removed_link;
}

/* A function given for the pc_link hash table's destroy function,
   this allows the hash elements to be free'd when the hash is removed. */
void pc_link_free(struct hash_elem *elem, void *aux UNUSED) {
  free(hash_entry (elem, struct pc_link, elem));
}

/* This will be called when a thread exits, it will check all hash elements
   to see if the given tid matches the parent tid in the pc_link. If so
   this needs to be removed from the hash and free'd. To do this, we store the 
   elements to be removed in an array and remove them after to allow the hash
   to iterate through properly, as removal during the iterator would stop it.*/
void pc_link_free_parents(int parent_tid) {
  struct pc_link *to_remove[hash_size(&pc_link_hash_table)];
  int index = 0;
  
  lock_acquire(&pc_link_lock);
  if (!hash_empty(&pc_link_hash_table)) {
    struct hash_iterator i;
    hash_first (&i, &pc_link_hash_table);

    while (hash_next (&i)) {
      struct pc_link *link = hash_entry (hash_cur (&i), struct pc_link, elem);
    
      if (link->parent_tid == parent_tid) {
        to_remove[index++] = link;
      }
    }
  }
  lock_release(&pc_link_lock);

  for (int i = 0; i < index; i++) {
    pc_link_remove(to_remove[i]);
    pc_link_free(&to_remove[i]->elem, NULL);
  }
}

/* Function given in hash_destroy for the pc_link hash table to free all 
   elements in the hash. */
void pc_link_hash_destroy(void) {
  hash_destroy(&pc_link_hash_table, &pc_link_free);
}
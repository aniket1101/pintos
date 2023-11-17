#include "userprog/pc_link.h"
#include <stdbool.h>
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/debug.h"
#include "threads/synch.h"

struct hash pc_link_hash_table;
struct lock pc_link_lock;

static hash_hash_func pc_link_hash;
static hash_less_func pc_link_less;
static hash_action_func pc_link_free;

/* Initialises the pc_link system, 
   creating the hash to contain the pc links and initialising lock. */
void pc_link_system_init(void) {
  hash_init(&pc_link_hash_table, &pc_link_hash, &pc_link_less, NULL);
  lock_init(&pc_link_lock);
}

/* Returns a hash value for a fd. */
static unsigned pc_link_hash(const struct hash_elem *e, void *aux UNUSED) {
  return hash_entry(e, struct pc_link, elem)->child_tid;
}

/* Returns true if a's child_tid is less than b's. */
static bool pc_link_less(const struct hash_elem *a, 
    const struct hash_elem *b, void *aux UNUSED) {
  return hash_entry(a, struct pc_link, elem)->child_tid
    < hash_entry(b, struct pc_link, elem)->child_tid;
}

/* Initialises the pc_link struct/
   Returns the link if successful, otherwise exits. */
struct pc_link *pc_link_init(tid_t child_tid) {
  struct pc_link *link = (struct pc_link *) malloc (sizeof(struct pc_link));
  if (link == NULL) { // If malloc fails, exit
    kernel_exit(-1);
  }

  // Intialise members
  link->parent_tid = thread_tid();
  link->child_tid = child_tid;
  link->child_alive = true;
  sema_init(&(link->waiter), 0);

  lock_acquire(&pc_link_lock);
  hash_insert(&pc_link_hash_table, &link->elem); // Insert link into hash
  lock_release(&pc_link_lock);
  
  return link;
}

/* Search for pc_link with corresponding child_tid in pc_link hash table. 
   Returns NULL if fails. */
struct pc_link *pc_link_lookup(int child_tid) {
  lock_acquire(&pc_link_lock);

  struct pc_link link_ = {.child_tid = child_tid}; // Fake link to search for
  struct hash_elem *found_elem 
    = hash_find(&pc_link_hash_table, &(link_.elem));
  
  struct pc_link *link = found_elem != NULL ? // Set to NULL if failed
    hash_entry(found_elem, struct pc_link, elem) : NULL;

  lock_release(&pc_link_lock);
  return link;
}

/* Lookup link with child's tid and set child's exit_code.
   Called from process_exit(). */
void pc_link_kill_child(struct thread *child) {
  struct pc_link *link = pc_link_lookup(child->tid); // Find correct link

  if (link != NULL) {
    // Set exit code to child thread's exit code
    link->child_exit_code = child->exit_code; 
    link->child_alive = false; // Child is dead
    sema_up(&link->waiter); // Stop waiting for this child
  }
}

/* Remove link from pc_link hash. Returns NULL if failed */
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


/* Finds all pc_links with pid = parent_tid, 
   then frees and deletes them from the hash */
void pc_link_free_parents(int parent_tid) {
  // Array of links to be removed to avoid invalidating hash_iterator
  struct pc_link *to_remove[hash_size(&pc_link_hash_table)];  
  int index = 0;
  
  lock_acquire(&pc_link_lock);
  if (!hash_empty(&pc_link_hash_table)) {
    struct hash_iterator i;
    hash_first (&i, &pc_link_hash_table);

    while (hash_next (&i)) { // Loop through the hash
      struct pc_link *link = hash_entry (hash_cur (&i), struct pc_link, elem);
    
      if (link->parent_tid == parent_tid) { // If parent will be deleted...
        to_remove[index++] = link; // Set link to be removed
      }
    }
  }
  lock_release(&pc_link_lock);

  // Remove links from hash and free them
  for (int i = 0; i < index; i++) {
    pc_link_remove(to_remove[i]);
    free(to_remove[i]);
  }
}

/* Free function for pc_link_hash_destroy(). */
static void pc_link_free(struct hash_elem *elem, void *aux UNUSED) {
  free(hash_entry (elem, struct pc_link, elem));
}

/* Destroy pc_link hash table, freeing each pc_link. */
void pc_link_hash_destroy(void) {
  hash_destroy(&pc_link_hash_table, &pc_link_free);
}
#include "userprog/pc_link.h"
#include <stdbool.h>
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/debug.h"

#define MAX_SIZE 100

struct hash pc_link_hash_table;

struct hash *pc_link_get_hash_table(void) {
  return &pc_link_hash_table;
}

struct pc_link *pc_link_init(tid_t child_tid) {
  struct pc_link *link = (struct pc_link *) malloc (sizeof(struct pc_link));
  if (link == NULL) {
    kernel_exit(-1);
  }

  link->parent_tid = thread_tid();
  link->child_tid = child_tid;
  link->child_alive = true;

  hash_insert(&pc_link_hash_table, &link->elem);
  
  sema_init(&(link->waiter), 0);
  
  return link;
}

void pc_link_kill_child(struct pc_link *link, struct thread *child) {
  link->child_exit_code = child->exit_code;
  link->child_alive = false;
  sema_up(&link->waiter);
}

struct pc_link *pc_link_remove(struct pc_link *link) {
  struct hash_elem *removed_elem = hash_delete(&pc_link_hash_table, &link->elem);
  return removed_elem != NULL ? hash_entry (removed_elem, struct pc_link, elem) : NULL;
}

void pc_link_free(struct hash_elem *elem, void *aux UNUSED) {
  free(hash_entry (elem, struct pc_link, elem));
}

bool tid_less(const struct hash_elem *a, 
    const struct hash_elem *b, void *aux UNUSED) {
  return hash_entry(a, struct pc_link, elem)->child_tid
    < hash_entry(b, struct pc_link, elem)->child_tid;
}

unsigned tid_func(const struct hash_elem *e, void *aux UNUSED) {
  return hash_entry(e, struct pc_link, elem)->child_tid;
}

struct pc_link *pc_link_lookup(int child_tid) {
  if (!hash_empty(&pc_link_hash_table)) {
    struct hash_iterator i;

    hash_first (&i, &pc_link_hash_table);
    while (hash_next (&i)) {
        struct pc_link *link = hash_entry (hash_cur (&i), struct pc_link, elem);
        if (link->child_tid == child_tid) {
          return link;
        }
    }
  }
  return NULL;
}

void pc_link_free_parents(int parent_tid) {
  struct pc_link *to_remove[MAX_SIZE];
  int index = 0;
  
  if (!hash_empty(&pc_link_hash_table)) {
    struct hash_iterator i;
    hash_first (&i, &pc_link_hash_table);

    while (hash_next (&i)) {
      struct pc_link *link = hash_entry (hash_cur (&i), struct pc_link, elem);
    
      if (link->parent_tid == parent_tid) {
        to_remove[index++] = link;
      }
    }

    for (int i = 0; i < index; i++) {
      pc_link_remove(to_remove[i]);
      pc_link_free(&to_remove[i]->elem, NULL);
    }
  }
}
#include "userprog/pc_link.h"
#include <stdbool.h>
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/debug.h"

#define MAX_SIZE 100

struct pc_link *pc_link_init(tid_t child_tid) {
  struct pc_link *link = (struct pc_link *) malloc (sizeof(struct pc_link));
  if (link == NULL) {
    kernel_exit(-1);
  }

  link->p_tid = thread_tid();
  link->c_tid = child_tid;
  link->c_is_alive = true;

  hash_insert(get_thread_table(), &link->h_elem);
  PUTBUF_FORMAT("\tHash size is now %d", hash_size(get_thread_table()));
  
  sema_init(&(link->waiter), 0);
  
  return link;
}

void pc_link_kill_child(struct pc_link *link, struct thread *child) {
  link->c_exit_code = child->exit_code;
  link->c_is_alive = false;
  sema_up(&link->waiter);
}

void pc_link_free(struct pc_link *link) {
  hash_delete(get_thread_table(), &(link->h_elem));
  free(link);
}

bool tid_less(const struct hash_elem *a, 
    const struct hash_elem *b, void *aux UNUSED) {
  return hash_entry(a, struct pc_link, h_elem)->c_tid
    < hash_entry(b, struct pc_link, h_elem)->c_tid;
}

unsigned tid_func(const struct hash_elem *e, void *aux UNUSED) {
  return hash_entry(e, struct pc_link, h_elem)->c_tid;
}

void free_table(struct hash_elem *e, void *aux UNUSED) {
  free(hash_entry(e, struct pc_link, h_elem));
}

struct pc_link *pc_link_lookup(int c_tid) {
  struct hash *hash = get_thread_table();
  if (!hash_empty(hash)) {
    struct hash_iterator i;

    hash_first (&i, hash);
    while (hash_next (&i)) {
        struct pc_link *link = hash_entry (hash_cur (&i), struct pc_link, h_elem);
        if (link->c_tid == c_tid) {
          return link;
        }
    }
  }
  return NULL;
}

void free_parents(int p_tid) {
  struct hash *hash = get_thread_table();
  struct pc_link *to_remove[MAX_SIZE];
  int index = 0;
  
  if (!hash_empty(hash)) {
    struct hash_iterator i;
    hash_first (&i, hash);

    while (hash_next (&i)) {
      struct pc_link *link = hash_entry (hash_cur (&i), struct pc_link, h_elem);
    
      if (link->p_tid == p_tid) {
        to_remove[index++] = link;
      }
    }

    for (int i = 0; i < index; i++) {
      pc_link_free(to_remove[i]);
    }
  }
}
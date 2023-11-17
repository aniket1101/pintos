#include "userprog/fd.h"
#include <hash.h>
#include <string.h>
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/malloc.h"

static int total_fds; // Total number of fds created

static hash_hash_func fd_hash;
static hash_less_func fd_less;

/* Initialise the fd system. */
void fd_system_init(void) {
  total_fds = 0;
}

/* Initialise thread t's fd hash table. */
void fd_hash_init(struct thread *t) {
  hash_init(&t->fds, &fd_hash, &fd_less, NULL);
}

/* Returns a hash value for a fd */
static unsigned fd_hash(const struct hash_elem *h, void *aux UNUSED) {
  const struct fd *fd = hash_entry (h, struct fd, elem);
  return hash_int (fd->fd_num);
}

/* Returns true if fd a precedes fd b. */
static bool fd_less(const struct hash_elem *a_, const struct hash_elem *b_, 
    void *aux UNUSED) {
  const struct fd *a = hash_entry (a_, struct fd, elem);
  const struct fd *b = hash_entry (b_, struct fd, elem);
  return a->fd_num < b->fd_num;
}

/* Add an fd which points to info to current thread's fds hash table. */
struct fd *fd_add(struct file_info *info) {
	struct fd *fd = (struct fd *) malloc(sizeof(struct fd));
  if (fd == NULL) {
    return NULL;
  }

  fd->file_info = info;
  fd->pos = 0;
  // Increment total numbers of fds (skiping console fds 0 and 1) 
  fd->fd_num = (total_fds++) + 2; 

  info->num_fds++; // Increment number of fds pointing to info

  // Insert fd to current thread's hash, returning NULL if insert fails
  return hash_insert(&thread_current()->fds, &fd->elem) == NULL ? fd : NULL; 
}

/* Search for fd with num fd in current thread's hash table. 
   Returns NULL if fails. */
struct fd *fd_lookup(int fd) {
  struct fd fd_ = {.fd_num = fd}; // Fake element to search for
  struct hash_elem *found_elem = hash_find (&thread_current()->fds, &fd_.elem);

  // Return NULL if find failed, otherwise cast to fd and return
  return found_elem != NULL ? hash_entry (found_elem, struct fd, elem) : NULL; 
} 

/* Search for fd. Call kernel_exit(-1) if lookup fails. */
struct fd *fd_lookup_safe(int fd) {
  struct fd *fd_ = fd_lookup(fd);
  
  // If lookup fails, exit
  if (fd_ == NULL) { 
    kernel_exit(-1);
  }

  return fd_;
}

/* Remove fd from current thread's hashmap. Returns NULL if fails.*/
struct fd *fd_remove(struct fd *fd_) {
  struct hash_elem *removed_elem = hash_delete(&thread_current()->fds, &fd_->elem);
  return removed_elem != NULL ? hash_entry (removed_elem, struct fd, elem) : NULL;
}

/* Free function for fd_hash_destroy(). */
void fd_free(struct hash_elem *h_elem, void *aux UNUSED) {
  free(hash_entry (h_elem, struct fd, elem));
}

/* Destroy current thread's hash table, freeing each fd. */
void fd_hash_destroy(void) {
  hash_destroy(&thread_current()->fds, &fd_free);
}
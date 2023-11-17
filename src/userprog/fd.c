#include "userprog/fd.h"
#include <hash.h>
#include <string.h>
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/malloc.h"

static int total_fds;

static unsigned fd_hash (const struct hash_elem *h, void *aux UNUSED);
static bool fd_less (const struct hash_elem *a_, const struct hash_elem *b_, 
  void *aux UNUSED);

void fd_system_init(void) {
  total_fds = 0;
}

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
#include "userprog/debug.h"
struct fd *fd_add(struct file_info *info) {
  info->num_fds++;

	struct fd *fd = (struct fd *) malloc(sizeof(struct fd));
  fd->file_info = info;
  fd->pos = 0;
  fd->fd_num = (total_fds++) + 2;

  return hash_insert(&thread_current()->fds, &fd->elem) == NULL ? fd : NULL; 
}

struct fd *fd_lookup(int fd) {
  struct fd fd_ = {.fd_num = fd};
  struct hash_elem *found_elem = hash_find (&thread_current()->fds, &fd_.elem);
  return found_elem != NULL ? hash_entry (found_elem, struct fd, elem) : NULL;
} 

struct fd *fd_lookup_safe(int fd) {
  struct fd *fd_ = fd_lookup(fd);
  if (fd_ == NULL) {
    kernel_exit(-1);
  }
  return fd_;
}

struct fd *fd_remove(struct fd *fd_) {
  struct hash_elem *removed_elem = hash_delete(&thread_current()->fds, &fd_->elem);
  return removed_elem != NULL ? hash_entry (removed_elem, struct fd, elem) : NULL;
}

void fd_free(struct hash_elem *h_elem, void *aux UNUSED) {
  free(hash_entry (h_elem, struct fd, elem));
}

void fd_hash_destroy(void) {
  hash_destroy(&thread_current()->fds, &fd_free);
}
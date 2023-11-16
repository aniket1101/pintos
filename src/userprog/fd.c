#include "userprog/fd.h"
#include <hash.h>
#include <string.h>
#include "threads/malloc.h"

static struct hash all_file_infos;  
static int total_fds;


void fd_system_init(void) {
  hash_init(&all_file_infos, &file_info_hash, &file_info_less, NULL);
  total_fds = 0;
}


/* Returns a hash value for a file_info */
unsigned file_info_hash (const struct hash_elem *h, void *aux UNUSED)
{
  const struct file_info *file_info = hash_entry (h, struct file_info, elem);
  return hash_string (file_info->name);
}

/* Returns true if file_info a precedes file_info b. */
bool file_info_less (const struct hash_elem *a_, const struct hash_elem *b_, 
    void *aux UNUSED) {
  const struct file_info *a = hash_entry (a_, struct file_info, elem);
  const struct file_info *b = hash_entry (b_, struct file_info, elem);
  return strcmp(a->name, b->name) < 0;
}

/* Sets up file_info struct when a file is created. Many fields aren't
   initialised because the file hasn't been opened yet.
   Returns NULL if file_info cannot be initialised. */
struct file_info *file_info_init(char name[MAX_FILENAME_SIZE]) {
	struct file_info *info = (struct file_info *) malloc(sizeof(struct file_info));
  if (info == NULL) {
    return NULL;
  }

	info->name = name;
  info->num_fds = 0;
  info->should_remove = false;

  if (hash_insert(&all_file_infos, &info->elem) != NULL) {
    return NULL;
  }

	return info;
}

struct file_info *file_info_lookup(char name[MAX_FILENAME_SIZE]) {
  struct file_info info = {.name = name};
  struct hash_elem *found_elem = hash_find (&all_file_infos, &info.elem);
  return found_elem != NULL ? hash_entry (found_elem, struct file_info, elem) : NULL;
} 


/* Returns a hash value for a fd */
unsigned fd_hash (const struct hash_elem *h, void *aux UNUSED)
{
  const struct fd *fd = hash_entry (h, struct fd, elem);
  return hash_int (fd->fd_num);
}

/* Returns true if fd a precedes fd b. */
bool fd_less (const struct hash_elem *a_, const struct hash_elem *b_, 
    void *aux UNUSED) {
  const struct fd *a = hash_entry (a_, struct fd, elem);
  const struct fd *b = hash_entry (b_, struct fd, elem);
  return a->fd_num < b->fd_num;
}

struct fd *thread_add_fd(struct file_info *info) {
  info->num_fds++;

	struct fd *fd = (struct fd *) malloc(sizeof(struct fd));
  fd->file_info = info;
  fd->pos = 0;
  fd->fd_num = (total_fds++) + 2;
  return hash_insert(&thread_current()->fds, &fd->elem) == NULL ? fd : NULL; 
}

struct fd *thread_remove_fd(int fd, struct thread *t) {
  struct fd fd_ = {.fd_num = fd};
  
  struct hash_elem *removed_elem = hash_delete(&t->fds, &fd_.elem);
  return removed_elem != NULL ? hash_entry (removed_elem, struct fd, elem) : NULL;
}

struct fd *thread_fd_lookup(int fd, struct thread *t) {
  struct fd fd_ = {.fd_num = fd};
  struct hash_elem *found_elem = hash_find (&t->fds, &fd_.elem);
  return found_elem != NULL ? hash_entry (found_elem, struct fd, elem) : NULL;
} 
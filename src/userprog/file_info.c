#include "userprog/file_info.h"
#include <hash.h>
#include <string.h>
#include "userprog/syscall.h"
#include "threads/malloc.h"
#include "threads/synch.h"

struct hash file_info_hash_table;  
struct lock file_info_lock;

static unsigned file_info_hash (const struct hash_elem *h, void *aux UNUSED);
static bool file_info_less (const struct hash_elem *a_, 
    const struct hash_elem *b_, void *aux UNUSED);

void file_info_system_init(void) {
  lock_init(&file_info_lock);
  hash_init(&file_info_hash_table, &file_info_hash, &file_info_less, NULL);
}

/* Returns a hash value for a file_info */
static unsigned file_info_hash (const struct hash_elem *h, void *aux UNUSED) {
  const struct file_info *file_info = hash_entry (h, struct file_info, elem);
  return hash_string (file_info->name);
}

/* Returns true if file_info a precedes file_info b. */
static bool file_info_less (const struct hash_elem *a_, 
    const struct hash_elem *b_, void *aux UNUSED) {
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

	lock_acquire(&file_info_lock);
  if (hash_insert(&file_info_hash_table, &info->elem) != NULL) {
    info = NULL;
  }
	lock_release(&file_info_lock);

	return info;
}

struct file_info *file_info_lookup(char name[MAX_FILENAME_SIZE]) {
	lock_acquire(&file_info_lock);
  struct file_info info = {.name = name};
  struct hash_elem *found_elem = hash_find (&file_info_hash_table, &info.elem);
  struct file_info *found_info = found_elem != NULL ? hash_entry (found_elem, struct file_info, elem) : NULL;
	lock_release(&file_info_lock);
	return found_info;
} 

struct file_info *file_info_remove(struct file_info *info) {
	lock_acquire(&file_info_lock);
  struct hash_elem *removed_elem = hash_delete (&file_info_hash_table, &info->elem);
  struct file_info *removed_info = removed_elem != NULL ? hash_entry (removed_elem, struct file_info, elem) : NULL;
	lock_release(&file_info_lock);
	return removed_info;
}

void file_info_free(struct hash_elem *h_elem, void *aux UNUSED) {
  free(hash_entry (h_elem, struct file_info, elem));
}

void file_info_hash_destroy(void) {
  hash_destroy(&file_info_hash_table, &file_info_free);
}
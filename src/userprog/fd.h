#ifndef USERPROG_FD_H
#define USERPROG_FD_H

#include <hash.h>
#include <debug.h>
#include <stdbool.h>
#include "filesys/off_t.h"
#include "threads/thread.h"

#define MAX_FILENAME_SIZE 14

struct fd {
	int fd_num;
	off_t pos;
	struct file_info *file_info;
	struct hash_elem elem;
};

struct file_info {
  char *name;
	struct file *file;

  int num_fds;
	bool should_remove;

	struct hash_elem elem;
};

struct hash *file_info_get_hash_table(void);
void fd_system_init(void);

unsigned file_info_hash (const struct hash_elem *h, void *aux UNUSED);
bool file_info_less (const struct hash_elem *a_, const struct hash_elem *b_, 
	void *aux UNUSED);

struct file_info *file_info_init(char name[MAX_FILENAME_SIZE]);
struct file_info *file_info_lookup(char name[MAX_FILENAME_SIZE]);
struct file_info *file_info_remove(struct file_info *info);
void file_info_free(struct hash_elem *h_elem, void *aux UNUSED);

unsigned fd_hash (const struct hash_elem *h, void *aux UNUSED);
bool fd_less (const struct hash_elem *a_, const struct hash_elem *b_, 
  void *aux UNUSED);

struct fd *thread_add_fd(struct file_info *info);
struct fd *thread_fd_lookup(int fd, struct thread *t);
struct fd *thread_fd_lookup_safe(int fd, struct thread *t);
struct fd *thread_remove_fd(struct fd *fd_, struct thread *t);
void fd_free(struct hash_elem *h_elem, void *aux UNUSED);

#endif
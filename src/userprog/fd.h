#ifndef USERPROG_FD_H
#define USERPROG_FD_H

#include <hash.h>
#include <debug.h>
#include <stdbool.h>
#include "filesys/off_t.h"
#include "threads/thread.h"
#include "userprog/file_info.h"

#define MAX_FILENAME_SIZE 14

struct fd {
	int fd_num;
	off_t pos;
	struct file_info *file_info;
	struct hash_elem elem;
};

void fd_system_init(void);
void fd_hash_init(struct thread *t);

struct fd *fd_add(struct file_info *info);
struct fd *fd_lookup(int fd);
struct fd *fd_lookup_safe(int fd);
struct fd *fd_remove(struct fd *fd_);

void fd_free(struct hash_elem *h_elem, void *aux UNUSED);
void fd_hash_destroy(void);

#endif
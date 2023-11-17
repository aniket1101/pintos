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
	int fd_num; /* Number used by user processes to access file. */
	off_t pos;  				 /* Current position in the file. */
	struct file_info *file_info; /* File associated with fd. */
	struct hash_elem elem; 		 /* Elem for hash table of fds. */
};

void fd_system_init(void);
void fd_hash_init(struct thread *t);

struct fd *fd_add(struct file_info *info);
struct fd *fd_lookup(int fd);
struct fd *fd_lookup_safe(int fd);
struct fd *fd_remove(struct fd *fd_);

hash_action_func fd_free;
void fd_hash_destroy(void);

#endif
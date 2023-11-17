#ifndef USERPROG_FILE_INFO_H
#define USERPROG_FILE_INFO_H

#include <hash.h>
#include <debug.h>
#include <stdbool.h>
#include "filesys/off_t.h"

#define MAX_FILENAME_SIZE 14

/* Struct to hold information about a created file. */
struct file_info {
  char *name; /* String confined to 14 chars. */
	struct file *file;				  	/* File pointer. NULL until open() called. */	

  int num_fds;			            /* Number of fds pointing to this file. */
	bool should_remove; /* Was remove() called on fd pointing to this file? */

	struct hash_elem elem; 			  /* Allows for hash of file_infos. */
};

void file_info_system_init(void);

struct file_info *file_info_init(char name[MAX_FILENAME_SIZE]);
struct file_info *file_info_lookup(char name[MAX_FILENAME_SIZE]);
struct file_info *file_info_remove(struct file_info *info);

hash_action_func file_info_free;
void file_info_hash_destroy(void);

#endif
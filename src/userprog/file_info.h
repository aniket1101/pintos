#ifndef USERPROG_FILE_INFO_H
#define USERPROG_FILE_INFO_H

#include <hash.h>
#include <debug.h>
#include <stdbool.h>
#include "filesys/off_t.h"

#define MAX_FILENAME_SIZE 14

struct file_info {
  char *name;
	struct file *file;

  int num_fds;
	bool should_remove;

	struct hash_elem elem;
};

void file_info_system_init(void);

struct file_info *file_info_init(char name[MAX_FILENAME_SIZE]);
struct file_info *file_info_lookup(char name[MAX_FILENAME_SIZE]);
struct file_info *file_info_remove(struct file_info *info);

void file_info_free(struct hash_elem *h_elem, void *aux UNUSED);
void file_info_hash_destroy(void);

#endif
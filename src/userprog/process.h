#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/init.h"

#define WORD_SIZE 4 

tid_t process_execute (const char *cmd_line);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* load() helpers. */

bool install_page (void *upage, void *kpage, bool writable);

#endif /* userprog/process.h */

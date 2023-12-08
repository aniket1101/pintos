#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdbool.h>
#include "filesys/off_t.h"
#include "threads/thread.h"

enum page_status {
    FILE,                       /* In the file system */
    SWAPPED                    /* Swapped out */
};

struct supp_page {
    void *vaddr;                /* Virtual memory address for a page */
    enum page_status status;    /* Status of a page */

    struct file *file;
    bool writable;           /* Tracks whether a page can be written to */
    off_t file_offset;
    size_t read_bytes;        /* A page's read bytes */
    size_t zero_bytes;        /* A page's zero bytes */

    size_t swap_slot;
    
    struct hash_elem elem;      /* Allows for hash of pages */
};


void supp_page_table_system_init(void);
void supp_page_table_init(struct thread *t);
struct supp_page *supp_page_put(void *vaddr, enum page_status status, struct file *file, 
		off_t offset, bool writable, size_t read_bytes);
        
// struct supp_page *supp_page_put(void *vaddr, enum page_status status);
struct supp_page *supp_page_lookup(void *vaddr);
bool supp_page_remove(void *vaddr);
void supp_page_table_destroy(struct thread *t);

#endif /* vm/page.h*/

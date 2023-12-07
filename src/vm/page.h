#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "../threads/thread.h"
#include "filesys/off_t.h"


enum page_status {
    SWAPPED,                    /* Swapped out */
    ZERO,                       /* Page completely zeroed out */
    MMAPPED,                    /* Mapped in the filesystem */
    LOADED                      /* Already loaded in */
};

struct supp_page {
    off_t file_offset;
    size_t page_read_bytes;
    struct file *file;
    void *vaddr;                /* Virtual memory address for a page */
    enum page_status status;    /* Status of a page */
    
    uint32_t read_bytes;        /* A page's read bytes */
    uint32_t zero_bytes;        /* A page's zero bytes */
    
    uint8_t *upage;             /* upage for the page */
    bool is_writable;           /* Tracks whether a page can be written to */
    
    struct hash_elem elem;      /* Allows for hash of pages */
};


void supp_page_table_system_init(void);
void supp_page_table_init(struct thread *t);
struct supp_page *supp_page_put(void *vaddr, enum page_status status);
struct supp_page *supp_page_lookup(void *vaddr);
bool supp_page_remove(void *vaddr);
void supp_page_table_destroy(struct thread *t);

#endif /* vm/page.h*/
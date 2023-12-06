#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdbool.h>
#include "filesys/off_t.h"

enum page_status {
    SWAPPED,                    /* Swapped out */
    ZERO,                       /* Page completely zeroed out */
    MMAPPED,                    /* Mapped in the filesystem */
    LOADED                      /* Already loaded in */
};

struct supp_page {
    unsigned file_hash;
    int offset;
    int size;
    void *vaddr;                /* Virtual memory address for a page */
    enum page_status status;         /* Status of a page */
    uint32_t read_bytes;        /* A page's read bytes */
    uint32_t zero_bytes;        /* A page's zero bytes */
    uint8_t *upage;             /* upage for the page */
    bool is_writable;           /* Tracks whether a page can be written to */
    struct hash_elem elem;      /* Allows for hash of pages */
};


bool supp_page_table_init(struct hash *hash_table);
void supp_page_table_destroy(struct hash *hash_table);
struct supp_page *get_supp_page_table(struct hash *hash_table, void *vaddr);
// void add_to_spt(enum page_status status, void *addr, struct file *file, off_t offset, bool is_writable);
void insert_supp_page_table(void *vaddr, enum page_status status);
void remove_supp_page(struct hash *hash_table, void *vaddr);




#endif /* vm/page.h*/
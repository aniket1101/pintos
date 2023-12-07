#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include <stdbool.h>
#include "filesys/off_t.h"

enum page_status {
    FILE,                       /* In the file system */
    ZERO,                       /* Page completely zeroed out */
    SWAPPED                    /* Swapped out */
};

struct supp_page {
    int map_id;
    struct file *file;
    off_t file_offset;
    size_t page_read_bytes;
    enum page_status status;    /* Status of a page */
    void *vaddr;                /* Virtual memory address for a page */
    bool is_writable;           /* Tracks whether a page can be written to */
    struct hash_elem elem;      /* Allows for hash of pages */
};


bool supp_page_table_init(struct hash *hash_table);
void supp_page_table_destroy(struct hash *hash_table);
struct supp_page *get_supp_page_table(struct hash *hash_table, void *vaddr);
void add_to_spt(enum page_status status, void *vaddr, struct file *file, off_t offset, bool is_writable, size_t page_read_bytes);
void remove_supp_page(struct hash *hash_table, void *vaddr);




#endif /* vm/page.h*/
#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

enum page_status {
    LOADED,                     /* Loaded into memorty */
    SWAPPED,                    /* Swapped out */
    ZERO,                       /* Page completely zeroed out */
    LAZY                        /* Lazy loaded */
};

struct supp_page_table_elem {
    void *vaddr;                /* Virtual memory address for a page */
    page_status status;         /* Status of a page */
    uint32_t read_bytes;        /* A page's read bytes */
    uint32_t zero_bytes;        /* A page's zero bytes */
    uint8_t *upage;             /* upage for the page */
    bool is_writable;           /* Tracks whether a page can be written to */
    struct hash_elem elem;      /* Allows for hash of pages */
};

bool supp_page_table_init(struct hash *hash_table);
void supp_page_table_destroy(struct hash *hash_table);
struct supp_page_table_elem *get_supp_page_table(struct hash *hash_table,
                                                              void *vaddr);
struct supp_page_table_elem *insert_supp_page_table(struct hash *hash_table,
                                            struct supp_page_table_elem *elem);



#endif /* vm/page.h*/
#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

struct supp_page_table_elem {
    void *vaddr;                /* Virtual memory address for a page*/
    int status;                 /* Status of a page*/
    struct hash_elem elem;      /* Allows for hash of pages*/
};

bool supp_page_table_init(struct hash *hash_table);
void supp_page_table_destroy(struct hash *hash_table);
struct supp_page_table_elem *get_supp_page_table(struct hash *hash_table,
                                                              void *vaddr);
struct supp_page_table_elem *insert_supp_page_table(struct hash *hash_table,
                                            struct supp_page_table_elem *elem);



#endif /* vm/page.h*/
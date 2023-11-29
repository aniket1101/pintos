#include "vm/page.h"

static hash_hash_func supp_page_table_hash;
static hash_less_func supp_page_table_less;

bool supp_page_table_init(struct hash *hash_table) {
    return hash_init(hash_table, &supp_page_table_hash,
                                 &supp_page_table_less, NULL);
}

void supp_page_table_destroy(struct hash *hash_table) {
    hash_destroy(hash_table, NULL);
}

struct supp_page *get_supp_page_table(struct hash *hash_table,
                                                              void *vaddr) {
    return hash_entry(hash_find(hash_table, vaddr),
     struct supp_page, elem);
}

struct supp_page *insert_supp_page_table(struct hash *hash_table,
                                            struct supp_page *elem) {
    struct hash_elem *el = hash_insert(hash_table, &elem->elem);
    return (el == NULL) ? NULL : hash_entry(el, struct supp_page,
     elem);
}

static unsigned supp_page_table_hash(const struct hash_elem *e, void *aux) {
  struct supp_page *entry = hash_entry(e, struct supp_page, elem);
  return hash_bytes(e, sizeof(void *));
}

static bool supp_page_table_less(const struct hash_elem *a, 
    const struct hash_elem *b, void *aux) {
    return hash_entry(a, struct supp_page, elem)->vaddr
    < hash_entry(b, struct supp_page, elem)->vaddr;
}


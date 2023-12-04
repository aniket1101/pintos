#include "vm/page.h"
#include <stdio.h>
#include "threads/malloc.h"
#include "threads/vaddr.h"

static hash_hash_func supp_page_table_hash;
static hash_less_func supp_page_table_less;

bool supp_page_table_init(struct hash *hash_table) {
    return hash_init(hash_table, &supp_page_table_hash,
                                 &supp_page_table_less, NULL);
}

void supp_page_table_destroy(struct hash *hash_table) {
    hash_destroy(hash_table, NULL);
}

struct supp_page *get_supp_page_table(struct hash *hash_table, void *vaddr) {
    struct supp_page page;
    page.vaddr = vaddr;
    struct hash_elem *entry = hash_find(hash_table, &page.elem);
    return entry == NULL ? NULL : hash_entry(entry, struct supp_page, elem);
}

void insert_supp_page_table(struct hash *hash_table,
                                            void *vaddr,
                                             enum page_status status) {
    ASSERT(hash_table != NULL);
    struct supp_page *el = malloc(sizeof(struct supp_page));
    ASSERT(el != NULL);
    el->vaddr = pg_round_down(vaddr);
    el->status = status;
    struct hash_elem *entry = hash_insert(hash_table, &el->elem);
    if (entry != NULL) {
        hash_entry(entry, struct supp_page, elem)->status = status;
    }
}

static unsigned supp_page_table_hash(const struct hash_elem *e, void *aux) {
  struct supp_page *entry = hash_entry(e, struct supp_page, elem);
  return hash_bytes(entry->vaddr, sizeof(entry->vaddr));
}

static bool supp_page_table_less(const struct hash_elem *a, 
        const struct hash_elem *b, void *aux) {
    return hash_entry(a, struct supp_page, elem)->vaddr
    < hash_entry(b, struct supp_page, elem)->vaddr;
}



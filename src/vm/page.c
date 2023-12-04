#include "vm/page.h"
#include <stdio.h>
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

static hash_hash_func supp_page_table_hash;
static hash_less_func supp_page_table_less;
static void free_page_table(struct hash_elem *elem, void *aux UNUSED);
static void delete_supp_page(struct hash_elem *elem, void *aux UNUSED);

bool supp_page_table_init(struct hash *hash_table) {
    return hash_init(hash_table, &supp_page_table_hash,
                                 &supp_page_table_less, NULL);
}

void supp_page_table_destroy(struct hash *hash_table) {
    ASSERT(hash_table != NULL);
    hash_apply(hash_table, &free_page_table);
    hash_destroy(hash_table, NULL);
}

static void free_page_table(struct hash_elem *elem, void *aux UNUSED) {
    struct supp_page *page = hash_entry(elem, struct supp_page, elem);
    switch(page->status) {
        case LOADED:
            void *kaddr = pagedir_get_page(thread_current()->pagedir,
                                           page->vaddr);
            ASSERT(kaddr != NULL);
            free_frame(kaddr);
            break;
        
        default:
            break;
    }
}

struct supp_page *get_supp_page_table(struct hash *hash_table, void *vaddr) {
    struct supp_page page;
    page.vaddr = vaddr;
    struct hash_elem *entry = hash_find(hash_table, &page.elem);
    return entry == NULL ? NULL : hash_entry(entry, struct supp_page, elem);
}

void insert_supp_page_table(struct hash *hash_table, void *vaddr,
                            enum page_status status) {
    ASSERT(hash_table != NULL);
    struct supp_page *el = (struct supp_page *) malloc(sizeof(struct supp_page));
    ASSERT(el != NULL);
    el->vaddr = pg_round_down(vaddr);
    el->status = status;
    struct hash_elem *entry = hash_insert(hash_table, &(el->elem));
    if (entry != NULL) {
        hash_entry(entry, struct supp_page, elem)->status = status;
    }
}

void remove_supp_page(struct hash *hash_table, void *vaddr) {
    struct supp_page page;
    page.vaddr =vaddr;
    struct hash_elem *elem = hash_delete(hash_table, &page.elem);

    ASSERT(elem != NULL);

    delete_supp_page(elem, NULL);
}

static void delete_supp_page(struct hash_elem *elem, void *aux UNUSED) {
    free(hash_entry(elem, struct supp_page, elem));
}

static unsigned supp_page_table_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct supp_page *entry = hash_entry(e, struct supp_page, elem);
  return hash_bytes(&entry->vaddr, sizeof(entry->vaddr));
}

static bool supp_page_table_less(const struct hash_elem *a, 
        const struct hash_elem *b, void *aux UNUSED) {
    return hash_entry(a, struct supp_page, elem)->vaddr
    < hash_entry(b, struct supp_page, elem)->vaddr;
}



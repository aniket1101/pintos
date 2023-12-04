#include "mmap.h"


static hash_hash_func mmap_link_addr_table_hash;
static hash_less_func mmap_link_addr_table_less;
static hash_hash_func mmap_file_page_table_hash;
static hash_less_func mmap_file_page_table_less;


bool mmap_init(struct hash *hash_table) {
    return hash_init(hash_table, &mmap_link_addr_table_hash,
                                 &mmap_link_addr_table_less, NULL);
}

static unsigned mmap_file_page_table_hash(const struct hash_elem *e, void *aux) {
  struct mmap_file_page *entry = hash_entry(e, struct mmap_file_page, elem);
  return hash_bytes(&entry->page, sizeof(entry->page));
}

static bool mmap_file_page_table_less(const struct hash_elem *a, 
        const struct hash_elem *b, void *aux) {
    return hash_entry(a, struct mmap_file_page, elem)->page
    < hash_entry(b, struct mmap_file_page, elem)->page;
}

static unsigned mmap_link_addr_table_hash(const struct hash_elem *e, void *aux) {
  struct mmap_link_addr *entry = hash_entry(e, struct mmap_link_addr, elem);
  return hash_bytes(&entry->mapid, sizeof(entry->mapid));
}

static bool mmap_link_addr_table_less(const struct hash_elem *a, 
        const struct hash_elem *b, void *aux) {
    return hash_entry(a, struct mmap_link_addr, elem)->mapid
    < hash_entry(b, struct mmap_link_addr, elem)->mapid;
}

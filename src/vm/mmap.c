#include "mmap.h"

bool mmap_table_init(struct hash *hash_table) {
    return hash_init(hash_table, &mmap_table_hash,
                                 &mmap_table_less, NULL);
}

static unsigned mmap_table_hash(const struct hash_elem *e, void *aux) {
  struct mmap_file *entry = hash_entry(e, struct mmap_file, elem);
  return hash_bytes(&entry->vaddr, sizeof(entry->vaddr));
}

static bool mmap_table_less(const struct hash_elem *a, 
        const struct hash_elem *b, void *aux) {
    return hash_entry(a, struct supp_page, elem)->vaddr
    < hash_entry(b, struct supp_page, elem)->vaddr;
}

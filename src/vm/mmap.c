#include "mmap.h"


static hash_hash_func mmap_link_addr_table_hash;
static hash_less_func mmap_link_addr_table_less;
static hash_hash_func mmap_fpt_hash;
static hash_less_func mmap_fpt_less;


bool mmap_init(struct hash *hash_table) {
    return hash_init(hash_table, &mmap_link_addr_table_hash,
                                 &mmap_link_addr_table_less, NULL);
}

bool add_mmap(hash *hash_table, mapid_t mapid, void *start_page,
 void *end_page) {
    struct mapid_link_addr *map_link 
    = (struct mapid_link_addr*) malloc(sizeof(struct mapid_link_addr));
    
    if (map_link == NULL) {
        return false;
    }

    map_link->mapid = mapid;
    map_link->start_page = start_page;
    map_link->end_page = end_page;

    struct hash_elem *elem = hash_insert(hash_table, &map_link->hash_elem);

    return elem == NULL;
 }

 struct mapid_link_addr *get_mmap(struct hash *hash_table, mapid_t mapid) {
    struct mapid_link_addr map_link;
    map_link.mapid = mapid;
    return hash_entry(hash_find(hash_table, map_link.elem),
     struct map_link_addr, elem);
 }

 bool delete_mmap(struct hash *hash_table, mapid_t mapid) {
    struct mapid_link_addr *link = get_mmap(table, mapid);
    struct hash_elem *elem = hash_delete(hash_table, &link->elem);
    return elem != NULL;
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

bool mmap_fpt_init(struct hash *hash_table) {
    return hash_init(hash_table, &mmap_fpt_hash,
                                 &mmap_fpt_less, NULL);
}

static unsigned mmap_fpt_hash(const struct hash_elem *e, void *aux) {
  struct mmap_file_page *entry = hash_entry(e, struct mmap_file_page, elem);
  return hash_bytes(&entry->page, sizeof(entry->page));
}

static bool mmap_fpt_less(const struct hash_elem *a, 
        const struct hash_elem *b, void *aux) {
    return hash_entry(a, struct mmap_file_page, elem)->page
    < hash_entry(b, struct mmap_file_page, elem)->page;
}


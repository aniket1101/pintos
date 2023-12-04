#include "mmap.h"
#include "threads/vaddr.h"


static hash_hash_func mmap_link_addr_table_hash;
static hash_less_func mmap_link_addr_table_less;
static hash_hash_func mmap_fpt_hash;
static hash_less_func mmap_fpt_less;
void delete_mmap_fpt(struct hash_elem *elem, void *aux UNUSED);


bool mmap_init(struct hash *hash_table) {
    return hash_init(hash_table, &mmap_link_addr_table_hash,
                                 &mmap_link_addr_table_less, NULL);
}

bool add_mmap(struct hash *hash_table, mapid_t map_id, void *start_page,
 void *end_page) {
    struct mmap_link_addr *map_link 
    = (struct mmap_link_addr*) malloc(sizeof(struct mmap_link_addr));
    
    if (map_link == NULL) {
        return false;
    }

    map_link->map_id = map_id;
    map_link->start_page = start_page;
    map_link->end_page = end_page;

    struct hash_elem *elem = hash_insert(hash_table, &map_link->elem);

    return elem == NULL;
 }

 struct mmap_link_addr *get_mmap(struct hash *hash_table, mapid_t map_id) {
    struct mmap_link_addr map_link;
    map_link.map_id = map_id;
    return hash_entry(hash_find(hash_table, &map_link.elem),
     struct mmap_link_addr, elem);
 }

 bool delete_mmap(struct hash *hash_table, mapid_t map_id) {
    struct mmap_link_addr *link = get_mmap(hash_table, map_id);
    struct hash_elem *elem = hash_delete(hash_table, &link->elem);
    return elem != NULL;
 }

static unsigned mmap_link_addr_table_hash(const struct hash_elem *e,
 void *aux UNUSED) {
  struct mmap_link_addr *entry = hash_entry(e, struct mmap_link_addr, elem);
  return hash_bytes(&entry->map_id, sizeof(entry->map_id));
}

static bool mmap_link_addr_table_less(const struct hash_elem *a, 
        const struct hash_elem *b, void *aux UNUSED) {
    return hash_entry(a, struct mmap_link_addr, elem)->map_id
    < hash_entry(b, struct mmap_link_addr, elem)->map_id;
}

bool mmap_fpt_init(struct hash *hash_table) {
    return hash_init(hash_table, &mmap_fpt_hash,
                                 &mmap_fpt_less, NULL);
}

bool insert_mmap_fpt(struct hash *hash_table, mapid_t map_id, void *page,
    struct file *file, off_t offset, uint32_t page_space, bool is_writable) {
        struct mmap_file_page *mmap_fp 
    = (struct mmap_file_page*) malloc(sizeof(struct mmap_file_page));
    
    if (mmap_fp == NULL) {
        return false;
    }
    ASSERT(page_space <= PGSIZE);
    mmap_fp->map_id = map_id;
    mmap_fp->page = page;
    mmap_fp->file = file;
    mmap_fp->offset = offset;
    mmap_fp->page_space = page_space;
    mmap_fp->is_writable = is_writable;    

    struct hash_elem *elem = hash_insert(hash_table, &mmap_fp->elem);

    return elem == NULL;
}

struct mmap_file_page *get_mmap_fpt(struct hash *hash_table, void *page) {
    struct mmap_file_page mmap_fp;
    mmap_fp.page = page;
    struct hash_elem *el = hash_find(hash_table, &mmap_fp.elem);
    return el == NULL ? NULL : hash_entry(el, struct mmap_file_page, elem);
}

bool delete_mmap_fp(struct hash *hash_table, struct mmap_file_page *mmap_fp) {
    ASSERT(mmap_fp != NULL);
    struct hash_elem *elem = hash_delete(hash_table, &mmap_fp->elem);
    if (elem != NULL) {
        delete_mmap_fpt(elem, NULL);
    }

    return elem != NULL;
}

void destroy_mmap_fpt(struct hash *hash_table) {
    ASSERT(hash_table != NULL);
    hash_destroy(hash_table, NULL);
}

void delete_mmap_fpt(struct hash_elem *elem, void *aux UNUSED) {
    free(hash_entry(elem, struct mmap_file_page, elem));
}

static unsigned mmap_fpt_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct mmap_file_page *entry = hash_entry(e, struct mmap_file_page, elem);
  return hash_bytes(&entry->page, sizeof(entry->page));
}

static bool mmap_fpt_less(const struct hash_elem *a, 
        const struct hash_elem *b, void *aux UNUSED) {
    return hash_entry(a, struct mmap_file_page, elem)->page
    < hash_entry(b, struct mmap_file_page, elem)->page;
}


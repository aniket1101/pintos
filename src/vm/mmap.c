#include "mmap.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"


static hash_hash_func mmap_entry_hash;
static hash_less_func mmap_entry_less;
void delete_mmap_hash_entry(struct hash_elem *elem, void *aux UNUSED);


bool mmap_init(struct hash *mmap_table) {
    return hash_init(mmap_table, &mmap_entry_hash,
                                 &mmap_entry_less, NULL);
}

bool add_mmap_entry(void *start_page) {
  struct mmap_entry *map_link 
    = (struct mmap_entry*) malloc(sizeof(struct mmap_entry));
    
  if (map_link == NULL) {
      return false;
  }
  map_link->map_id = thread_current()->map_id;
  map_link->start_page = start_page;
  // map_link->end_page = end_page;

  struct hash_elem *elem = hash_insert(&(thread_current()->mmap_table), &map_link->elem);

  return elem != NULL;
}

struct mmap_entry *get_mmap_entry(mapid_t map_id) {
  struct mmap_entry map_link;
  map_link.map_id = map_id;
  return hash_entry(hash_find(&(thread_current()->mmap_table), &map_link.elem),
    struct mmap_entry, elem);
}

bool delete_mmap_entry(mapid_t map_id) {
  struct mmap_entry *link = get_mmap_entry(map_id);
  struct hash_elem *elem = hash_delete(&(thread_current()->mmap_table), &link->elem);
  return elem != NULL;
}

static unsigned mmap_entry_hash(const struct hash_elem *e,
 void *aux UNUSED) {
  struct mmap_entry *entry = hash_entry(e, struct mmap_entry, elem);
  return hash_bytes(&entry->map_id, sizeof(entry->map_id));
}

static bool mmap_entry_less(const struct hash_elem *a, 
        const struct hash_elem *b, void *aux UNUSED) {
    return hash_entry(a, struct mmap_entry, elem)->map_id
    < hash_entry(b, struct mmap_entry, elem)->map_id;
}
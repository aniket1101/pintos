#include "mmap.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "userprog/debug.h"
#include "vm/frame.h"
#include "vm/page.h"

static hash_hash_func mmap_entry_hash;
static hash_less_func mmap_entry_less;
void delete_mmap_hash_entry(struct hash_elem *elem, void *aux UNUSED);
static void mmap_entry_destroy(struct hash_elem *h_elem, void *aux UNUSED);

/* Initialises an mmap table */
bool mmap_init(struct hash *mmap_table) {
  return hash_init(mmap_table, &mmap_entry_hash,
    &mmap_entry_less, NULL);
}

/* Hashes an entry through the map id */
static unsigned mmap_entry_hash(const struct hash_elem *e,
 void *aux UNUSED) {
  struct mmap_entry *entry = hash_entry(e, struct mmap_entry, elem);
  return hash_int(entry->map_id);
}

/* Compares two entries through their hashed value */
static bool mmap_entry_less(const struct hash_elem *a, 
        const struct hash_elem *b, void *aux UNUSED) {
    return hash_entry(a, struct mmap_entry, elem)->map_id
    < hash_entry(b, struct mmap_entry, elem)->map_id;
}

/* Adds an entry to the mmap table */
bool add_mmap_entry(void *start_page, int page_cnt) {
  struct mmap_entry *map_entry
    = (struct mmap_entry*) malloc(sizeof(struct mmap_entry));
    
  if (map_entry == NULL) {
      return false;
  }

  map_entry->map_id = thread_current()->map_id;
  map_entry->start_page = start_page;
  map_entry->page_count = page_cnt;


  struct hash_elem *elem = hash_insert(&(thread_current()->mmap_table), &map_entry->elem);
  thread_current()->map_id++;

  return elem == NULL;
}

/* Returns the mmap entry with the specific map id */
struct mmap_entry *get_mmap_entry(mapid_t map_id) {
  struct mmap_entry map_entry = {.map_id = map_id};
  struct hash_elem *elem = hash_find(&(thread_current()->mmap_table), &(map_entry.elem));
  return elem == NULL ? NULL : hash_entry(elem, struct mmap_entry, elem);
}

/* Deletes the mmap entry with the specific map id */
bool delete_mmap_entry(mapid_t map_id) {
  struct mmap_entry *map_entry = get_mmap_entry(map_id);
  struct hash_elem *elem = hash_delete(&(thread_current()->mmap_table), &map_entry->elem);
  if (elem != NULL) {
    free_mmap_entry(map_entry);
    return true;
  }

  return false;
}

/* Removes all page entries in the spt and frees the mmap entry */
void free_mmap_entry(struct mmap_entry *entry) {
  ASSERT(entry != NULL);
  struct supp_page *page = supp_page_lookup(entry->start_page);
  ASSERT(page != NULL);
  for (void *curr = entry->start_page; 
      curr < entry->start_page + (entry->page_count * PGSIZE);
      curr += PGSIZE) {
      
    /* file system, write bsck, free frsme, remove from psge dir and suppl page table*/
    if (page->file != NULL) {
      validate_get_buffer(curr, PGSIZE);
      file_write_at(page->file, curr, PGSIZE, curr - entry->start_page);
    }

    frame_free(frame_lookup(curr));
    supp_page_remove(curr);
  }
  
  free(entry);
}

/* Removes all page entries in the spt and frees the mmap entry of hash_elem */
static void mmap_entry_destroy(struct hash_elem *h_elem, void *aux UNUSED) {
  struct mmap_entry *entry = hash_entry(h_elem, struct mmap_entry, elem);
  free_mmap_entry(entry);
}

/* Destroys the entire table of the thread */
void mmap_destroy(void) {
  if (!hash_empty(&thread_current()->mmap_table)) {
    hash_destroy(&thread_current()->mmap_table, &mmap_entry_destroy);
  }
}

/* Returns true iff a given address is mapped to a file in the current
   thread. */
bool is_mapped (void *addr) {
  return addr_to_map (addr) != NULL;
}

/* Finds the mmap entry with starting address start */
struct mmap_entry *addr_to_map (void *start) {
  struct hash_iterator i;
  hash_first (&i, &thread_current()->mmap_table);
  while (hash_next (&i)) {
      struct mmap_entry *m = hash_entry (hash_cur (&i), struct mmap_entry, elem);

      ASSERT (m != NULL);

      if (start <= pg_round_down (start) &&
          pg_round_down (start) < start + (m->page_count * PGSIZE))
        return m;
    }
  return NULL;
}

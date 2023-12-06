#include "mmap.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"


static hash_hash_func mmap_link_addr_table_hash;
static hash_less_func mmap_link_addr_table_less;
static hash_hash_func mmap_fpt_hash;
static hash_less_func mmap_fpt_less;
void delete_mmap_fpt(struct hash_elem *elem, void *aux UNUSED);


bool mmap_init(struct hash *hash_table) {
    return hash_init(hash_table, &mmap_link_addr_table_hash,
                                 &mmap_link_addr_table_less, NULL);
}

void add_to_mmap(enum page_status status, void *addr, struct file *file,
                    off_t offset, uint32_t page_space, bool is_writable) {
  off_t read_bytes = file_length(file);
  for (; offset <= read_bytes; offset += PGSIZE) {
    insert_supp_page_table(&(thread_current()->supp_page_table), addr + offset, status);
    insert_mmap_fpt(addr + offset, file, offset, page_space, is_writable);
  }

  add_mmap(addr, offset + addr);

  thread_current()->map_id++;
}

bool add_mmap(void *start_page, void *end_page) {
  struct mmap_link_addr *map_link 
    = (struct mmap_link_addr*) malloc(sizeof(struct mmap_link_addr));
    
  if (map_link == NULL) {
      return false;
  }
  map_link->map_id = thread_current()->map_id;
  map_link->start_page = start_page;
  map_link->end_page = end_page;

  struct hash_elem *elem = hash_insert(&(thread_current()->mmap_link_addr_table), &map_link->elem);

  return elem != NULL;
}

struct mmap_link_addr *get_mmap(mapid_t map_id) {
  struct mmap_link_addr map_link;
  map_link.map_id = map_id;
  return hash_entry(hash_find(&(thread_current()->mmap_link_addr_table), &map_link.elem),
    struct mmap_link_addr, elem);
}

bool delete_mmap(mapid_t map_id) {
  struct mmap_link_addr *link = get_mmap(map_id);
  struct hash_elem *elem = hash_delete(&(thread_current()->mmap_link_addr_table), &link->elem);
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

bool insert_mmap_fpt(void *page,
    struct file *file, off_t offset, uint32_t page_space, bool is_writable) {
  struct mmap_file_page *mmap_fp 
    = (struct mmap_file_page*) malloc(sizeof(struct mmap_file_page));
    
  if (mmap_fp == NULL) {
    return false;
  }
  ASSERT(page_space <= PGSIZE);
  mmap_fp->map_id = thread_current()->map_id;
  mmap_fp->page = page;
  mmap_fp->file = file;
  mmap_fp->offset = offset;
  mmap_fp->page_space = page_space;
  mmap_fp->is_writable = is_writable;    

  struct hash_elem *elem = hash_insert(&(thread_current()->mmap_file_page_table), &mmap_fp->elem);

  return elem != NULL;
}

struct mmap_file_page *get_mmap_fpt(void *page) {
  struct mmap_file_page mmap_fp;
  mmap_fp.page = page;
  struct hash_elem *el = hash_find(&(thread_current()->mmap_file_page_table), &mmap_fp.elem);
  return el == NULL ? NULL : hash_entry(el, struct mmap_file_page, elem);
}

bool delete_mmap_fp(struct mmap_file_page *mmap_fp) {
  ASSERT(mmap_fp != NULL);
  struct hash_elem *elem = hash_delete(&(thread_current()->mmap_file_page_table), &mmap_fp->elem);
  if (elem != NULL) {
    delete_mmap_fpt(elem, NULL);
  }

  return elem != NULL;
}

void destroy_mmap_fpt(void) {
  hash_destroy(&(thread_current()->mmap_file_page_table), NULL);
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
#include <stdlib.h>
#include <stdint.h>
#include <hash.h>
#include <stdbool.h>
#include "filesys/off_t.h"
#include "threads/malloc.h"
#include "vm/page.h"


typedef int mapid_t;

struct mmap_entry {
    mapid_t map_id;
    void *start_page;
    int page_count;
    struct hash_elem elem;
};

bool mmap_init(struct hash *mmap_table);
bool add_mmap_entry(void *start_page, int page_cnt);
bool delete_mmap_entry(mapid_t map_id);
struct mmap_entry *get_mmap_entry(mapid_t map_id);
bool insert_mmap_entry(void *page,
    struct file *file, off_t offset, uint32_t page_space, bool is_writable);
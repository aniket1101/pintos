#include <stdlib.h>
#include <stdint.h>
#include <hash.h>
#include <stdbool.h>
#include "filesys/off_t.h"
#include "threads/malloc.h"
#include "vm/page.h"


typedef int mapid_t;

struct mmap_link_addr {
    mapid_t map_id;
    void *start_page;
    void *end_page;
    struct hash_elem elem;
};

struct mmap_file_page {
    mapid_t map_id;
    void *page;
    struct file *file;
    off_t offset;
    uint32_t page_space;
    bool is_writable;
    struct hash_elem elem;
};

bool mmap_init(struct hash *hash_table);
void add_to_mmap(enum page_status status, void *addr, struct file *file,
                    off_t offset, uint32_t page_space, bool is_writable);
bool add_mmap(void *start_page, void *end_page);
bool delete_mmap(mapid_t map_id);
struct mmap_link_addr *get_mmap(mapid_t map_id);
bool mmap_fpt_init(struct hash *hash_table);
bool insert_mmap_fpt(void *page,
    struct file *file, off_t offset, uint32_t page_space, bool is_writable);
struct mmap_file_page *get_mmap_fpt(void *page);
bool delete_mmap_fp(struct mmap_file_page *mmap_fp);
void destroy_mmap_fpt(void);
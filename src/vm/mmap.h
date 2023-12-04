#include <stdlib.h>
#include <hash.h>

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
    int page_space;
    bool is_writable;
    struct hash_elem h_elem;
}
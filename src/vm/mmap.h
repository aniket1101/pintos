#include <stdlib.h>

typedef int mapid_t;

struct mmap_file {
    int fd;
    int size;
    void *start_page;
    mapid_t map_id;
    struct list page_list;
};

struct mmap_file_page {
    mapid_t map_id;
    void *page;
    struct file *file;
    off_t offset;
    int page_space;
    bool is_writable;
    struct hash_elem h_elem;
    struct list_elem l_elem;
}
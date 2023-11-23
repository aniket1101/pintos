#include <hash.h>

void *frame_get_page(void *upage);

struct frame {
    struct thread *t;
    void *uaddr;
    void *kaddr;
    struct hash_elem elem;
};
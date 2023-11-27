#include <hash.h>

void frame_init(void);
void *frame_get_page(const void *upage);
void put_frame(void *upage);
struct frame *choose_frame(void);
void evict_frame(struct frame *frame);
bool wipe_frame_memory(void *kaddr);
void free_frame(void *kaddr);

struct frame {
    struct thread *t;
    void *uaddr;
    void *kaddr;
    struct hash_elem elem;
};
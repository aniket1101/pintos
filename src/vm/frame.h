#include <hash.h>

void frame_init(void);
struct frame *choose_frame(void);
void *frame_get_page(void *upage);
void frame_evict(struct frame *frame);
bool wipe_frame_memory(void *kaddr);
void free_frame(void *kaddr);

struct frame {
    struct thread *t;
    void *uaddr;
    void *kaddr;
    struct hash_elem elem;
};
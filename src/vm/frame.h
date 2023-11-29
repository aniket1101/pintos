#include <hash.h>
#include "threads/palloc.h"

void frame_init(void);
void *get_frame(void *upage);
void *put_frame(enum palloc_flags flag, void *upage);
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
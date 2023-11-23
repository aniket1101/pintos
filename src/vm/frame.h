#include <hash.h>

static void *frame_get_page(void *upage);
static void evict_frame(struct frame *frame);
static struct frame *choose_frame(void);

struct frame {
    struct thread *t;
    void *uaddr;
    void *kaddr;
    struct hash_elem elem;
};
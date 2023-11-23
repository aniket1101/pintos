#include <hash.h>

static void *frame_get_page(void *upage);
static struct frame *choose_frame(void);
static void evict_frame(struct frame *frame);
static bool wipe_frame_memory(void *kaddr);
static void free_frame(void *kaddr);

struct frame {
    struct thread *t;
    void *uaddr;
    void *kaddr;
    struct hash_elem elem;
};
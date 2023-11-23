#include "frame.h"
#include <hash.h>
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"

static hash_hash_func frame_table_hash;
static hash_less_func frame_table_less;

static struct hash frame_table;
static struct lock frame_lock;

void frame_init(struct hash *frame_table, struct lock *frame_lock) {
    hash_init(&frame_table, &frame_table_hash, &frame_table_less, NULL);
    lock_init(&frame_lock);
}

void *frame_get_page(void *upage) {
    ASSERT(is_user_vaddr(upage));

    void *kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL){
        // evict a frame
        kpage = palloc_get_page(PAL_USER | PAL_ZERO);
        ASSERT(kpage != NULL);
    };

    struct frame *next_frame = (struct frame *) malloc(sizeof(struct frame));

    next_frame->t = thread_current();
    next_frame->kaddr = kpage;
    next_frame->uaddr = upage;

    struct hash_elem *inserted = hash_insert(&frame_table, &next_frame->elem);
    
    if (inserted != NULL) {
        // ERROR: Think of how to implement
    }

    return kpage;
}



static unsigned frame_table_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct frame *frame = hash_entry(e, struct frame, elem);
  return hash_bytes(e, sizeof(void *));
}

static bool frame_table_less(const struct hash_elem *a, 
    const struct hash_elem *b, void *aux UNUSED) {
    return hash_entry(a, struct frame, elem)->kaddr
    < hash_entry(b, struct frame, elem)->kaddr;
}


#include "frame.h"
#include <hash.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/debug.h"

static hash_hash_func frame_table_hash;
static hash_less_func frame_table_less;

static struct hash frame_table;
static struct lock frame_lock;

static void lock_frame_access(void);
static void unlock_frame_access(void);

void frame_init(void) {
    hash_init(&frame_table, &frame_table_hash, &frame_table_less, NULL);
    lock_init(&frame_lock);
}

void *get_frame(void *upage) {
    PUTBUF("IN GET PAGE");
    ASSERT(is_user_vaddr(upage));

    // Find frame with virtual address upage
    struct frame frame = {.uaddr = upage}; // Fake element to search for
    struct hash_elem *found_elem = hash_find (&frame_table, &(frame.elem));

    // If it's not in any frame, cause a page fault
    if (found_elem == NULL) { 
        return NULL;
    }

    // Otherwise we can just return the physical address
    return hash_entry(found_elem, struct frame, elem);
}

void *put_frame(enum palloc_flags flag, void *upage) {
    ASSERT(is_user_vaddr(upage));
    PUTBUF_FORMAT("UPAGE IS: %p", upage);
    void *kpage = palloc_get_page(flag); 
    PUTBUF_FORMAT("KPAGE IS: %p", kpage);   
    lock_frame_access();
    if (kpage == NULL) {
        // evict a frame
        PUTBUF("SHOULD NOT GO INSIDE HERE (evict)");
        evict_frame(choose_frame());
        kpage = palloc_get_page(flag);
        ASSERT(kpage != NULL);
    }

    struct frame *next_frame = (struct frame *) malloc(sizeof(struct frame));

    next_frame->t = thread_current();
    next_frame->kaddr = kpage;
    next_frame->uaddr = upage;

    struct hash_elem *inserted = hash_insert(&frame_table, &(next_frame->elem));
    unlock_frame_access();    

    // if (inserted != NULL) {
    //     PUTBUF("SHOULD NOT GO INSIDE HERE (!inserted)");
    //     kernel_exit(-1);
    // }
    // PUTBUF("FINISHED PUT FRAME");

    return kpage;
}

struct frame *choose_frame(void) {
    struct frame *frame = NULL;

    if (!hash_empty(&frame_table)) {
        struct hash_iterator i;

        hash_first (&i, &frame_table);
        while (hash_next (&i)) {
            frame = hash_entry (hash_cur (&i), struct frame, elem);
        }
    }

    return frame;
}

void evict_frame(struct frame *frame) {
    free_frame(frame->kaddr);
    // kernel_exit(-1);
}

bool wipe_frame_memory(void *kaddr) {
    ASSERT(is_kernel_vaddr(kaddr));
    struct frame frame;
    frame.kaddr = kaddr;
    struct hash_elem *elem = hash_find(&frame_table, &(frame.elem));
    
    if (elem == NULL) {
        return false;
    }

    struct frame *entry = hash_entry(elem, struct frame, elem);
    evict_frame(entry);
    return true;

}

void free_frame(void *kaddr) {
    struct frame frame;
    frame.kaddr = kaddr;

    bool frame_locked = lock_held_by_current_thread(&frame_lock);

    if (!frame_locked) {
        lock_frame_access();
    }

    struct hash_elem *elem = hash_delete(&frame_table, &frame.elem);
    ASSERT(elem != NULL);
    struct frame *freed_frame = hash_entry(elem, struct frame, elem);

    // Frees the page and removes its reference
    pagedir_clear_page(freed_frame->t->pagedir, freed_frame->uaddr);

    palloc_free_page(freed_frame->kaddr);
    free(freed_frame);

    if (!frame_locked) {
        unlock_frame_access();
    }
}

static void lock_frame_access() {
    lock_acquire(&frame_lock);
}

static void unlock_frame_access() {
    lock_release(&frame_lock);
}

static unsigned frame_table_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct frame *frame = hash_entry(e, struct frame, elem);
  return hash_int((uint32_t) frame->kaddr);
}

static bool frame_table_less(const struct hash_elem *a, 
    const struct hash_elem *b, void *aux UNUSED) {
    return hash_entry(a, struct frame, elem)->kaddr
    < hash_entry(b, struct frame, elem)->kaddr;
}


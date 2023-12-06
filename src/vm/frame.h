#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "threads/palloc.h"

struct frame {
    struct thread *t; /* Thread with page in pagedir. */

    void *vaddr;      /* Virtual address of frame's page. */
    void *kaddr;      /* Kernel (physical) address of frame's page. */

    struct hash_elem elem;
};

void frame_table_init(void);

struct frame *frame_put(void *vaddr, enum palloc_flags flag);
struct frame *frame_lookup(void *vaddr);
void *frame_lookup_kaddr(void *vaddr);

void evict_frame(void);
void free_frame(struct frame *frame);
void frame_table_destroy(void);

#endif /* vm/frame.h*/
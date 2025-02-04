#ifndef VM_FRAME_H
#define VM_FRAME_H

#include <hash.h>
#include "threads/palloc.h"
#include <list.h>
#include "filesys/file.h"


struct frame {
    struct thread *t; /* Thread with page in pagedir. */

    void *vaddr;    /* Virtual address of frame's page. */
    void *kaddr;      /* Kernel (physical) address of frame's page. */

    struct hash threads;

    struct hash_elem elem;
};

struct shared_file {
    struct frame *frame;
    struct file *file;
    int offset;
    struct hash_elem elem;
};

struct frame_thread {
    struct thread *t;
    struct hash_elem elem;
};

void frame_table_init(void);

struct frame *frame_put(void *vaddr, enum palloc_flags flag);
struct frame *frame_put_file(void *vaddr, enum palloc_flags flag, struct file *file, int offset);
struct frame *frame_lookup(void *vaddr);
struct frame *frame_kaddr_lookup(void *kaddr);

void evict_frame(void);
void frame_free(struct frame *frame);
void frame_destroy(void *kaddr);

#endif /* vm/frame.h*/
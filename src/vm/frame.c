#include "frame.h"
#include <hash.h>
#include "filesys/file.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "userprog/debug.h"
#include "devices/swap.h"
#include "vm/page.h"
#include "vm/mmap.h"

static hash_hash_func frame_hash;
static hash_less_func frame_less;

static struct hash frame_table;
static struct lock frame_lock;

static int clock_hand;
static struct frame *frame_at_clock;

static struct frame *choose_frame(void);
static struct frame *choose_frame_lru(void);
static struct frame *frame_get_at(int index);

void frame_table_init(void) {
  hash_init(&frame_table, &frame_hash, &frame_less, NULL);
  lock_init(&frame_lock);
  clock_hand = 0;
}

static unsigned frame_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct frame *frame = hash_entry(e, struct frame, elem);
  return hash_int((uint32_t) frame->kaddr);
}

static bool frame_less(const struct hash_elem *a, 
    const struct hash_elem *b, void *aux UNUSED) {
  return hash_entry(a, struct frame, elem)->kaddr
      < hash_entry(b, struct frame, elem)->kaddr;
}

/* Initialise a frame entry with flag and vaddr and insert into frame_table. 
   PAL_USER will be used as a flag whether passed as argument or not. */
struct frame *frame_put(void *vaddr, enum palloc_flags flag) {
  ASSERT(is_user_vaddr(vaddr));
  flag |= PAL_USER;

  lock_acquire(&frame_lock);   

  struct frame *frame = frame_lookup(vaddr);
  // If vaddr already associated with frame, return that frame
  if (frame != NULL) { 
    goto ret; 
  } 

  frame = (struct frame *) malloc(sizeof(struct frame));
  // If malloc failed, return NULL
  if (frame == NULL) {
    goto ret;
  }

  void *kaddr = palloc_get_page(flag);  
  if (kaddr == NULL) { // If no pages left
    evict_frame(); // Evict a frame
    // Get a new page, asserting that there is now a free page
    kaddr = palloc_get_page(PAL_ASSERT | flag); 
  }

  frame->t = thread_current();
  frame->vaddr = vaddr;
  frame->kaddr = kaddr;
  frame->swapped = false;

  ASSERT(hash_insert(&frame_table, &frame->elem) == NULL);

  ret: 
    lock_release(&frame_lock);  
    return frame;
}

struct frame *frame_kaddr_lookup(void *kaddr) {
    // // Find frame with virtual address vaddr
    struct frame frame = {.kaddr = kaddr}; // Fake element to search for
    struct hash_elem *found_elem = hash_find (&frame_table, &frame.elem);

    // Return frame or NULL if no frame found
    return found_elem == NULL ? NULL : hash_entry(found_elem, struct frame, elem);
}

struct frame *frame_lookup(void *vaddr) {
  // // Find frame with kernel address kaddr
  void *kaddr = pagedir_get_page(thread_current()->pagedir, vaddr);
  return kaddr == NULL ? NULL : frame_kaddr_lookup(kaddr);
}

static struct frame *choose_frame_lru(void) {
  struct hash_iterator i;
  hash_first(&i, &frame_table);
  struct frame *f = NULL;
  while (f == NULL) {
    f = hash_entry(hash_next(&i), struct frame, elem);
  }

  return f;
}

void evict_frame(void) {
  struct frame *to_evict = choose_frame();
  ASSERT (to_evict != NULL); 
  frame_free(to_evict);
}

/* Choose the frame to be evicted according to clock replacement algorithm. */
static struct frame *choose_frame(void) {
  if (hash_empty(&frame_table)) {
    return NULL;
  }

  struct hash_iterator i;  
  hash_first (&i, &frame_table);
  
  //Set current element to clock hand
  struct hash_elem *start_elem = NULL;
  for (int index = 0; index <= clock_hand; index++) {
    start_elem = hash_next (&i);
  }
  
  ASSERT(start_elem != NULL);
  while (true) {
    for (struct hash_elem *h = start_elem; h != NULL; h = hash_next(&i)) {
      struct frame *f = hash_entry(h, struct frame, elem);
      if (!pagedir_is_accessed(f->t->pagedir, f->vaddr)) {
        if (pagedir_is_dirty(f->t->pagedir, f->vaddr)) {
          f->swap_slot = swap_out(f->vaddr);
          f->swapped = true;
        }

        clock_hand++;
        return f;
      }

      pagedir_set_accessed(f->t->pagedir, f->vaddr, false);
      
      clock_hand++;
      frame_at_clock = f;
    }
    
    hash_first(&i, &frame_table);
    start_elem = hash_next(&i); 
    clock_hand = 0;
  }
}

void frame_free(struct frame *frame) {
  ASSERT(frame != NULL);
  palloc_free_page(frame->kaddr);
  ASSERT(hash_delete(&frame_table, &frame->elem) != NULL);
  free(frame);
}

static struct frame *frame_get_at(int index) {
  struct hash_iterator iter;
  hash_first(&iter, &frame_table);
  struct hash_elem *h_elem = NULL;
  for (int j = 0; j <= index; j++) {
    h_elem = hash_next(&iter);
    ASSERT (h_elem != NULL);
  }

  return hash_entry(h_elem, struct frame, elem);
}

void frame_destroy(void *kaddr) {
  lock_acquire(&frame_lock);
  struct frame *frame = frame_kaddr_lookup(kaddr);
  if (frame == NULL) {
    palloc_free_page(kaddr);
  } else {
    if (frame_at_clock != NULL 
        && !frame_less(&frame_at_clock->elem, &frame->elem, NULL)) {
      frame_at_clock = frame_get_at(clock_hand--);
    }
    
    if (frame->swapped) {
      swap_drop(frame->swap_slot);
    }
    
    frame_free(frame);
  }

  lock_release(&frame_lock);
} 

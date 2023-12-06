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
#include "devices/swap.h"

static hash_hash_func frame_hash;
static hash_less_func frame_less;
static hash_action_func frame_free_action;

static struct hash frame_table;
static int clock_hand;
static struct lock frame_lock;

static struct frame *choose_frame(void);

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
  lock_acquire(&frame_lock);      

  struct frame *frame = frame_lookup(vaddr);
  // If vaddr already associated with frame, return that frame
  if (frame != NULL) { 
    return frame; 
  } 

  frame = (struct frame *) malloc(sizeof(struct frame));
  // If malloc failed, return NULL
  if (frame == NULL) {
    return frame; 
  }

  void *kaddr = palloc_get_page(PAL_USER | flag);  
  if (kaddr == NULL) { // If no pages left
    evict_frame(); // Evict a frame
    // Get a new page, asserting that there is now a free page
    kaddr = palloc_get_page(PAL_USER | PAL_ASSERT | flag); 
  }

  frame->t = thread_current();
  frame->vaddr = vaddr;
  frame->kaddr = kaddr;

  hash_insert(&frame_table, &frame->elem);
  // if (hash_insert(&frame_table, &frame->elem) != NULL) {
  //   frame = NULL; // Return NULL if hash_insert fails
  // }

  lock_release(&frame_lock);    
  return frame;
}

struct frame *frame_lookup(void *vaddr) {
    // Find frame with virtual address vaddr
    struct frame frame = {.vaddr = vaddr}; // Fake element to search for
    struct hash_elem *found_elem = hash_find (&frame_table, &frame.elem);

    // Return frame or NULL if no frame found
    return found_elem == NULL ? NULL : hash_entry(found_elem, struct frame, elem);
}

void *frame_lookup_kaddr(void *vaddr) {
  return frame_lookup(vaddr)->kaddr;
}

void evict_frame(void) {
  struct frame *to_evict = choose_frame();
  if (to_evict == NULL) {
    kernel_exit(-1);
  }
  
  free_frame(to_evict);
}

/* Choose the frame to be evicted according to clock replacement algorithm. */
static struct frame *choose_frame(void) {
  lock_acquire(&frame_lock);
  if (hash_empty(&frame_table)) {
    lock_release(&frame_lock);
    return NULL;
  }
  
  struct hash_iterator i;  
  hash_first (&i, &frame_table);

  // Set current element to clock hand
  for (int index = 0; index < clock_hand; index++) {
    hash_next (&i);
  }

  while (true) {
    struct frame *frame = hash_entry(hash_cur(&i), struct frame, elem);
    // havent checked for aliases?
    if (!pagedir_is_accessed(frame->t->pagedir, frame->vaddr)) {
      if (pagedir_is_dirty(frame->t->pagedir, frame->vaddr)) {
        // need to check if its in mmap?
        swap_in(frame->vaddr, sizeof(frame));
      }
    
      lock_release(&frame_lock);
      return frame;
    }
    
    pagedir_set_accessed(frame->t->pagedir, frame->vaddr, false);

    clock_hand++;
    
    // Sets iterator to next element, checking if its the end of the hash
    if (hash_next (&i)) {
      hash_first (&i, &frame_table);
      clock_hand = 0;
    } 
  }
}

void free_frame(struct frame *frame) {
  frame_free_action(&frame->elem, NULL);
}

/* Free function for frame_table_destroy(). */
static void frame_free_action(struct hash_elem *elem, void *aux UNUSED) {
  lock_acquire(&frame_lock);
  free(hash_entry(elem, struct frame, elem));
  lock_release(&frame_lock);
}

/* Destroy frame page table, freeing each frame. */
void frame_table_destroy(void) {
	hash_destroy(&frame_table, &frame_free_action);
}

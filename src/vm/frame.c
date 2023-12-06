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
#include "filesys/file.h"

static hash_hash_func frame_hash;
static hash_less_func frame_less;
static hash_hash_func file_hash_hash;
static hash_less_func file_less;

static struct hash frame_table;
static struct hash shared_files;
static struct lock frame_lock;
static int clock_hand;

static struct frame *choose_frame(void);

void frame_table_init(void) {
  hash_init(&frame_table, &frame_hash, &frame_less, NULL);
  lock_init(&frame_lock);
  clock_hand = 0;
  hash_init(&shared_files, &file_hash_hash, &file_less, NULL);
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

static unsigned file_hash_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct shared_file *shared_file = hash_entry(e, struct shared_file, elem);
  return (file_hash(shared_file->file) * shared_file->offset);
}

static bool file_less(const struct hash_elem *a, 
    const struct hash_elem *b, void *aux) {
  return file_hash_hash(a, aux) < file_hash_hash(b, aux);
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

void evict_frame(void) {
  struct frame *to_evict = choose_frame();
  ASSERT (to_evict == NULL); 
  frame_free(to_evict);
}

/* Choose the frame to be evicted according to clock replacement algorithm. */
static struct frame *choose_frame(void) {
  if (hash_empty(&frame_table)) {
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

void frame_free(struct frame *frame) {
  ASSERT(frame != NULL);
  palloc_free_page(frame->kaddr);
  ASSERT(hash_delete(&frame_table, &frame->elem) != NULL);
  free(frame);
}

void frame_destroy(void *kaddr) {
  lock_acquire(&frame_lock);
  struct frame *frame = frame_kaddr_lookup(kaddr);
  if (frame == NULL) {
    palloc_free_page(kaddr);
  } else {
    frame_free(frame);
  }
  lock_release(&frame_lock);
} 

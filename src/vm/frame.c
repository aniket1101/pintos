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
#include "userprog/process.h"

static hash_hash_func frame_hash;
static hash_less_func frame_less;
static hash_hash_func file_hash_hash;
static hash_less_func file_less;
static hash_hash_func frame_thread_hash;
static hash_less_func frame_thread_less;
static hash_action_func frame_thread_destroy;

static struct hash frame_table;
static struct hash shared_files;
static struct lock frame_lock;
static struct lock shared_file_lock;

static int clock_hand;
static struct frame *frame_at_clock;

static struct frame *choose_frame(void);
static struct frame *frame_get_at(int index);
bool frame_is_accessed(struct frame *frame);
void set_accessed_false(struct frame *frame);
void remove_thread(struct frame *frame);
struct shared_file *get_shared_file(struct frame *frame);

void frame_table_init(void) {
  hash_init(&frame_table, &frame_hash, &frame_less, NULL);
  lock_init(&frame_lock);
  lock_init(&shared_file_lock);
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

struct frame *frame_put_file(void *vaddr, enum palloc_flags flag, struct file *file, int offset) {
  struct shared_file s_file;
  s_file.file = file;
  s_file.offset = offset;
  struct hash_elem *elem = hash_find(&shared_files, &(s_file.elem));
  struct frame *frame;
  if (elem == NULL) {
    // Shared file is not in a frame yet
    struct shared_file *shared_file = (struct shared_file *) malloc (sizeof (struct shared_file));
    frame = frame_put(vaddr, flag);
    shared_file->frame = frame;
    shared_file->file = file;
    shared_file->offset = offset;
    hash_insert(&shared_files, &(shared_file->elem));
  } else {
    // Shared file is in frame
    frame = hash_entry(elem, struct shared_file, elem)->frame;
    struct frame_thread *frame_thread = (struct frame_thread *) malloc (sizeof (struct frame_thread));
    frame_thread->t = thread_current();
    install_page(frame->vaddr, frame->kaddr, false);
    hash_insert(&(frame->threads), &(frame_thread->elem));
  }

  return frame;
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
  hash_init(&(frame->threads), &frame_thread_hash, &frame_thread_less, NULL);
  frame->vaddr = vaddr;
  frame->kaddr = kaddr;
  frame->swapped = false;
  struct frame_thread *frame_thread = (struct frame_thread *) malloc (sizeof (struct frame_thread));
  frame_thread->t = thread_current();
  hash_insert(&(frame->threads), &(frame_thread->elem));

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
  ASSERT (to_evict != NULL);
  lock_acquire(&frame_lock);
  frame_free(to_evict);
  lock_release(&frame_lock);
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
      if (!frame_is_accessed(f)) {
        if (hash_size(&(f->threads)) == 1) {
          // dirty case will not be for shared files so we know threads size is 1
          struct hash_iterator i;
          hash_first (&i, &(f->threads));
          struct frame_thread *frame_thread = hash_entry (hash_cur (&i), struct frame_thread, elem);
          if (pagedir_is_dirty(frame_thread->t->pagedir, f->vaddr)) {
            f->swap_slot = swap_out(f->vaddr);
            f->swapped = true;
          }
        }
        clock_hand++;
        return f;
      }

      clock_hand++;
      frame_at_clock = f;
    }
    
    hash_first(&i, &frame_table);
    start_elem = hash_next(&i); 
    clock_hand = 0;
  }
}

bool frame_is_accessed(struct frame *frame) {
  // Called from choose frame so frame lock is acquired
  if (!hash_empty(&(frame->threads))) {
    struct hash_iterator i;
    hash_first (&i, &(frame->threads));

    while (hash_next (&i)) { // Loop through the hash
      struct frame_thread *frame_thread = hash_entry (hash_cur (&i), struct frame_thread, elem);
      if (pagedir_is_accessed(frame_thread->t->pagedir, frame->vaddr)) {
        set_accessed_false(frame);
        return true;
      }
    }
  }
  return false;
}

void set_accessed_false(struct frame *frame) {
  // Called from choose frame so frame lock is acquired
    if (!hash_empty(&(frame->threads))) {
    struct hash_iterator i;
    hash_first (&i, &(frame->threads));

    while (hash_next (&i)) { // Loop through the hash
      struct frame_thread *frame_thread = hash_entry (hash_cur (&i), struct frame_thread, elem);
      pagedir_set_accessed(frame_thread->t->pagedir, frame->vaddr, false);
    }
  }
}

void frame_free(struct frame *frame) {
  ASSERT(frame != NULL);
  frame->t = thread_current();
  if (hash_size(&(frame->threads)) == 1) {
    // thread_current is the only thread in the frame
    struct hash_iterator i;
    hash_first (&i, &(frame->threads));
    struct frame_thread *frame_thread = hash_entry (hash_cur (&i), struct frame_thread, elem);
    // if (pagedir_is_dirty(frame_thread->t->pagedir, frame->vaddr)) {
      // struct supp_page *page = supp_page_lookup(frame->vaddr);
      // file_write_at(page->file, frame->vaddr, page->read_bytes, page->file_offset);
    // }
  }

  hash_destroy(&(frame->threads), &frame_thread_destroy);

  struct shared_file *shared_file = get_shared_file(frame);
  if (shared_file != NULL) {
    lock_acquire(&shared_file_lock);
    hash_delete(&shared_files, &(shared_file->elem));
    lock_release(&shared_file_lock);
    free(shared_file);
  }
  ASSERT(hash_delete(&frame_table, &frame->elem) != NULL);
  palloc_free_page(frame->kaddr);
  free(frame);
}

struct shared_file *get_shared_file(struct frame *frame) {
  lock_acquire(&shared_file_lock);
  if (!hash_empty(&shared_files)) {
    struct hash_iterator i;
    hash_first (&i, &shared_files);

    while (hash_next (&i)) { // Loop through the hash
      struct shared_file *s_file = hash_entry (hash_cur (&i), struct shared_file, elem);
      if (frame == s_file->frame) {
        lock_release(&shared_file_lock);
        return s_file;
      }
    }
  }

  lock_release(&shared_file_lock);
  return NULL;
}

static struct frame *frame_get_at(int index) {
  lock_acquire(&frame_lock);  
  struct hash_iterator iter;
  hash_first(&iter, &frame_table);
  struct hash_elem *h_elem = NULL;
  for (int j = 0; j <= index; j++) {
    h_elem = hash_next(&iter);
    ASSERT (h_elem != NULL);
  }
  struct frame *frame = hash_entry(h_elem, struct frame, elem);
  lock_release(&frame_lock);  

  return frame;
}

void frame_destroy(void *kaddr) {
  lock_acquire(&frame_lock);
  struct frame *frame = frame_kaddr_lookup(kaddr);
  if (frame != NULL) {
    if (hash_size(&(frame->threads)) == 1) {
      if (frame_at_clock != NULL 
          && !frame_less(&frame_at_clock->elem, &frame->elem, NULL)) {
        frame_at_clock = frame_get_at(clock_hand--);
      }
      if (frame->swapped) {
        swap_drop(frame->swap_slot);
      }
      frame_free(frame);
    } else {
      remove_thread(frame);
    }
  }

  lock_release(&frame_lock);
} 

void frame_thread_destroy (struct hash_elem *e, void *aux UNUSED) {
  free(hash_entry(e, struct frame_thread, elem));
}

void remove_thread(struct frame *frame) {
  struct frame_thread ft;
  ft.t = thread_current();
  struct hash_elem *elem = hash_delete(&(frame->threads), &(ft.elem));
  if (elem != NULL) {
    free(hash_entry(elem, struct frame_thread, elem));
  }
}

static unsigned frame_thread_hash(const struct hash_elem *e, void *aux UNUSED) {
  return hash_int(hash_entry(e, struct frame_thread, elem)->t->tid);
}

static bool frame_thread_less(const struct hash_elem *a, 
    const struct hash_elem *b, void *aux) {
  return frame_thread_hash(a, aux) < frame_thread_hash(b, aux);
}
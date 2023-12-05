#include "vm/page.h"
#include <stdio.h>
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "vm/frame.h"

static hash_hash_func supp_page_hash;
static hash_less_func supp_page_less;
static hash_action_func supp_page_free;

static struct lock supp_page_table_lock;

void supp_page_table_system_init(void) {
	lock_init(&supp_page_table_lock);
}

/* Initialise thread t's supplemental page table. */
void supp_page_table_init(struct thread *t) {
	hash_init(&t->supp_page_table, &supp_page_hash, &supp_page_less, NULL);
}

static unsigned supp_page_hash(const struct hash_elem *e, void *aux UNUSED) {
  struct supp_page *entry = hash_entry(e, struct supp_page, elem);
  return hash_bytes(&entry->vaddr, sizeof(entry->vaddr));
}

static bool supp_page_less(const struct hash_elem *a, 
		const struct hash_elem *b, void *aux UNUSED) {
	return hash_entry(a, struct supp_page, elem)->vaddr
			< hash_entry(b, struct supp_page, elem)->vaddr;
}

/* Initialise a supp_page entry with a vaddr and page_status and 
	 insert to current thread's page table. */
struct supp_page *supp_page_init(void *vaddr, enum page_status status) {
	ASSERT(&thread_current()->supp_page_table != NULL);
	struct supp_page *supp_page = (struct supp_page *) malloc(sizeof(struct supp_page));
	if (supp_page == NULL) { // If malloc failed, return NULL
		return NULL;
	}

	supp_page->vaddr = pg_round_down(vaddr);
	supp_page->status = status;
	
	lock_acquire(&supp_page_table_lock);
	// Insert supp_page to current thread's page table
	if (hash_insert(&thread_current()->supp_page_table, &supp_page->elem) != NULL) { 
		supp_page = NULL; // page is NULL if insert failed
	}

	lock_release(&supp_page_table_lock);
	return supp_page;
}

/* Find supp_page with vaddr in current thread's hash table.
	 Returns NULL if nothing found. */
struct supp_page *supp_page_lookup(void *vaddr) {
    struct supp_page page = {.vaddr = vaddr};
    struct hash_elem *found_elem // Return NULL if no supp_page found
			= hash_find(&thread_current()->supp_page_table, &page.elem);
    return found_elem == NULL ? NULL : hash_entry(found_elem, struct supp_page, elem);
}

/* Remove supp_page with vaddr from current thread's supp page table. 
	 Returns NULL if cannot be removed. */
bool supp_page_remove(void *vaddr) {
	/* Find page in current thread's table with vaddr. */
	struct supp_page *supp_page = supp_page_lookup(vaddr); 
	if (supp_page == NULL) { // Return false if no vaddr found
		return false; 
	} 

	lock_acquire(&supp_page_table_lock);

	struct hash_elem *removed_elem // Delete page from current thread's table
		= hash_delete(&thread_current()->supp_page_table, &supp_page->elem);

	lock_release(&supp_page_table_lock);

	if (removed_elem != NULL) { // If elem was removed, free it
		supp_page_free(removed_elem, NULL);
		return true;
	}

	return false; // Return false if no element removed
}

/* Free function for supp_page_table_destroy(). */
static void supp_page_free(struct hash_elem *elem, void *aux UNUSED) {
	struct supp_page *page = hash_entry(elem, struct supp_page, elem);
	if (page->status == LOADED) { // If page was loaded, free the frame
		void *kaddr = pagedir_get_page(thread_current()->pagedir,	page->vaddr);
		if (kaddr != NULL) {
			free_frame(kaddr);	
		}
	}

	free(page);
}

/* Destroy thread t's supp_page hash table, freeing each entry. */
void supp_page_table_destroy(struct thread *t) {
	hash_destroy(&t->supp_page_table, &supp_page_free);
}

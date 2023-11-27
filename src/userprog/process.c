#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <user/syscall.h>
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "userprog/fd.h"
#include "userprog/pc_link.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "debug.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include <hash.h>

#define PUSH_ESP(val, type) \
  if_->esp -= sizeof(type); \
  *((type *) if_->esp) = val

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Struct to pass program information to start process */
struct arg {
  bool start_failed;     /* Checks if loading file has failed. */ 
  struct semaphore sema; /* Waits for start_process to finish. */ 
  int c;                 /* Number of arguments. */
  char v[];              /* String of arguments, separated by '\0'. */
};

static inline void push_args(struct intr_frame *if_, struct arg *arg);
static void load_error(struct arg *arg) NO_RETURN;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *cmd_line) 
{
  tid_t tid;
  const int size = strlen(cmd_line) + 1; // Calculate size of cmd_line
  if (size >= PGSIZE) { // If cmd_line is larger than a single page, return -1
    return TID_ERROR;
  }

  /* Make a copy of cmd_line.
     Otherwise there's a race between the caller and load(). */
  char fn_copy[size];
  strlcpy (fn_copy, cmd_line, size);

  struct arg *arg = palloc_get_page(PAL_ZERO); // Allocate page for args
  if (arg == NULL) { // If palloc failed, return -1
    return TID_ERROR;
  }

  sema_init(&arg->sema, 0); // Initialise start_process waiting sema

  int i = 0; // Index to iterate through arg->v
  char *token, *save_ptr; // Helper variables for strtok_r
  
  // Tokenize fn_copy by spaces
  for (token = strtok_r (fn_copy, " ", &save_ptr); token != NULL;
      token = strtok_r (NULL, " ", &save_ptr)) {

    // Copy token to correct position in arg->v
    strlcpy(arg->v + i, token, strlen(token) + 1);
    
    i += strlen(token) + 1; // Increment index by token size
    arg->c++; // Increment number of arguments
  }

  // If size of args is larger than single page, return -1
  if (i + (WORD_SIZE * (arg->c + 4)) >= PGSIZE) {
    palloc_free_page (arg); 
    return TID_ERROR;
  }

  // Create a new thread to execute cmd_line
  tid = thread_create (arg->v, PRI_DEFAULT, start_process, arg);
  
  // Wait until start_process has finished exuting before returning 
  sema_down(&arg->sema); 
  if (arg->start_failed) { // If start_process() fails, return -1
    tid = TID_ERROR;
  }

  palloc_free_page (arg);
  return tid;
}


/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *arg_)
{
  struct arg *arg = arg_; // Cast void pointer to arg struct
  struct intr_frame if_; 
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (arg->v, &if_.eip, &if_.esp);

  /* If load failed, return -1 from process_execute() and quit */
  if (!success) {
    load_error(arg);
  } 

  lock_filesys_access();
  // Open executable and deny writing to it 
  struct file *file = filesys_open(arg->v); 
  if (file != NULL) {
    file_deny_write(file);
    thread_current()->file = file;
    thread_current()->is_writable = false;
  }
  unlock_filesys_access();

  push_args(&if_, arg); // Push arguments onto the stack

  sema_up(&arg->sema); // Stop waiting for start_process() to finish

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Ensure process_execute() returns -1 and quit. */
static void load_error(struct arg *arg) {
  arg->start_failed = true;
  sema_up(&arg->sema);
  thread_exit();
}

/* Push arguments in v onto the stack and update the stack pointer (esp)*/
static inline void push_args(struct intr_frame *if_, struct arg *arg) {
  if (if_->esp != PHYS_BASE) { // If esp is invalid, quit
    load_error(arg);
  }

  void *arg_ptrs[arg->c]; // Array to hold pointers to arg strings on the stack  

  /* Push arguments on the stack */
  int index = 0; // Index of arg->v string
  for (int i = 0; i < arg->c; i++) {
    int size = strlen(arg->v + index) + 1; // Get size of arg

    if_->esp -= size; // Decrease esp to make room to save arg
    strlcpy(if_->esp, arg->v + index, size); // Copy arg string onto stack
    arg_ptrs[i] = if_->esp; // Save ptr to arg

    index += size; // Continue to next string in arg->v
  }

  /* Word align the stack pointer */
  int alignment = ((uint32_t) if_->esp) % WORD_SIZE;
  
  if_->esp -= alignment; //Decrease by alignment

  /* Push a null pointer sentinel on the stack */
  PUSH_ESP(NULL, void *);

 
  /* Push pointers to arguments on the stack */
  for (int i = arg->c - 1; i >= 0; i--) {
    PUSH_ESP(arg_ptrs[i], void *); // Push saved pointer onto stack
  }

  /* Push first pointer on the stack */
  PUSH_ESP(if_->esp + WORD_SIZE, void *); // Last pushed ptr is WORD_SIZE above

  /* Push the number of arguments on the stack */
  PUSH_ESP(arg->c, int);

  /* Push a fake return address on the stack */
  PUSH_ESP(NULL, void *);

  if (if_->esp <= PHYS_BASE - PGSIZE) { // If stack overflow occurs, quit
    load_error(arg);
  }
}

/* Waits for thread TID to die and returns its exit status. 
 * If it was terminated by the kernel (i.e. killed due to an exception), 
 * returns -1.  
 * If TID is invalid or if it was not a child of the calling process, or if 
 * process_wait() has already been successfully called for the given TID, 
 * returns -1 immediately, without waiting.
 * 
 * This function will be implemented in task 2.
 * For now, it does nothing. */
int
process_wait (tid_t child_tid) 
{
  // If child_tid input is the error tid, we should not wait
  if (child_tid == TID_ERROR) {
    return TID_ERROR;
  }

  struct pc_link *link = pc_link_lookup(child_tid);

  if (link == NULL) {
    // Kernel thread would not call exec, we would need to add it to our hash
    if (thread_tid() == 1) {
      link = pc_link_init(child_tid);
    } else {
      // A wait has already been done or the child was not in the hash
      return TID_ERROR;
    }
  } else {
    // Link isn't null, we need to verify that the thread calling is the parent
    if (link->parent_tid != thread_tid()) {
      return TID_ERROR;
    }

  }

    // Checks if child exit code is already available, if not, call sema_down
  if (link->child_alive) {
    sema_down(&link->waiter);
  }

  // Removes from the hash and frees link as wait has completed
  int exit_code = link->child_exit_code;
  pc_link_remove(link);
  free(link);

  return exit_code;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();

  fd_hash_destroy(); // Destroy this thread's hash table of fds

  lock_filesys_access();
  // Allow this executable to be written to
  if (cur->file != NULL) {
    file_allow_write(cur->file);
    file_close(cur->file);
  }
  unlock_filesys_access();

  pc_link_kill_child(cur); // Set associated pc_link struct's child exit code
  pc_link_free_parents(cur->tid); // Free all pc_link structs cur is parent of

  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,'
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  lock_filesys_access();
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  unlock_filesys_access();
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;
      
      /* Check if virtual page already allocated */
      struct thread *t = thread_current ();
      uint8_t *kpage = pagedir_get_page (t->pagedir, upage);
      
      if (kpage == NULL){
        
        /* Get a new page of memory. */
        kpage = palloc_get_page (PAL_USER);
        if (kpage == NULL){
          return false;
        }
        
        /* Add the page to the process's address space. */
        if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }     
        
      } else {
        
        /* Check if writable flag for the page should be updated */
        if(writable && !pagedir_is_writable(t->pagedir, upage)){
          pagedir_set_writable(t->pagedir, upage, writable); 
        }
        
      }

      /* Load data into the page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes){
        return false; 
      }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

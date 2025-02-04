#include "userprog/exception.h"
#include <inttypes.h>
#include <stdio.h>
#include <debug.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/file.h"
#include "userprog/gdt.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/debug.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/mmap.h"
#include "devices/swap.h"
#include "userprog/pagedir.h"
#include <string.h>
#include "debug.h"

#define STACK_LIMIT (8 << 20)
#define PUSHA_OVERFLOW 32
#define PUSH_OVERFLOW 4
#define EAX_ERR 0xffffffff

static void exception_exit(struct intr_frame *f) NO_RETURN;
static bool should_grow_stack(void *fault_addr, void *vaddr, void *esp);

/* Number of page faults processed. */
static long long page_fault_cnt;

static void kill (struct intr_frame *);
static void page_fault (struct intr_frame *);

/* Registers handlers for interrupts that can be caused by user
   programs.

   In a real Unix-like OS, most of these interrupts would be
   passed along to the user process in the form of signals, as
   described in [SV-386] 3-24 and 3-25, but we don't implement
   signals.  Instead, we'll make them simply kill the user
   process.

   Page faults are an exception.  Here they are treated the same
   way as other exceptions, but this will need to change to
   implement virtual memory.

   Refer to [IA32-v3a] section 5.15 "Exception and Interrupt
   Reference" for a description of each of these exceptions. */
void
exception_init (void) 
{
  /* These exceptions can be raised explicitly by a user program,
     e.g. via the INT, INT3, INTO, and BOUND instructions.  Thus,
     we set DPL==3, meaning that user programs are allowed to
     invoke them via these instructions. */
  intr_register_int (3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
  intr_register_int (4, 3, INTR_ON, kill, "#OF Overflow Exception");
  intr_register_int (5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

  /* These exceptions have DPL==0, preventing user processes from
     invoking them via the INT instruction.  They can still be
     caused indirectly, e.g. #DE can be caused by dividing by
     0.  */
  intr_register_int (0, 0, INTR_ON, kill, "#DE Divide Error");
  intr_register_int (1, 0, INTR_ON, kill, "#DB Debug Exception");
  intr_register_int (6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
  intr_register_int (7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
  intr_register_int (11, 0, INTR_ON, kill, "#NP Segment Not Present");
  intr_register_int (12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
  intr_register_int (13, 0, INTR_ON, kill, "#GP General Protection Exception");
  intr_register_int (16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
  intr_register_int (19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

  /* Most exceptions can be handled with interrupts turned on.
     We need to disable interrupts for page faults because the
     fault address is stored in CR2 and needs to be preserved. */
  intr_register_int (14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Prints exception statistics. */
void
exception_print_stats (void) 
{
  printf ("Exception: %lld page faults\n", page_fault_cnt);
}

/* Handler for an exception (probably) caused by a user process. */
static void
kill (struct intr_frame *f) 
{
  /* This interrupt is one (probably) caused by a user process.
     For example, the process might have tried to access unmapped
     virtual memory (a page fault).  For now, we simply kill the
     user process.  Later, we'll want to handle page faults in
     the kernel.  Real Unix-like operating systems pass most
     exceptions back to the process via signals, but we don't
     implement them. */
     
  /* The interrupt frame's code segment value tells us where the
     exception originated. */
  switch (f->cs)
    {
    case SEL_UCSEG:
      /* User's code segment, so it's a user exception, as we
         expected.  Kill the user process.  */
      printf ("%s: dying due to interrupt %#04x (%s).\n",
              thread_name (), f->vec_no, intr_name (f->vec_no));
      intr_dump_frame (f);
      thread_exit (); 

    case SEL_KCSEG:
      /* Kernel's code segment, which indicates a kernel bug.
         Kernel code shouldn't throw exceptions.  (Page faults
         may cause kernel exceptions--but they shouldn't arrive
         here.)  Panic the kernel to make the point.  */
      intr_dump_frame (f);
      PANIC ("Kernel bug - unexpected interrupt in kernel"); 

    default:
      /* Some other code segment?  
         Shouldn't happen.  Panic the kernel. */
      printf ("Interrupt %#04x (%s) in unknown segment %04x\n",
             f->vec_no, intr_name (f->vec_no), f->cs);
      PANIC ("Kernel bug - this shouldn't be possible!");
    }
}

/* Page fault handler.  This is a skeleton that must be filled in
   to implement virtual memory.  Some solutions to task 2 may
   also require modifying this code.

   At entry, the address that faulted is in CR2 (Control Register
   2) and information about the fault, formatted as described in
   the PF_* macros in exception.h, is in F's error_code member.  The
   example code here shows how to parse that information.  You
   can find more information about both of these in the
   description of "Interrupt 14--Page Fault Exception (#PF)" in
   [IA32-v3a] section 5.15 "Exception and Interrupt Reference". */
static void
page_fault (struct intr_frame *f) 
{
   bool not_present UNUSED;  /* True: not-present page, false: writing r/o page. */
   bool write UNUSED; /* True: access was write, false: access was read. */
   bool user;  /* True: access by user, false: access by kernel. */
   void *fault_addr;  /* Fault address. */
   struct thread *t = thread_current(); /* The current thread. */

   /* Obtain faulting address, the virtual address that was
      accessed to cause the fault.  It may point to code or to
      data.  It is not necessarily the address of the instruction
      that caused the fault (that's f->eip).
      See [IA32-v2a] "MOV--Move to/from Control Registers" and
      [IA32-v3a] 5.15 "Interrupt 14--Page Fault Exception
      (#PF)". */
   asm ("movl %%cr2, %0" : "=r" (fault_addr));

   /* Turn interrupts back on (they were only off so that we could
      be assured of reading CR2 before it changed). */
   intr_enable ();

   /* Count page faults. */
   page_fault_cnt++;

   /* Determine cause. */
   not_present = (f->error_code & PF_P) == 0;
   write = (f->error_code & PF_W) != 0;
   user = (f->error_code & PF_U) != 0;
	
   PUTBUF_FORMAT("Page fault at %p: %s error %s page in %s context.",
      fault_addr,
      not_present ? "not present" : "rights violation",
      write ? "writing" : "reading",
      user ? "user" : "kernel");

   if ((is_kernel_vaddr(fault_addr) && write) || !not_present) {
      PUTBUF("Kernel addr write or read violation: exit(-1)");
      exception_exit(f);
   }
   

   /* Round the fault address down to a page boundary. */
   void *vaddr = pg_round_down(fault_addr);
   
   /* Get the relevant page from this thread's page table. */
   struct supp_page *page = supp_page_lookup(vaddr);
   
   /* Check if there's a supplementary page table entry (i.e fault was caused)
   by accessing something that's not in the frame table */
   if (page != NULL) {

      /* Get (if it exists) the frame that the virtual address maps to */
      struct frame *frame = frame_lookup(vaddr);
      
      switch(page->status) {                                                    
         case SWAPPED:
            // Handle swap by lazy loading
            swap_in(vaddr, page->swap_slot);
            break;

         case FILE:
            // Checks we don't go over the stack limit
            if (vaddr > PHYS_BASE - STACK_LIMIT) {
               exception_exit(f);
            }
            if (frame == NULL) { 
               /* If there page is writable, we get a new frame. If it's read
               only, try to share it */
               frame = page->writable ? frame_put(vaddr, PAL_USER) : 
                 frame_put_file(vaddr, PAL_USER, page->file, page->file_offset);
               
               ASSERT(frame != NULL);
               install_page(vaddr, frame->kaddr, page->writable);
               ASSERT(page->file != NULL);
               
               /* Get the offset of the file before we add data from the file */
               off_t original_pos = file_tell(page->file);
               file_seek(page->file, page->file_offset);

               /* Reads file data into the physical address */
               off_t bytes_read 
                  = file_read(page->file, frame->kaddr, page->read_bytes);

               ASSERT(page->read_bytes == 0 || 
                      bytes_read == (int) page->read_bytes);
               // Returns offset to the original before we moved it to add data
               file_seek(page->file, original_pos);
               // Pad the rest of the page with zeros
               memset (frame->kaddr + page->read_bytes, 0 , page->zero_bytes);
            } 
            else if(page->writable && !pagedir_is_writable(t->pagedir, vaddr)) {
               // Updates that the page is writable in the page directory
               pagedir_set_writable(t->pagedir, vaddr, page->writable);
            }

         break;

         default:
            PUTBUF("Unrecognised page status!!");
            NOT_REACHED();
      }
      return;
   } else if (should_grow_stack(fault_addr, vaddr, (user ? f->esp : t->esp))) {
      // If we need to grow the stack, get a free frame for the new data
      struct frame *frame = frame_put(vaddr, PAL_USER | PAL_ZERO);
      ASSERT(frame != NULL);
      install_page (vaddr, frame->kaddr, true);
      return;
   } 

   PUTBUF("Unhandled page fault: exit(-1)");
   exception_exit(f);
}

// Sets registers to the right values after a page fault
static void exception_exit(struct intr_frame *f) {
   f->eip = (void (*) (void)) f->eax;
   f->eax = EAX_ERR;
   exit_process(-1);
}

// Checks whether we need to grow the stack
static bool should_grow_stack(void *fault_addr, void *vaddr, void *esp) {
   if (PHYS_BASE - vaddr <= STACK_LIMIT) {
      uint32_t diff = esp - fault_addr;
      return diff == 0 || diff == PUSH_OVERFLOW || diff == PUSHA_OVERFLOW;
   }

   return false;
}

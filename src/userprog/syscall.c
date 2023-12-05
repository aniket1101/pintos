#include <syscall-nr.h>
#include <string.h>
#include <stdio.h>
#include <list.h>
#include <debug.h>
#include <user/syscall.h>
#include "userprog/syscall.h"
#include "userprog/pc_link.h"
#include "userprog/fd.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/debug.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "vm/frame.h"
#include "vm/page.h"
#include "vm/mmap.h"

// Calculate offset from esp according to argument number
#define arg_esp_offs(argnum, esp) (esp + ((argnum + 1) * WORD_SIZE))

#define pop_var(esp, type) *((type *) check_pointer(esp)) // Deference ptr

// Pop argument with number argnum off the stack (ptr arguments need additional check)
#define pop_arg(argnum, type) pop_var(arg_esp_offs(argnum, f->esp), type) 
#define pop_ptr_arg(argnum, type) (type) check_pointer((void *) pop_arg(argnum, type))

#define NUM_SYSCALLS 15
#define EXIT_BUF_SIZE 30

/* Ensuring that only one syscall can access the file system at a time. */
static struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

typedef void handle_func(struct intr_frame *f); 

static handle_func handle_halt;
static handle_func handle_exit;
static handle_func handle_exec;
static handle_func handle_wait;
static handle_func handle_create;
static handle_func handle_remove;
static handle_func handle_open;
static handle_func handle_filesize;
static handle_func handle_read;
static handle_func handle_write;
static handle_func handle_seek;
static handle_func handle_tell;
static handle_func handle_close;
static handle_func handle_mmap;
static handle_func handle_munmap;

/* Array of handler functions, indexed by syscall_num. */
handle_func *handlers[NUM_SYSCALLS] = {
  &handle_halt, 
  &handle_exit, 
  &handle_exec, 
  &handle_wait, 
  &handle_create,
  &handle_remove, 
  &handle_open, 
  &handle_filesize, 
  &handle_read, 
  &handle_write, 
  &handle_seek, 
  &handle_tell, 
  &handle_close,
  &handle_mmap,
  &handle_munmap
}; 

/* Syscall functions which have access to the kernel/
   These are exclusively called by handle_ functions */
static inline pid_t kernel_exec (const char *file);
static inline int kernel_wait (pid_t);
static inline bool kernel_create (const char *file, unsigned initial_size);
static inline bool kernel_remove (const char *file);
static inline int kernel_open (const char *file);
static inline int kernel_read (int fd, void *buffer, unsigned length);
static inline int kernel_write (int fd, const void *buffer, unsigned length);
static inline void kernel_close (int fd);
static inline int kernel_mmap (void *addr, struct fd *fd);
static inline void kernel_munmap (mapid_t mapping);

/* Helper functions */
static bool check_mapping(void *start, void *end);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
  
  pc_link_system_init();
  fd_system_init();
  file_info_system_init();
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_num = pop_var(f->esp, int);

  // If syscall_num is invalid, exit
  if (syscall_num < 0 || syscall_num >= NUM_SYSCALLS) { 
    kernel_exit(-1);
  } 

  handlers[syscall_num](f); // Call associated handler for syscall_num
}

/* Checks whether the pointer is valid */
void *check_pointer(void *ptr) {
  if (is_user_vaddr(ptr) 
      && pagedir_get_page(thread_current()->pagedir, ptr)) {
    return ptr;
  } 

  // If ptr is above (or equal to) PHYS_BASE or is unmapped, exit
  kernel_exit(-1);
}

/* Implements the halt system call */
static void handle_halt(struct intr_frame *f UNUSED) {
  shutdown_power_off();
}

/* Wrapper for kernel_exit() */
static void handle_exit(struct intr_frame *f) {
  int status = pop_arg(0, int);

  kernel_exit(status);
}

/* Wrapper for kernel_exec() */
static void handle_exec(struct intr_frame *f) {
  const char *cmd_line = pop_ptr_arg(0, const char *);

  f->eax = kernel_exec(cmd_line);
}

/* Wrapper for kernel_wait() */
static void handle_wait(struct intr_frame *f) {
  pid_t pid = pop_arg(0, pid_t);

  f->eax = kernel_wait(pid);
}

/* Wrapper for kernel_create() */
static void handle_create(struct intr_frame *f) {
  const char *file = pop_ptr_arg(0, const char *);
  unsigned initial_size = pop_arg(1, unsigned);

  f->eax = kernel_create(file, initial_size);
}

/* Wrapper for kernel_remove() function */
static void handle_remove(struct intr_frame *f) {
  const char *file = pop_ptr_arg(0, const char *);

  f->eax = kernel_remove(file);
}

/* Wrapper for kernel_open() */
static void handle_open(struct intr_frame *f) {
  const char *file_name = pop_ptr_arg(0, const char *);

  f->eax = kernel_open(file_name);
}

/* Implements the filesize system call by calculating the 
   size of the file with the specified fd */
static void handle_filesize(struct intr_frame *f) {
  int fd_num = pop_arg(0, int);

  struct fd *fd_ = fd_lookup_safe(fd_num);
  lock_acquire(&filesys_lock);
  f->eax = file_length(fd_->file_info->file);
  lock_release(&filesys_lock);
}

/* Wrapper for kernel_write() */
static void handle_read(struct intr_frame *f) {
  int fd = pop_arg(0, int);
  void *buffer = pop_ptr_arg(1, void *);
  unsigned size = pop_arg(2, unsigned);

  f->eax = kernel_read(fd, buffer, size);
}

/* Wrapper for kernel_write() */
static void handle_write(struct intr_frame *f) {
  int fd = pop_arg(0, int);
  const void *buffer = pop_ptr_arg(1, const void *);
  unsigned size = pop_arg(2, unsigned);

  f->eax = kernel_write(fd, buffer, size);
}

/* Implements the seek system call by changing the file's position */
static void handle_seek(struct intr_frame *f) {
  int fd_num = pop_arg(0, int);
  unsigned position = pop_arg(1, unsigned);

  struct fd *fd_ = fd_lookup_safe(fd_num);

  lock_acquire(&filesys_lock);
  file_seek(fd_->file_info->file, position);
  fd_->pos = file_tell(fd_->file_info->file);
  lock_release(&filesys_lock);
}

/* Implements the tell system call by returning the file's position */
static void handle_tell(struct intr_frame *f) {
  int fd_num = pop_arg(0, int);

  struct fd *fd_ = fd_lookup_safe(fd_num);
  
  lock_acquire(&filesys_lock);
  file_seek(fd_->file_info->file, fd_->pos);
  f->eax = file_tell(fd_->file_info->file);
  lock_release(&filesys_lock);
}

/* Wrapper for kernel_close() */
static void handle_close(struct intr_frame *f) {
  int fd = pop_arg(0, int);
  kernel_close(fd);
}

/* Wrapper for kernel_mmap() */
static void handle_mmap(struct intr_frame *f) {
  int fd_num = pop_arg(0, int);
  void *addr = pop_arg(1, void *);
  struct fd *fd_ = fd_lookup_safe(fd_num);
  f->eax = kernel_mmap(addr, fd_);
}

/* Wrapper for kernel_munmap() */
static void handle_munmap(struct intr_frame *f) {
  int mapping = pop_arg(0, mapid_t);
  kernel_munmap(mapping);
}

/* Below are implementations of syscall functions with kernel access */ 

/* Implements the exit system call by:
- Setting the thread's exit code to the status
- Outputting a message with the exit code to the terminal */
void kernel_exit(int status) {
  char buf[EXIT_BUF_SIZE]; int cnt;
  thread_current()->exit_code = status;
  cnt = snprintf(buf, EXIT_BUF_SIZE, "%s: exit(%d)\n", 
    thread_current()->name, status);
  putbuf(buf, cnt);

  thread_exit();
}

/* Implements the wait system call by:
  - Waiting for process with pid to exit
  - Returning the returned pid */  
static inline pid_t kernel_wait(pid_t pid) {
  return process_wait(pid);
}

/* Implements the exec system call by:
  - Executing the process called in cmd_line
  - Returning the returned pid */  
static inline pid_t kernel_exec(const char* cmd_line) {
  pid_t pid = ((pid_t) process_execute(cmd_line));

  // If process_execute returns an incorrect id, return it
  if (pid == TID_ERROR) {
    return TID_ERROR;
  }

  // Initialises pc_link struct which has info about the parent and child
  pc_link_init(pid);

  return pid;
}

/* Implements the create system call by:
  - Checking that the name is valid
  - Makes a file_info struct for the new file
  - Adding the struct to the list of files */
static inline bool kernel_create(const char *file, unsigned initial_size) {
  if (strlen(file) <= MAX_FILENAME_SIZE) {
    lock_acquire(&filesys_lock);

    if (filesys_create(file, (off_t) initial_size)) {
      lock_release(&filesys_lock);
      return file_info_init((char *) file) != NULL;
    }

    lock_release(&filesys_lock);
  }

  return false;
}

/* Implements the remove system call by:
  - Getting the file_info struct of the file with the specified name
  - Sets to_remove to true
  - Deletes the file if the file is closed */
static inline bool kernel_remove(const char *file_name) {
  struct file_info *info = file_info_lookup((char *) file_name);
  if (info == NULL) {
    return false;
  }

  info->should_remove = true;
  /* Check if any thread has the file open, if so, should_remove is set true
     and every time the file is closed, the size needs to be rechecked to 
     see if the file can be removed. If there are no openers, the file_info
     will get removed from all_files and free'd, the file is then removed 
     in the file system. */
  if (info->num_fds == 0) {
    free(file_info_remove(info));

    lock_acquire(&filesys_lock);
    int res = filesys_remove(file_name);
    lock_release(&filesys_lock);
    return res;
  }

  return true;
}

/* Implements the open system call by:
  - Checking that the file_name is valid
  - Finds/creates the file
  - Adds to the list of open files */
static inline int kernel_open(const char* file_name) {
  // Check if file name is ""
  if (!strcmp(file_name, "")) {
    return -1;
  }

  struct file_info *info = file_info_lookup((char *) file_name);

  // If file has been flagged to remove it cannot be opened
  if (info != NULL && info->should_remove) {
    return -1;
  }
  
  // If file has not been created, create the file_info
  if (info == NULL) {
    info = file_info_init((char *) file_name);
    if (info == NULL) {
      return -1;
    }
  }

  // If the number of fds is 0, then the file needs to be opened in filesystem
  if (info->num_fds == 0) {
    lock_acquire(&filesys_lock);
    
    struct file *file = filesys_open(file_name);

    // File cannot be opened
    if (file == NULL) {
      lock_release(&filesys_lock);
      return -1;
    }
    
    lock_release(&filesys_lock);
    info->file = file;
  } 

  // Set fd and insert it into file_info and thread list
  struct fd *added_fd = fd_add(info);
  return added_fd == NULL ? -1 : added_fd->fd_num;
}

static inline int kernel_read(int fd, void *buffer, unsigned size) {
  if (fd == STDIN_FILENO) {
    return input_getc();
  }

  struct fd *fd_ = fd_lookup_safe(fd);

  lock_acquire(&filesys_lock);

  // Updates postion of file to the threads saved position
  file_seek(fd_->file_info->file, fd_->pos);
  int offset = file_read(fd_->file_info->file, buffer, size);
  fd_->pos += offset; // Updates saved position

  lock_release(&filesys_lock);
  return offset;
}

static inline int kernel_write(int fd, const void *buffer, unsigned size) {
  if (fd == STDOUT_FILENO) {
    putbuf((const char *) buffer, size);
    return size;
  }

  struct fd *fd_ = fd_lookup_safe(fd);

  lock_acquire(&filesys_lock);

  // Updates postion of file to the threads saved position
  file_seek(fd_->file_info->file, fd_->pos);
  int offset = file_write(fd_->file_info->file, buffer, size);
  fd_->pos += offset; // Updates saved position

  lock_release(&filesys_lock);
  return offset;
}

/* Implements the close system call by:
  - Removing the fd from the file's list of possible fds
  - Sets is_open to false
  - Removes the file if it was removed by another thread */
static inline void kernel_close(int fd_num) {
  struct fd *fd_ = fd_lookup(fd_num);
  if (fd_ == NULL) {
    kernel_exit(-1);
  }
  // Remove fd from thread's fd list 
  fd_remove(fd_);
  
  struct file_info *info = fd_->file_info;
  info->num_fds--;
  
  free(fd_);
  // If fds is 0 then the file can be closed in the file system
  if (info->num_fds == 0) {
    lock_acquire(&filesys_lock);
    file_close(info->file);

    /* If the file should be removed, as there are no threads that currently
       opening the file, we can safely remove it. */
    if (info->should_remove) {
      filesys_remove(info->name);
      file_info_remove(info);
      free(info);
    }

    lock_release(&filesys_lock);
  }
}

static inline int kernel_mmap(void *addr, struct fd *fd) {
  mapid_t map_id = -1;

  if (pg_ofs(addr) != 0) {
    goto ret;
  }

  struct file *file = fd->file_info->file;
  if (file == NULL || addr == NULL || fd->fd_num < 2) {
    goto ret;
  }

  lock_acquire(&filesys_lock);
  uint32_t read_bytes = file_length(file);
  lock_release(&filesys_lock);

  if (read_bytes == 0 || check_mapping(addr, addr + read_bytes)) {
    goto ret;
  }

  struct thread *t = thread_current();
  map_id = t->next_mapid++;

  lock_acquire(&filesys_lock);
  file = file_reopen(file);
  lock_release(&filesys_lock);

  uint32_t curr_page;
  for (curr_page = 0; curr_page <= read_bytes; curr_page += PGSIZE) {
    
    insert_mmap_fpt(&t->mmap_file_page_table, map_id,
      addr + curr_page, file, curr_page, PGSIZE, true);
    insert_supp_page_table(&t->supp_page_table, addr + curr_page,
                                              MMAPPED);
  }
  add_mmap(&t->mmap_link_addr_table, map_id, addr, curr_page + addr);
  
  ret:
    return map_id;
}

static inline void kernel_munmap(mapid_t mapping) {
  struct thread *t = thread_current();
  struct mmap_link_addr *map_addr = get_mmap(&t->mmap_link_addr_table, mapping);
  struct file *file = NULL;
  for (void *curr = map_addr->start_page; curr < map_addr->end_page;
      curr += PGSIZE) {
        struct mmap_file_page *mmap_fp = get_mmap_fpt(&t->mmap_file_page_table,
                                                  curr);
        file = mmap_fp->file;
        void *kaddr = pagedir_get_page(t->pagedir, curr);
        if (kaddr != NULL) {
          wipe_frame_memory(kaddr);
          pagedir_clear_page(t->pagedir, curr);
        }

        delete_mmap_fp(&t->mmap_file_page_table, mmap_fp);
        remove_supp_page(&t->supp_page_table, curr);
  }

  delete_mmap(&t->mmap_link_addr_table, mapping);
      
  lock_acquire(&filesys_lock);
  file_close(file);
  lock_release(&filesys_lock);
}

static bool check_mapping(void *start, void *end) {
  ASSERT(start < end);

  struct thread *t = thread_current();
  for(; start <= end; start += PGSIZE) {
    if (get_supp_page_table(&t->supp_page_table, start) != NULL) {
      return true;
    }
  }
  return false;
}

/* Acquires filesys lock. */
void lock_filesys_access(void) {
  lock_acquire(&filesys_lock);
}

/* Releases filesys lock. */
void unlock_filesys_access(void) {
  lock_release(&filesys_lock);
}
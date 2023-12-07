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

// Calculate offset from esp according to argument number
#define arg_offs(arg_num, esp) (esp + ((arg_num + 1) * WORD_SIZE))

// Pop argument with number argnum off the stack (ptr arguments need additional check)
#define pop(esp, type) *((type *) validate_buffer(esp, sizeof(type)))
#define pop_arg(argnum, type) pop(arg_offs(argnum, f->esp), type) 

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
static inline int kernel_mmap (void *addr, struct file_info *info);
static inline void kernel_munmap (int mapping);

static uint8_t safe_get(void *ptr);
static void *validate_buffer(void *ptr, unsigned size);
static char *validate_string(char *ptr);

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
  int syscall_num = pop(f->esp, int);

  // If syscall_num is invalid, exit
  if (syscall_num < 0 || syscall_num >= NUM_SYSCALLS) { 
    kernel_exit(-1);
  }

  handlers[syscall_num](f); // Call associated handler for syscall_num
}

/* Reads a byte at user virtual address UADDR.
UADDR must be below PHYS_BASE.
Returns the byte value if successful, -1 if a segfault
occurred. */
static int get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
UDST must be below PHYS_BASE.
Returns true if successful, false if a segfault occurred. */
static bool put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
    : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

static uint8_t safe_get(void *ptr) {
  int res;
  if (is_user_vaddr(ptr) && (res = get_user((uint8_t *) ptr)) != -1) {
    return (uint8_t) res;
  }

  kernel_exit(-1);
}

static void safe_put(void *ptr, uint8_t byte) {
  if (!is_user_vaddr(ptr) || !put_user(ptr, byte)) {
    kernel_exit(-1);
  }
}

static void *validate_buffer(void *ptr, unsigned size) {
  safe_get(ptr);

  while (size >= PGSIZE) {
    safe_get(ptr = pg_round_up(ptr));
    size -= PGSIZE - pg_ofs(ptr);
    ptr++;
  }

  return ptr;
}

static char *validate_string(char *ptr) {
  while (safe_get(ptr++) != '\0') { 
    PUTBUF("safe get");
  }
  return ptr;
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

/* Implements the exit system call by:
- Setting the thread's exit code to the status
- Outputting a message with the exit code to the terminal */
void kernel_exit(int status) {
  char buf[EXIT_BUF_SIZE]; 
  thread_current()->exit_code = status;
  int cnt = snprintf(buf, EXIT_BUF_SIZE, "%s: exit(%d)\n", 
    thread_current()->name, status);
  putbuf(buf, cnt);

  thread_exit();
}


/* Implements the exec system call by:
  - Executing the process called in cmd_line
  - Returning the returned pid */  
static void handle_exec(struct intr_frame *f) {
  char *cmd_line = pop_arg(0, char *); 
  validate_string(cmd_line);

  pid_t pid = ((pid_t) process_execute(cmd_line));

  // If process_execute returns an incorrect id, return it
  if (pid != TID_ERROR) {
    // Initialises pc_link struct which has info about the parent and child
    pc_link_init(pid);
  }

  f->eax = pid;  
}

/* Implements the wait system call by:
  - Waiting for process with pid to exit
  - Returning the returned pid */  
static void handle_wait(struct intr_frame *f) {
  pid_t pid = pop_arg(0, pid_t);
  f->eax = process_wait(pid);
}

/* Implements the create system call by:
  - Checking that the name is valid
  - Makes a file_info struct for the new file
  - Adding the struct to the list of files */
static void handle_create(struct intr_frame *f) {
  char *file_name = pop_arg(0, char *);
  validate_string(file_name);
  unsigned initial_size = pop_arg(1, unsigned);
  
  bool success = false;
  if (strlen(file_name) <= MAX_FILENAME_SIZE) {
    lock_acquire(&filesys_lock);
    if (filesys_create(file_name, (off_t) initial_size)) {
      success = file_info_init(file_name) != NULL;
    }
    lock_release(&filesys_lock);
  }

  f->eax = (int) success;  
}

/* Implements the remove system call by:
  - Getting the file_info struct of the file with the specified name
  - Sets to_remove to true
  - Deletes the file if the file is closed */
static void handle_remove(struct intr_frame *f) {
  char *file_name = pop_arg(0, char *);
  validate_string(file_name);
  
  bool success = false;
  struct file_info *info = file_info_lookup((char *) file_name);
  if (info == NULL) {
    goto ret;
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
    success = filesys_remove(file_name);
    lock_release(&filesys_lock);
  }

  ret:
    f->eax = (int) success;
}

/* Implements the open system call by:
  - Checking that the file_name is valid
  - Finds/creates the file
  - Adds to the list of open files */
static void handle_open(struct intr_frame *f) {
  char *file_name = pop_arg(0, char *);
  validate_string(file_name);
  
  int fd_num = -1;
  
  struct file_info *info = file_info_lookup(file_name);
  // If file has been flagged to remove it cannot be opened
  if (info != NULL && info->should_remove) {
    goto ret;
  }

  // If file has not been created, create the file_info
  if (info == NULL) {
    info = file_info_init(file_name);
    if (info == NULL) {
      goto ret;
    }
  }

  // If the number of fds is 0, then the file needs to be opened in filesystem
  if (info->num_fds == 0) {
    lock_acquire(&filesys_lock);
    
    struct file *file = filesys_open(file_name);

    // File cannot be opened
    if (file == NULL) {
      lock_release(&filesys_lock);
      goto ret;
    }
    
    lock_release(&filesys_lock);
    info->file = file;
  }

  // Set fd and insert it into file_info and thread list
  struct fd *added_fd = fd_add(info);
  if (added_fd == NULL) {
    goto ret;
  } 

  fd_num = added_fd->fd_num;

  ret:
    f->eax = fd_num;
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
  void *buffer = pop_arg(1, void *);
  unsigned size = pop_arg(2, unsigned);
  validate_buffer(buffer, size);
  
  if (size == 0) {
    f->eax = 0;
    return;
  }
  
  if (fd == STDIN_FILENO) {
    while (buffer < buffer + size) {
      safe_put(buffer++, input_getc());
    }

    f->eax = size; 
    return;
  }

  struct fd *fd_ = fd_lookup_safe(fd);

  lock_acquire(&filesys_lock);

  // Updates postion of file to the threads saved position
  file_seek(fd_->file_info->file, fd_->pos);
  int bytes_read = file_read(fd_->file_info->file, buffer, size);
  fd_->pos += bytes_read; // Updates saved position

  lock_release(&filesys_lock);
  f->eax = bytes_read;
}

/* Wrapper for kernel_write() */
static void handle_write(struct intr_frame *f) {
  int fd = pop_arg(0, int);
  void *buffer = pop_arg(1, void *);
  unsigned size = pop_arg(2, unsigned);
  validate_buffer(buffer, size);

  if (size == 0) {
    f->eax = 0;
    return;
  }

  if (fd == STDOUT_FILENO) {
    putbuf((const char *) buffer, size);
    f->eax = size;
    return;
  } 
  struct fd *fd_ = fd_lookup_safe(fd);

  lock_acquire(&filesys_lock);

  // Updates postion of file to the threads saved position
  file_seek(fd_->file_info->file, fd_->pos);
  int bytes_read = file_write(fd_->file_info->file, buffer, size);
  fd_->pos += bytes_read; // Updates saved position

  lock_release(&filesys_lock);
  f->eax = bytes_read;
}

/* Implements the seek system call by changing the file's position */
static void handle_seek(struct intr_frame *f) {
  int fd = pop_arg(0, int);
  unsigned position = pop_arg(1, unsigned);

  struct fd *fd_ = fd_lookup_safe(fd);

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

/* Implements the close system call by:
  - Removing the fd from the file's list of possible fds
  - Sets is_open to false
  - Removes the file if it was removed by another thread */
static void handle_close(struct intr_frame *f) {
  int fd_num = pop_arg(0, int);

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

/* Wrapper for kernel_mmap() */
static void handle_mmap(struct intr_frame *f) {
  int fd_num = pop_arg(0, int);
  // void *addr = safe_get_buf(safe_get_arg(0, f), );
  struct fd *fd_ UNUSED = fd_lookup_safe(fd_num);

  kernel_exit(-1);
}

static void handle_munmap(struct intr_frame *f) {
  int mapping UNUSED = pop_arg(0, int);

  kernel_exit(-1);
}

/* Below are implementations of syscall functions with kernel access */ 




// static inline pid_t kernel_wait(pid_t pid) {
//   return process_wait(pid);
// }


// static inline pid_t kernel_exec(const char* cmd_line) {
//   pid_t pid = ((pid_t) process_execute(cmd_line));

//   // If process_execute returns an incorrect id, return it
//   if (pid == TID_ERROR) {
//     return TID_ERROR;
//   }

//   // Initialises pc_link struct which has info about the parent and child
//   pc_link_init(pid);

//   return pid;
// }


// static inline bool kernel_create(const char *file, unsigned initial_size) {
//   if (strlen(file) <= MAX_FILENAME_SIZE) {
//     lock_acquire(&filesys_lock);

//     if (filesys_create(file, (off_t) initial_size)) {
//       lock_release(&filesys_lock);
//       return file_info_init((char *) file) != NULL;
//     }

//     lock_release(&filesys_lock);
//   }

//   return false;
// }


// static inline bool kernel_remove(const char *file_name) {
//   struct file_info *info = file_info_lookup((char *) file_name);
//   if (info == NULL) {
//     return false;
//   }

//   info->should_remove = true;
//   /* Check if any thread has the file open, if so, should_remove is set true
//      and every time the file is closed, the size needs to be rechecked to 
//      see if the file can be removed. If there are no openers, the file_info
//      will get removed from all_files and free'd, the file is then removed 
//      in the file system. */
//   if (info->num_fds == 0) {
//     free(file_info_remove(info));

//     lock_acquire(&filesys_lock);
//     int res = filesys_remove(file_name);
//     lock_release(&filesys_lock);
//     return res;
//   }

//   return true;
// }


// static inline int kernel_open(const char* file_name) {
//   // Check if file name is ""
//   if (!strcmp(file_name, "")) {
//     return -1;
//   }

//   struct file_info *info = file_info_lookup((char *) file_name);

//   // If file has been flagged to remove it cannot be opened
//   if (info != NULL && info->should_remove) {
//     return -1;
//   }
  
//   // If file has not been created, create the file_info
//   if (info == NULL) {
//     info = file_info_init((char *) file_name);
//     if (info == NULL) {
//       return -1;
//     }
//   }

//   // If the number of fds is 0, then the file needs to be opened in filesystem
//   if (info->num_fds == 0) {
//     lock_acquire(&filesys_lock);
    
//     struct file *file = filesys_open(file_name);

//     // File cannot be opened
//     if (file == NULL) {
//       lock_release(&filesys_lock);
//       return -1;
//     }
    
//     lock_release(&filesys_lock);
//     info->file = file;
//   } 

//   // Set fd and insert it into file_info and thread list
//   struct fd *added_fd = fd_add(info);
//   return added_fd == NULL ? -1 : added_fd->fd_num;
// }

// static inline int kernel_read(int fd, void *buffer, unsigned size) {
//   if (fd == STDIN_FILENO) {
//     return input_getc();
//   }

//   struct fd *fd_ = fd_lookup_safe(fd);

//   lock_acquire(&filesys_lock);

//   // Updates postion of file to the threads saved position
//   file_seek(fd_->file_info->file, fd_->pos);
//   int offset = file_read(fd_->file_info->file, buffer, size);
//   fd_->pos += offset; // Updates saved position

//   lock_release(&filesys_lock);
//   return offset;
// }

// static inline int kernel_write(int fd, const void *buffer, unsigned size) {
//   if (fd == STDOUT_FILENO) {
//     putbuf((const char *) buffer, size);
//     return size;
//   }

//   struct fd *fd_ = fd_lookup_safe(fd);

//   lock_acquire(&filesys_lock);

//   // Updates postion of file to the threads saved position
//   file_seek(fd_->file_info->file, fd_->pos);
//   int offset = file_write(fd_->file_info->file, buffer, size);
//   fd_->pos += offset; // Updates saved position

//   lock_release(&filesys_lock);
//   return offset;
// }


// static inline void kernel_close(int fd_num) {
//   struct fd *fd_ = fd_lookup(fd_num);
//   if (fd_ == NULL) {
//     kernel_exit(-1);
//   }
//   // Remove fd from thread's fd list 
//   fd_remove(fd_);
  
//   struct file_info *info = fd_->file_info;
//   info->num_fds--;
  
//   free(fd_);
//   // If fds is 0 then the file can be closed in the file system
//   if (info->num_fds == 0) {
//     lock_acquire(&filesys_lock);
//     file_close(info->file);

//     /* If the file should be removed, as there are no threads that currently
//        opening the file, we can safely remove it. */
//     if (info->should_remove) {
//       filesys_remove(info->name);
//       file_info_remove(info);
//       free(info);
//     }

//     lock_release(&filesys_lock);
//   }
// }

// static inline int kernel_mmap(void *addr, struct file_info *info) {
//   PUTBUF("mmap not implemented: exit(-1)");
//   kernel_exit(-1);
// }

// static inline void kernel_munmap(int mapping) {
//   PUTBUF("munmap not implemented: exit(-1)");
//   kernel_exit(-1);
// }

/* Acquires filesys lock. */
void lock_filesys_access(void) {
  lock_acquire(&filesys_lock);
}

/* Releases filesys lock. */
void unlock_filesys_access(void) {
  lock_release(&filesys_lock);
}
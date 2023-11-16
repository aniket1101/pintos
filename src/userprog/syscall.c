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
#include "threads/vaddr.h"
#include "devices/timer.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define EXIT_BUF_SIZE 30

#define pop_stack(esp, type) *((type *) check_pointer(esp))
#define pop_arg(argnum, type) pop_stack(f->esp + ((argnum + 1) * WORD_SIZE), type)

#define NUM_SYSCALLS 13

static void syscall_handler (struct intr_frame *);

static void handle_halt(struct intr_frame *f);
static void handle_exit(struct intr_frame *f);
static void handle_exec(struct intr_frame *f);
static void handle_wait(struct intr_frame *f);
static void handle_create(struct intr_frame *f);
static void handle_remove(struct intr_frame *f);
static void handle_open(struct intr_frame *f);
static void handle_filesize(struct intr_frame *f);
static void handle_read(struct intr_frame *f);
static void handle_write(struct intr_frame *f);
static void handle_seek(struct intr_frame *f);
static void handle_tell(struct intr_frame *f);
static void handle_close(struct intr_frame *f);

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

typedef int (file_modify_func)(struct file *, const void *, off_t);
static off_t file_modify(int fd, file_modify_func modify, const void *buffer, unsigned size);

typedef void (*handler_func)(struct intr_frame *f); 
handler_func handlers[NUM_SYSCALLS] = {
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
  &handle_close
}; 

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  fd_system_init();
}

static void
syscall_handler (struct intr_frame *f) 
{
  PUTBUF("Handle syscall:");
  HEX_DUMP_ESP(f->esp);  

  int syscall_num = pop_stack(f->esp, int);
  PUTBUF_FORMAT("\tpopped syscall num = %d off at %p. moved stack up by %d", 
    syscall_num, f->esp, sizeof(int *)); 

  if (syscall_num < 0 || syscall_num >= NUM_SYSCALLS) {
    kernel_exit(-1);
  } 

  handlers[syscall_num](f);

  HEX_DUMP_ESP(f->esp);
  PUTBUF("End syscall");
}

/* Checks whether the pointer is valid */
void *check_pointer(void *ptr) {
  if (is_user_vaddr(ptr) 
      && pagedir_get_page(thread_current()->pagedir, ptr)) {
    return ptr;
  } 

  kernel_exit(-1);
}

/* Implements the halt system call */
static void handle_halt(struct intr_frame *f UNUSED) {
  PUTBUF("Call halt syscall");
  shutdown_power_off();
}

/* Wrapper for kernel_exit() */
static void handle_exit(struct intr_frame *f) {
  PUTBUF("Call exit syscall");
  int status = pop_arg(0, int);

  kernel_exit(status);
}

/* Wrapper for kernel_exec() */
static void handle_exec(struct intr_frame *f UNUSED) {
  PUTBUF("Call exec syscall");
  const char *cmd_line = pop_arg(0, const char *);
  check_pointer((void *)cmd_line);

  f->eax = kernel_exec(cmd_line);
}

/* Wrapper for kernel_wait() */
static void handle_wait(struct intr_frame *f UNUSED) {
  PUTBUF("Call wait syscall");
  pid_t pid = pop_arg(0, pid_t);

  f->eax = kernel_wait(pid);
}

/* Wrapper for kernel_create() */
static void handle_create(struct intr_frame *f UNUSED) {
  PUTBUF("Call create syscall");
  const char *file = pop_arg(0, const char *);
  unsigned initial_size = pop_arg(1, unsigned);
  check_pointer((void *) file);

  f->eax = kernel_create(file, initial_size);
}

/* Wrapper for kernel_remove() function */
static void handle_remove(struct intr_frame *f UNUSED) {
  PUTBUF("Call remove syscall");
  const char *file = pop_arg(0, const char *);
  check_pointer((void *) file);

  f->eax = kernel_remove(file);
}

/* Wrapper for kernel_open() */
static void handle_open(struct intr_frame *f UNUSED) {
  PUTBUF("Call open syscall");
  const char *file_name = pop_arg(0, const char *);
  check_pointer((void *) file_name);

  f->eax = kernel_open(file_name);
}


/* Implements the filesize system call by calculating the 
   size of the file with the specified fd */
static void handle_filesize(struct intr_frame *f UNUSED) {
  PUTBUF("Call filesize syscall");
  int fd_num = pop_arg(0, int);
  struct fd *fd_ = thread_fd_lookup_safe(fd_num, thread_current());
  f->eax = file_length(fd_->file_info->file);
}

/* Wrapper for kernel_write() */
static void handle_read(struct intr_frame *f UNUSED) {
  PUTBUF("Call read syscall");
  int fd = pop_arg(0, int);
  void *buffer = pop_arg(1, void *);
  unsigned size = pop_arg(2, unsigned);
  check_pointer((void *) buffer);
  f->eax = kernel_read(fd, buffer, size);
}

/* Wrapper for kernel_write() */
static void handle_write(struct intr_frame *f) {
  PUTBUF("Call write syscall");
  int fd = pop_arg(0, int);
  const void *buffer = pop_arg(1, const void *);
  unsigned size = pop_arg(2, unsigned);
  check_pointer((void *) buffer);

  f->eax = kernel_write(fd, buffer, size);
}

/* Implements the seek system call by changing the file's position */
static void handle_seek(struct intr_frame *f UNUSED) {
  PUTBUF("Call seek syscall");
  int fd_num = pop_arg(0, int);
  unsigned position = pop_arg(1, unsigned);

  struct fd *fd_ = thread_fd_lookup_safe(fd_num, thread_current());

  file_seek(fd_->file_info->file, position);
  fd_->pos = file_tell(fd_->file_info->file);
}

/* Implements the tell system call by returning the file's position */
static void handle_tell(struct intr_frame *f UNUSED) {
  PUTBUF("Call tell syscall");
  int fd_num = pop_arg(0, int);

  struct fd *fd_ = thread_fd_lookup_safe(fd_num, thread_current());
  
  file_seek(fd_->file_info->file, fd_->pos);
  f->eax = file_tell(fd_->file_info->file);
}

/* Wrapper for kernel_close() */
static void handle_close(struct intr_frame *f UNUSED) {
  PUTBUF("Call close syscall");
  int fd = pop_arg(0, int);
  kernel_close(fd);
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
  PUTBUF_FORMAT("\tExecute command: %s", cmd_line);
  pid_t pid = ((pid_t) process_execute(cmd_line));
  PUTBUF_FORMAT("\tExec pid is %d", pid);

  struct pc_link *link = pc_link_find(pid);
  if (pid == TID_ERROR || link != NULL) {
    PUTBUF("\tTID error: exit(-1)");
    return TID_ERROR;
  }

  link = pc_link_init(pid);

  if (!link->c_is_alive) { //TODO: wait until start_process finished
    return link->c_exit_code;
  }

  return pid;
}

/* Implements the create system call by:
  - Checking that the name is valid
  - Makes a file_info struct for the new file
  - Adding the struct to the list of files */
static inline bool kernel_create(const char *file, unsigned initial_size) {
  if (filesys_create(file, (off_t) initial_size) && 
      strlen(file) <= MAX_FILENAME_SIZE) {
    return file_info_init((char *) file) != NULL;
  }
  
  return false;
}

/* Implements the remove system call by:
  - Getting the file_info struct of the file with the specified name
  - Sets to_remove to true
  - Deletes the file if the file is closed */
static inline bool kernel_remove(const char *file_name) {
  struct file_info *info = file_info_lookup((char *) file_name);
  
  if (info != NULL) {
    info->should_remove = true;

    if (info->num_fds == 0) {
      return filesys_remove(file_name);
    }
  }

  return false;
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
  
  // If file has not been created
  if (info == NULL) {
    info = file_info_init((char *) file_name);
    if (info == NULL) {
      return -1;
    }
  }

  if (info->num_fds == 0) {
    struct file *file = filesys_open(file_name);
    if (file == NULL) {
      return -1;
    }

    info->file = file;
  } 

  struct fd *added_fd = thread_add_fd(info);
  return added_fd == NULL ? -1 : added_fd->fd_num;
}

static inline int kernel_read(int fd, void *buffer, unsigned size) {
  if (fd == STDIN_FILENO) {
    return input_getc();
  }

  return file_modify(fd, &file_read, buffer, size);
}

static inline int kernel_write(int fd, const void *buffer, unsigned size) {
  if (fd == STDOUT_FILENO) {
    putbuf((const char *) buffer, size);
    return size;
  }

  return file_modify(fd, &file_write, buffer, size);
}

static int file_modify(int fd_num, file_modify_func modify, const void *buffer, unsigned size) {
  struct fd *fd_ = thread_fd_lookup_safe(fd_num, thread_current());
  file_seek(fd_->file_info->file, fd_->pos);
  int offset = modify(fd_->file_info->file, buffer, size);
  fd_->pos += offset;
  return offset;
}

/* Implements the close system call by:
  - Removing the fd from the file's list of possible fds
  - Sets is_open to false
  - Removes the file if it was removed by another thread */
static inline void kernel_close(int fd_num) {
  struct fd *fd_ = thread_remove_fd(fd_num, thread_current());
  if (fd_ == NULL) {
    kernel_exit(-1);
  }

  struct file_info *info = fd_->file_info; //TODO free fd
  info->num_fds--;

  if (info->num_fds == 0) {
    file_close(info->file);
    if (info->should_remove) {
      filesys_remove(info->name);
    }
  }
}

#include <syscall-nr.h>
#include <string.h>
#include <stdio.h>
#include <list.h>
#include <user/syscall.h>
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/debug.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "devices/timer.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "debug.h"

#define MAX_SIZE 100
#define MAX_FILENAME_SIZE 14

typedef void * (*elemFunc) (struct list_elem *, struct list_elem *);
typedef void * (*infoFunc) (struct list_elem *, void *);

#define arg_esp_offs(argnum, esp) (esp + ((argnum + 1) * WORD_SIZE))

#define pop_var(esp, type) *((type *) check_pointer(esp))
#define pop_arg(argnum, type) pop_var(arg_esp_offs(argnum, f->esp), type)
#define pop_ptr_arg(argnum, type) (type) check_pointer((void *) pop_arg(argnum, type))

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
static inline void kernel_exit (int status) NO_RETURN;
static inline pid_t kernel_exec (const char *file);
static inline int kernel_wait (pid_t);
static inline bool kernel_create (const char *file, unsigned initial_size);
static inline bool kernel_remove (const char *file);
static inline int kernel_open (const char *file);
static inline int kernel_read (int fd, void *buffer, unsigned length);
static inline int kernel_write (int fd, const void *buffer, unsigned length);
static inline void kernel_close (int fd);

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

struct file_info {
	struct list *fds;
	struct file *file;
  char *name;
	bool to_remove;
  bool is_open;
	struct list_elem elem;
};

struct function_info {
  int fd;
  elemFunc funct;
};

void *rem_fd(struct list_elem *, struct list_elem *);
void remove_fd(int);

void *fd_apply(int, elemFunc);
bool is_fd_valid(int);

void *traverse_fds(struct list_elem *, void *);
void *traverse_all_files(void *, void *);

struct thread_fd_elem *find_fd_elem(int);

void init_fd_elem(struct fd_elem *);

struct file *fd_to_file(int);

void *get_info_file(struct list_elem *, struct list_elem * UNUSED);

void init_file_info(struct file_info *, int, struct file *);
void make_file_info(struct file_info *, char name[MAX_FILENAME_SIZE]);
struct file_info *get_file_info(struct list_elem *, void *);
struct file_info *find_file_info(const char *);
struct file_info *fd_to_file_info (int);

static struct list all_files;

static int32_t next_fd;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // lock_init(fd_lock);
  next_fd = 2;
  list_init(&all_files);
}

static void
syscall_handler (struct intr_frame *f) 
{
  PUTBUF("Start syscall:");
  HEX_DUMP_ESP(f->esp);  

  int syscall_num = pop_var(f->esp, int);
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
  thread_current()->exit_code = pop_arg(0, int);

  kernel_exit(thread_current()->exit_code);
}

/* Wrapper for kernel_exec() */
static void handle_exec(struct intr_frame *f UNUSED) {
  PUTBUF("Call exec syscall");
  const char *cmd_line = pop_ptr_arg(0, const char *);

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
  const char *file = pop_ptr_arg(0, const char *);
  unsigned initial_size = pop_arg(1, unsigned);

  f->eax = kernel_create(file, initial_size);
}

/* Wrapper for kernel_remove() function */
static void handle_remove(struct intr_frame *f UNUSED) {
  PUTBUF("Call remove syscall");
  const char *file = pop_ptr_arg(0, const char *);

  f->eax = kernel_remove(file);
}

/* Wrapper for kernel_open() */
static void handle_open(struct intr_frame *f UNUSED) {
  PUTBUF("Call open syscall");
  const char *file_name = pop_ptr_arg(0, const char *);

  f->eax = kernel_open(file_name);
}


/* Implements the filesize system call by calculating the 
   size of the file with the specified fd */
static void handle_filesize(struct intr_frame *f UNUSED) {
  PUTBUF("Call filesize syscall");
  int fd = pop_arg(0, int);
  if (!is_fd_valid(fd)) {
    kernel_exit(-1);
  }

  f->eax = file_length(fd_to_file(fd));
}

/* Wrapper for kernel_write() */
static void handle_read(struct intr_frame *f UNUSED) {
  PUTBUF("Call read syscall");
  int fd = pop_arg(0, int);
  void *buffer = pop_ptr_arg(1, void *);
  unsigned size = pop_arg(2, unsigned);

  f->eax = kernel_read(fd, buffer, size);
}

/* Wrapper for kernel_write() */
static void handle_write(struct intr_frame *f) {
  PUTBUF("Call write syscall");
  int fd = pop_arg(0, int);
  const void *buffer = pop_ptr_arg(1, const void *);
  unsigned size = pop_arg(2, unsigned);

  f->eax = kernel_write(fd, buffer, size);
}

/* Implements the seek system call by changing the file's position */
static void handle_seek(struct intr_frame *f UNUSED) {
  PUTBUF("Call seek syscall");
  int fd = pop_arg(0, int);
  unsigned position = pop_arg(1, unsigned);

  if (!is_fd_valid(fd)) {
    kernel_exit(-1);
  }

  file_seek(fd_to_file(fd), position);
}

/* Implements the tell system call by returning the file's position */
static void handle_tell(struct intr_frame *f UNUSED) {
  PUTBUF("Call tell syscall");
  int fd = pop_arg(0, int);
  if (!is_fd_valid(fd)) {
    kernel_exit(-1);
  }

  f->eax = file_tell(fd_to_file(fd));
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
static inline void kernel_exit(int status) {
  char buf[MAX_SIZE]; int cnt;
  cnt = snprintf(buf, MAX_SIZE, "%s: exit(%d)\n", 
    thread_current()->name, status);
  putbuf(buf, cnt);

  process_exit();
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
  int result UNUSED = process_wait(pid);
  
  // need to check result
  if (pid == PID_ERROR) {
    return pid;
  }
  
  return pid - 1;
}

/* Implements the create system call by:
  - Checking that the name is valid
  - Makes a file_info struct for the new file
  - Adding the struct to the list of files */
static inline bool kernel_create(const char *file, unsigned initial_size) {
  if (filesys_create(file, (off_t) initial_size) && 
      strlen(file) <= MAX_FILENAME_SIZE) {
    struct file_info *info = (struct file_info *) malloc(sizeof(struct file_info));
    make_file_info(info, (char *) file);
    list_push_back(&all_files, &(info->elem));
    return true;
  }
  
  return false;
}

/* Implements the remove system call by:
  - Getting the file_info struct of the file with the specified name
  - Sets to_remove to true
  - Deletes the file if the file is closed */
static inline bool kernel_remove(const char *file) {
  struct file_info *info = find_file_info(file);
  
  if (info != NULL) {
    info->to_remove = true;  
    if (!info->is_open) {
      return filesys_remove(file);
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

  struct file_info *info = find_file_info(file_name);
  
  // If file has not been created
  if (info == NULL) {
    info = (struct file_info *) malloc(sizeof(struct file_info));
    
    struct file *file = filesys_open(file_name);
    if (file == NULL) {
      return -1;
    }

    info->file = file;

    // Need to have file in our list
    make_file_info(info, (char *) file_name);
    info->file = file;
    info->is_open = true;
    
    list_push_back(&all_files, &(info->elem));
  } 

  if (!info->is_open) {
    info->file = filesys_open(file_name);
    info->is_open = true;
  }  
  
  struct fd_elem *elem = (struct fd_elem *) malloc(sizeof(struct fd_elem));
  init_fd_elem(elem);
  list_push_back(info->fds, &(elem->elem));

  struct thread_fd_elem *t_elem = (struct thread_fd_elem *) malloc(sizeof(struct fd_elem));
  t_elem->fd = elem->fd;
  list_push_back(&(thread_current()->fds), &(t_elem->elem));

  return elem->fd;
}

static inline int kernel_read(int fd, void *buffer, unsigned size) {
  if (fd == STDIN_FILENO) {
    return input_getc();
  }

  if (!is_fd_valid(fd)) {
    kernel_exit(-1);
  }

  return file_read(fd_to_file(fd), buffer, size);
}

static inline int kernel_write(int fd, const void *buffer, unsigned size) {
  if (fd == STDOUT_FILENO) {
    putbuf((const char *) buffer, size);
    return size;
  }

  if (!is_fd_valid(fd)) {
    kernel_exit(-1);
  } 
  
  return file_write(fd_to_file(fd), buffer, size);
}

/* Implements the close system call by:
  - Removing the fd from the file's list of possible fds
  - Sets is_open to false
  - Removes the file if it was removed by another thread */
static inline void kernel_close(int fd) {
  if (!is_fd_valid(fd)) {
    kernel_exit(-1);
  }

  struct file_info *info = fd_to_file_info(fd);
  remove_fd(fd);

  if (list_empty(info->fds)) {
    file_close(info->file);
    info->is_open = false;
    if (info->to_remove) {
      kernel_remove(info->name);
    }
  }
}


/* Sets up file_info struct when a file is created. Many fields aren't
initialised because the file hasn't been opened yet. */
void make_file_info(struct file_info *info, char name[MAX_FILENAME_SIZE]) {
  struct list *fds = (struct list *) malloc(sizeof(struct list));
  list_init(fds);
  info->name = name;
  info->to_remove = false;
  info->is_open = false;
  info->fds = fds;
}

/* Initialises an fd_elem struct */
void init_fd_elem(struct fd_elem *elem) {
  elem->offset = 0;
  elem->fd = next_fd;
  next_fd++;
}

/* Initialises the rest of file_info fields when a file is opened */
void init_file_info(struct file_info *info, int fd, struct file *file) {
  struct list fds;
  list_init(&fds);
  struct fd_elem el;
  el.fd = fd;
  list_push_back(&fds, &(el.elem));
  info->fds = &fds;
  info->to_remove = false;
  info->file = file;
}

/* Returns the file_info struct of the file with the specified name */
struct file_info *find_file_info(const char *file) {
  return traverse_all_files(&get_file_info, (char *) file);
}

/* Helper for find_file_info. Checks the name of file_info struct and returns
it if the file has the right name */
struct file_info *get_file_info(struct list_elem *element, void *aux) {
  struct file_info *info = list_entry(element, struct file_info, elem);
  char *file = (char *) aux;
  if (!strcmp(info->name, file)) {
    return info;
  }
  return NULL;
}

/* Returns the file_info struct of the file with the specified fd */
struct file_info *fd_to_file_info (int fd) {
  return (struct file_info *) fd_apply(fd, &get_info_file);
}

/* Returns the file struct of the file with the specified fd */
struct file *fd_to_file(int fd) {
  return fd_to_file_info(fd)->file;
}

/* Helper for fd_to_fie_info. Returns the outer file_info struct from the 
list_element struct */
void *get_info_file(struct list_elem *file_elem, struct list_elem *fd_elem UNUSED) {
  return (void *) list_entry(file_elem, struct file_info, elem);
}

/* Checks whether the current thread has access to the specified fd */
bool is_fd_valid(int fd) {
  return find_fd_elem(fd) != NULL;
}

/* Removes an fd from the file's possible fds and from the current threads' list
of fds */
void remove_fd(int fd) {
  fd_apply(fd, &rem_fd);
  list_remove(&(find_fd_elem(fd)->elem));
}

/* Helper for remove_fd. Removes an fd from the file's possible fds and removes
the file if necessary */
void *rem_fd(struct list_elem *file_elem, struct list_elem *fd_elem) {
  struct file_info *info = list_entry(file_elem, struct file_info, elem);
  list_remove(fd_elem);
  if (!info->is_open && info->to_remove) {
    list_remove(file_elem);
  }
  return NULL;
}

/* Returns the thread_fd_elem struct with the specified fd */
struct thread_fd_elem *find_fd_elem(int fd) {
  if (!list_empty(&(thread_current()->fds))) {
    for (struct list_elem *curr = list_begin(&(thread_current()->fds)); 
         curr != list_tail(&(thread_current()->fds)); curr = list_next(curr)) {
      struct thread_fd_elem *elem = list_entry(curr, struct thread_fd_elem, elem);
      if (fd == elem->fd) {
        return elem;
      }
    }
  }
  return NULL;
}

void *traverse_all_files(void *func, void *aux) {
  struct list_elem *curr;
  infoFunc funct = (infoFunc) func;
  if(!list_empty(&all_files)) {
    for (curr = list_begin(&all_files); 
       curr != list_tail(&all_files); curr = list_next(curr)) {
      void *result = funct(curr, aux);
      if (result != NULL) {
        return result;
      }
    }
  }
  return NULL;
}

void *fd_apply(int fd, elemFunc func) {
  struct function_info fun_info;
  fun_info.fd = fd;
  fun_info.funct = func;
  return traverse_all_files (&traverse_fds, (void *) &fun_info);
}

void *traverse_fds(struct list_elem *curr, void *aux) {
  struct file_info *info = list_entry(curr, struct file_info, elem);
  struct list_elem *elem;
  struct function_info *fun_info = (struct function_info *) aux;
  if (!list_empty(info->fds)) {
    for (elem = list_begin(info->fds); 
        elem != list_tail(info->fds); elem = list_next(elem)) {
      struct fd_elem *fd_el = list_entry(elem, struct fd_elem, elem);

      if (fun_info->fd == fd_el->fd) {
        return fun_info->funct(curr, elem);
      }

    }
  }

  return NULL;
}
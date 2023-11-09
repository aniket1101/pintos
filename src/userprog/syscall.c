#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/timer.h"
#include "devices/shutdown.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include <string.h>
#include "debug.h"
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include "process.h"
#include "devices/input.h"

#define MAX_SIZE 100
#define MAX_FILENAME_SIZE 14

typedef void * (*elemFunc) (struct list_elem *, struct list_elem *);
typedef void * (*infoFunc) (struct list_elem *, void *);

static void syscall_handler (struct intr_frame *);
static int get_num_args(int);
static void *check_pointer(void *);

struct file_info {
	struct list *fds;
	struct file *file;
  char *name;
	bool to_remove;
  bool is_open;
	struct list_elem elem;
};

void rem_fd(struct list_elem *, struct list_elem *);
void remove_fd(int);
void init_file_info(struct file_info *, int, struct file *);
void *fd_apply(int *, void *);
void *inside_apply(struct list_elem *, void *);
void *outside_apply(void *, void *);
struct file_info *find_file_info(const char *);
void make_file_info(struct file_info *, char name[MAX_FILENAME_SIZE]);
struct thread_fd_elem *find_fd_elem(int);
bool is_fd_valid(int);
void init_fd_elem(struct fd_elem *);
struct file_info *fd_to_file_info (int);
struct file *fd_to_file(int);
struct file_info *get_info_file(struct list_elem *, struct list_elem * UNUSED);
struct file_info *get_file_info(struct list_elem *, void *);

static struct list all_files;

static int32_t next_fd;

/* Sets up file_info struct when a file is created. Many fields aren't
initialised because the file hasn't been opened yet. */
void make_file_info(struct file_info *info, char name[MAX_FILENAME_SIZE]) {
  struct list fds;
  list_init(&fds);
  info->name = name;
  info->to_remove = false;
  info->is_open = false;
  info->fds = &fds;
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
  list_push_back(&fds, &(el.fd_e));
  info->fds = &fds;
  info->to_remove = false;
  info->file = file;
}

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

  int syscall_num = *((int *) check_pointer(f->esp));
  PUTBUF_FORMAT("\tpopped syscall num = %d off at %p. moved stack up by %d", 
    syscall_num, f->esp, sizeof(int *)); 

  int num_args = get_num_args(syscall_num);
  PUTBUF_FORMAT("\tsyscall has %d args", num_args); 
  
  PUTBUF("Pop args:");
  void *args[3];
  for (int i = 0; i < num_args; i++) {
    args[i] = check_pointer(f->esp + sizeof(int *) + (i * sizeof(void *)));

    PUTBUF_FORMAT("\targ[%d] at %p", i, args[i]);
  }

  switch (syscall_num) {
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:
      PUTBUF("Call exit()");
      int status = *((int *) args[0]);
      exit(status);
      break;

    case SYS_WAIT:
      PUTBUF("Call wait()");
      pid_t pid = *((pid_t *) args[0]);
      f->eax = wait(pid);
      break;

    case SYS_WRITE:
      PUTBUF("Call write()");
      int fd = *((int*) args[0]);
      void *buff = *((void **) args[1]);
      unsigned size = *((unsigned *) args[2]);
      f->eax = write(fd, buff, size);
      break;
  }

  HEX_DUMP_ESP(f->esp);
  PUTBUF("End syscall");
}

/* Checks whether the pointer is valid */
void *check_pointer(void *ptr) {
  if (ptr != NULL && is_user_vaddr(ptr) 
      && pagedir_get_page(thread_current()->pagedir, ptr)) {
    return ptr;
  } 

  exit(-1);
}

void *outside_apply(void *func, void *aux) {
  struct list_elem *curr;
  infoFunc funct = (infoFunc) func;

  for (curr = list_begin(&all_files); 
       curr != list_end(&all_files); curr = list_next(curr)) {
    if (funct(curr, aux) != NULL) {
      break;
    }
  }
  return NULL;
}

void *fd_apply(int *fd, void *func) {
  void *aux[2] = {fd, func};
  return outside_apply(&inside_apply, aux);
}

void *inside_apply(struct list_elem *curr, void *aux) {
  struct file_info *info = list_entry(curr, struct file_info, elem);
  struct list_elem *elem;
  int fd = *((int *) (aux)); 
  elemFunc func = (elemFunc) (aux + sizeof(int)); 

  for (elem = list_begin(info->fds); 
      elem != list_end(info->fds); elem = list_next(elem)) {
    struct fd_elem *fd_el = list_entry(elem, struct fd_elem, fd_e);

    if (fd == fd_el->fd) {
      return func(curr, elem);
    }

  }
  return NULL;
}

/* Implements the halt system call */
void halt() {
  shutdown_power_off();
}

/* Implements the exit system call by:
- Setting the thread's exit code to the status
- Outputting a message with the exit code to the terminal */
void exit(int status) {
  struct thread *thread = thread_current();
  thread->exit_code = status;
  
  char buf[MAX_SIZE]; 
  int cnt;
  
  cnt = snprintf(buf, MAX_SIZE, "%s: exit(%d)\n", thread->name, thread->exit_code);
  write(1, buf, cnt);
  thread_exit();
}

// TODO
pid_t exec (const char *cmd_line) {

  pid_t pid = ((pid_t) process_execute(cmd_line));
  // int result = wait(pid);
  // need to check result
  if (pid == TID_ERROR) {
    return pid;
  }
  return pid - 1;
}

// TODO
int wait(pid_t pid UNUSED) {
  // while (true) {
  //   barrier();
  // }

  timer_sleep(600);
  return -1;
}

/* Implements the create system call by:
- Checking that the name is valid
- Makes a file_info struct for the new file
- Adding the struct to the list of files */
bool create (const char *file, unsigned initial_size) {
  if(file != NULL && strlen(file) <= MAX_FILENAME_SIZE && filesys_create(file, initial_size)) {
    struct file_info info;
    make_file_info(&info, (char *) file);
    list_push_back(&all_files, &(info.elem));
  }
  return false;
}

/* Implements the remove system call by:
- Getting the file_info struct of the file with the specified name
- Sets to_remove to true
- Deletes the file if the file is closed */
bool remove (const char *file) {
  struct file_info *info = find_file_info(file);
  info->to_remove = true;
  if (!info->is_open) {
    return filesys_remove(file);
  }
  return false;
}

/* Returns the file_info struct of the file with the specified name */
struct file_info *find_file_info(const char *file) {
  return outside_apply(&get_file_info, (char *) file);
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

// TODO
int open(const char *file_name) {
  // Get lock to modify all_files
  // lock_acquire(fd_lock);
  struct file_info *info = find_file_info(file_name);
  if (!info->is_open) {
    info->file = filesys_open(file_name);
    info->is_open = true;
  }  
  struct fd_elem elem;
  init_fd_elem(&elem);
  list_push_back(info->fds, &(elem.fd_e));
  struct thread_fd_elem t_elem = {.fd = elem.fd};
  list_push_back(thread_current()->fds, &(t_elem.fd_e));

  // lock_release(fd_lock);
  return elem.fd;
}

/* Implements the filesize system call by calculating the size of the file with
the specified fd */
int filesize(int fd) {
  if (is_fd_valid(fd)) {
    return file_length(fd_to_file(fd));
  } else {
    exit(-1);
  }
  
}

int read(int fd, void *buffer, unsigned size) {
  if (is_fd_valid(fd)) {
    if (fd == STDIN_FILENO) {
      return input_getc();
    } else {
      return file_read(fd_to_file(fd), buffer, size);
    }
  } else {
    exit(-1);
  }
}

// TODO
int write(int fd, const void *buffer, unsigned size) { 
  if (fd == STDOUT_FILENO) {
    // Write buffer to console
    putbuf((const char *) buffer, size);
  } else {
    // Write buffer to file, checking how many bytes can be written to
    // return file_write(get_open_file(fd)->file, buffer, size);
  }
  return size;
}

/* Implements the seek system call by changing the file's position */
void seek(int fd, unsigned position) {
  if (is_fd_valid(fd)) {
    file_seek(fd_to_file(fd), position);
  } else {
    exit(-1);
  }
}

/* Implements the tell system call by returning the file's position */
unsigned tell(int fd) {
  if (is_fd_valid(fd)) {
    return file_tell(fd_to_file(fd));
  } else {
    exit(-1);
  }
}

/* Implements the close system call by:
- Removing the fd from the file's list of possible fds
- Sets is_open to false
- Removes the file if it was removed by another thread */
void close(int fd) {
  // lock_acquire(fd_lock);
  if (is_fd_valid(fd)) {
    struct file_info *info = fd_to_file_info(fd);
    remove_fd(fd);
    if(list_empty(info->fds)) {
      file_close(info->file);
      info->is_open = false;
      if(info->to_remove) {
        remove(info->name);
      }
    }
  } else {
    exit(-1);
  }
}

/* Returns the file_info struct of the file with the specified fd */
struct file_info *fd_to_file_info (int fd) {
  return (struct file_info *) fd_apply(&fd, &get_info_file);
}

/* Returns the file struct of the file with the specified fd */
struct file *fd_to_file(int fd) {
  return fd_to_file_info(fd)->file;
}

/* Helper for fd_to_fie_info. Returns the outer file_info struct from the 
list_element struct */
struct file_info *get_info_file(struct list_elem *file_elem, struct list_elem *fd_elem UNUSED) {
  return list_entry(file_elem, struct file_info, elem);
}

/* Checks whether the current thread has access to the specified fd */
bool is_fd_valid(int fd) {
  return find_fd_elem(fd) != NULL;
}

/* Removes an fd from the file's possible fds and from the current threads' list
of fds */
void remove_fd(int fd) {
  fd_apply(&fd, &rem_fd);
  list_remove(&(find_fd_elem(fd)->fd_e));
}

/* Helper for remove_fd. Removes an fd from the file's possible fds and removes
the file if necessary */
void rem_fd(struct list_elem *file_elem, struct list_elem *fd_elem) {
  struct file_info *info = list_entry(file_elem, struct file_info, elem);
  list_remove(fd_elem);
  if (!info->is_open && info->to_remove) {
    list_remove(file_elem);
  }
}

/* Returns the thread_fd_elem struct with the specified fd */
struct thread_fd_elem *find_fd_elem(int fd) {
  for (struct list_elem *curr = list_begin(thread_current()->fds); 
       curr != list_end(thread_current()->fds); curr = list_next(curr)) {
    struct thread_fd_elem *elem = list_entry(curr, struct thread_fd_elem, fd_e);
    if (fd == elem->fd) {
      return elem;
    }
  }
  return NULL;
}

/* Returns the number of arguments the specified system call needs */
int get_num_args(int syscall_num) {
  switch (syscall_num) {
    case SYS_HALT:
      return 0;
    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
    case SYS_MUNMAP:
    case SYS_MKDIR:
    case SYS_ISDIR:
    case SYS_INUMBER:
      return 1;
    case SYS_CREATE:
    case SYS_SEEK:
    case SYS_MMAP:
    case SYS_READDIR:
      return 2;
    case SYS_READ:
    case SYS_WRITE:
      return 3;
    default:
      exit(-1);
  }
}
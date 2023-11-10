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
#include "threads/malloc.h"


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
void *traverse_fds(struct list_elem *, void *);
void *traverse_all_files(void *, void *);
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
  // HEX_DUMP_ESP(f->esp);  

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
      int exit_status = *((int *) args[0]);
      exit(exit_status);
      break;

    // case SYS_EXEC:
    //   break;

    case SYS_WAIT:
      PUTBUF("Call wait()");
      pid_t wait_pid = *((pid_t *) args[0]);
      f->eax = wait(wait_pid);
      break;

    case SYS_REMOVE:
      PUTBUF("Call remove()");
      char *remove_name = *((char **) args[0]);
      f->eax = remove(remove_name);
      break;

    case SYS_OPEN:
      PUTBUF("Call open()");
      const char *open_file_name = *((const char **) args[0]);
      f->eax = open(open_file_name);
      break;

    case SYS_FILESIZE:
      PUTBUF("Call filesize()");
      int filesize_fd = *((int *) args[0]);
      f->eax = filesize(filesize_fd);
      break;

    case SYS_TELL:
      PUTBUF("Call tell()");
      int tell_fd = *((int *) args[0]);
      f->eax = tell(tell_fd);
      break;

    case SYS_CLOSE:
      PUTBUF("Call close()");
      int close_fd = *((int *) args[0]);
      close(close_fd);
      break;

    // case SYS_MUNMAP:
    //   break;

    // case SYS_MKDIR:
    //   break;

    // case SYS_ISDIR:
    //   break;

    // case SYS_INUMBER:
    //   break;

    case SYS_CREATE:
      PUTBUF("Call create()");
      const char *create_name = *((const char **) args[0]);
      unsigned create_size = *((unsigned *) args[1]);
      f->eax = create(create_name, create_size);
      break;

    case SYS_SEEK:
      PUTBUF("Call seek()");
      int seek_fd = *((int *) args[0]);
      unsigned seek_position = *((unsigned *) args[1]);
      seek(seek_fd, seek_position);
      break;

    // case SYS_MMAP:
    //   break;

    // case SYS_READDIR:
    //   break;

    // case SYS_READ:
    //   break; 

    case SYS_WRITE:
      PUTBUF("Call write()");
      int write_fd = *((int*) args[0]);
      void *write_buff = *((void **) args[1]);
      unsigned write_size = *((unsigned *) args[2]);
      f->eax = write(write_fd, write_buff, write_size);
      break;

    default:
      exit(-1);
  }

  // HEX_DUMP_ESP(f->esp);
  PUTBUF("End syscall");
}

/* Checks whether the pointer is valid */
void *check_pointer(void *ptr) {
  if (ptr != NULL && is_user_vaddr(ptr) 
      && pagedir_get_page(thread_current()->pagedir, ptr) != NULL) {
    return ptr;
  } 

  exit(-1);
}

void *traverse_all_files(void *func, void *aux) {
  struct list_elem *curr;
  infoFunc funct = (infoFunc) func;
  if(!list_empty(&all_files)) {
    for (curr = list_begin(&all_files); 
       curr != list_tail(&all_files); curr = list_next(curr)) {
      struct file_info *info = list_entry(curr, struct file_info, elem);
      void *result = funct(curr, aux);
      if (result != NULL) {
        return result;
      }
    }
  }
  return NULL;
}

void *fd_apply(int *fd, void *func) {
  void *aux[2] = {fd, func};
  return traverse_all_files (&traverse_fds, aux);
}

void *traverse_fds(struct list_elem *curr, void *aux) {
  struct file_info *info = list_entry(curr, struct file_info, elem);
  struct list_elem *elem;
  int fd = *((int *) (aux)); 
  elemFunc func = (elemFunc) (aux + sizeof(int)); 
  
  if (!list_empty(info->fds)) {
    for (elem = list_begin(info->fds); 
        elem != list_tail(info->fds); elem = list_next(elem)) {
      struct fd_elem *fd_el = list_entry(elem, struct fd_elem, fd_e);

      if (fd == fd_el->fd) {
        return func(curr, elem);
      }

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
bool create(const char *file, unsigned initial_size) {

  if (file == NULL) {
    exit(-1);
  }

  bool creates = filesys_create(file, (off_t) initial_size);

  if(strlen(file) <= MAX_FILENAME_SIZE && creates) {
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

// TODO
int open(const char *file_name) {
  // Get lock to modify all_files
  // lock_acquire(fd_lock);

  // Check if file name is NULL or ""
  if (file_name == NULL ) {
    exit(-1);
  } else if (!strcmp(file_name, "")) {
    return -1;
  }
  struct file_info *info = find_file_info(file_name);
  
  // If file has not been created
  if(info == NULL) {
    struct file_info *new_info = (struct file_info *) malloc(sizeof(struct file_info));
    struct file *file = filesys_open(file_name);
    new_info->file = file;
    if (file == NULL) {
      return -1;
    }
    // Need to have file in our list
    make_file_info(new_info, (char *) file_name);
    new_info->file = file;
    new_info->is_open = true;
    info = new_info;
    list_push_back(&all_files, &(info->elem));
  } 

  if (!info->is_open) {
    info->file = filesys_open(file_name);
    info->is_open = true;
  }  

  struct fd_elem *elem = (struct fd_elem *) malloc(sizeof(struct fd_elem));
  init_fd_elem(elem);
  list_push_back(info->fds, &(elem->fd_e));

  struct thread_fd_elem *t_elem = (struct thread_fd_elem *) malloc(sizeof(struct fd_elem));
  t_elem->fd = elem->fd;
  list_push_back(&(thread_current()->fds), &(t_elem->fd_e));

  return elem->fd;
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
    // return file_write(fd_to_file(fd), buffer, size);
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
  if (!list_empty(&(thread_current()->fds))) {
    for (struct list_elem *curr = list_begin(&(thread_current()->fds)); 
         curr != list_tail(&(thread_current()->fds)); curr = list_next(curr)) {
      struct thread_fd_elem *elem = list_entry(curr, struct thread_fd_elem, fd_e);
      if (fd == elem->fd) {
        return elem;
      }
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
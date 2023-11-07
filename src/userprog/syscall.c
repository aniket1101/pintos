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
static int get_num_args(int syscall_num);
static void *check_pointer(void *ptr);

struct file_info {
	struct list *fds;
	struct file *file;
	bool to_remove;
	struct list_elem elem;
};

void rem_fd(struct list_elem *file_elem, struct list_elem *fd_elem);
void remove_fd(int fd);
struct file *get_file(struct list_elem *file_elem, struct list_elem fd_elem UNUSED);
struct file *fd_to_file(int fd);
void init_file_info(struct file_info *info, int fd, struct file *file);
void *fd_apply(int *fd, void *func);
void *inside_apply(struct list_elem *curr, void *aux);
void *outside_apply(void *func, void *aux);
// struct open_file * get_open_file(int fd);

static struct list open_files;

// static struct lock *fd_lock;

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
  list_init(&open_files);
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

void *check_pointer(void *ptr) {
  if (ptr != NULL && is_user_vaddr(ptr) 
      && pagedir_get_page(thread_current()->pagedir, ptr)) {
    return ptr;
  } 

  exit(-1);
}

// void *fd_apply(int fd, fd_function *func) {
//   struct list_elem *curr;
//   struct list_elem *elem;
  
//   for (curr = list_begin(&open_files); 
//        curr != list_end(&open_files); curr = list_next(curr)) {
//     struct file_info *info = list_entry(curr, struct file_info, elem);

//     for (elem = list_begin(&(info->fds)); 
//        elem != list_end(&(info->fds)); elem = list_next(elem)) {
//       struct fd_elem *fd_e = list_entry(fd_e, struct fd_elem, fd_elem)

//       if (fd == fd_e->fd) {
//         return func(curr, elem);
//       }

//     }
//   }
//   return NULL;
// }

void *outside_apply(void *func, void *aux) {
  struct list_elem *curr;
  infoFunc funct = (infoFunc) func;

  for (curr = list_begin(&open_files); 
       curr != list_end(&open_files); curr = list_next(curr)) {
    funct(curr, aux);
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

void halt() {
  shutdown_power_off();
}

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

bool create (const char *file, unsigned initial_size) {
  if(file != NULL && strlen(file) <= MAX_FILENAME_SIZE) {
    return filesys_create(file, initial_size);
  }
  return false;
}

bool remove (const char *file) {
  if (filesys_remove(file)) {

    return true;
  }
  return false;
}

// // TODO
// int open(const char *file_name) {
//   // Get lock to modify open_files
//   // lock_acquire(fd_lock);
//   struct file *file = filesys_open(file_name);
//   if (file == NULL) {
//     // lock_release(fd_lock);
//     return -1;
//   }
//   int fd = add_to_open_files(file);

//   // lock_release(fd_lock);
//   return fd;
// }

// int filesize(int fd) {
//   struct file *file = get_open_file(fd)->file_openers->file;
//   if (file != NULL) {
//     return file_length(get_open_file(fd)->file_openers->file);
//   }
//   return 0;
// }

// int read(int fd, void *buffer, unsigned size) {
//   if (fd == STDIN_FILENO) {
//     return input_getc();
//   } else {
//     return file_read(get_open_file(fd)->file_openers->file, buffer, size);
//   }
// }

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

// void seek(int fd, unsigned position) {
//   struct file *file = get_open_file(fd)->file_openers->file;
//   // Position is above 0 as it is unsigned, assertion will not fail
//   if (file != NULL) {
//     file_seek(file, position);
//   }
// }

// unsigned tell(int fd) {
//   struct file *file = get_open_file(fd)->file_openers->file;
//   if (file != NULL) {
//     return file_tell(file);
//   }
//   return -1;
// }

// void close(int fd) {
//   // lock_acquire(fd_lock);
//   struct open_file *file = get_open_file(fd);
//   if (file != NULL) {
//     list_remove(&(file->elem));
//     file_close(file->file_openers->file);
//   }
//   // lock_release(fd_lock);
// }

struct file *fd_to_file(int fd) {
  return (struct file *) fd_apply(&fd, &get_file);
}

struct file *get_file(struct list_elem *file_elem, struct list_elem fd_elem UNUSED) {
  struct file_info *info = list_entry(file_elem, struct file_info, elem);
  return info->file;
}

void remove_fd(int fd) {
  fd_apply(&fd, &rem_fd);
}

void rem_fd(struct list_elem *file_elem, struct list_elem *fd_elem) {
  struct file_info *info = list_entry(file_elem, struct file_info, elem);
  list_remove(fd_elem);
  if (list_empty(info->fds) && info->to_remove) {
    list_remove(file_elem);
  }
}

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
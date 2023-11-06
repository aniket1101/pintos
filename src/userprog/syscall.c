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

static void syscall_handler (struct intr_frame *);
static int get_num_args(int syscall_num);
static void *check_pointer(void *ptr);
int add_to_open_files(struct file *file);
struct open_file * get_open_file(int fd);

struct open_file {
  struct list_elem elem;
  int file_desc;
  struct file *file;
  // struct list readers;
  bool to_be_removed;
};

static struct list open_files;

// static struct lock *fd_lock;

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

pid_t exec (const char *cmd_line) {

  pid_t pid = ((pid_t) process_execute(cmd_line));
  // int result = wait(pid);
  // need to check result
  if (pid == TID_ERROR) {
    return pid;
  }
  return pid - 1;
}

int wait(pid_t pid UNUSED) {
  // while (true) {
  //   barrier();
  // }

  timer_sleep(600);
  return -1;
}

bool create (const char *file, unsigned initial_size) {
  bool success = false;
  if(file != NULL && strlen(file) <= 14) {
    success = filesys_create(file, initial_size);
  }
  return success;
}

bool remove (const char *file) {
  return filesys_remove(file);
}

int add_to_open_files(struct file *file) {
  // Initialise new file
  struct open_file new_file; 
  new_file.file = file;
  // new_file.readers = list_init(&readers);
  new_file.to_be_removed = false;
  
  if (list_empty(&open_files)) {
    // List is empty, so new desc will be 2
    new_file.file_desc = 2;
    list_push_front(&open_files, &(new_file.elem));

    return new_file.file_desc;
  } else {
    // Initialised to 1 in the case that 2 is not being used
    int pre_file_desc = 1;
    // Initialised outside of the loop in the case it will be put at the end
    struct list_elem *e = list_begin (&open_files); 
    for (; e != list_end (&open_files); e = list_next (e))
    {
      // Finds a gap in ordered list and inserts new element
      if (list_entry(e, struct open_file, elem)->file_desc - pre_file_desc > 1) {
        new_file.file_desc = pre_file_desc + 1;
        list_insert(&(new_file.elem), e);

        return new_file.file_desc;
      }
      // Ensures that getting e->prev will not give the head for list_entry
      if (e != list_begin (&open_files)) {
        pre_file_desc = list_entry(e->prev, struct open_file, elem)->file_desc;
      }
    }
    // e is pointing to the tail of the list
    new_file.file_desc = list_entry(e->prev, struct open_file, elem)->file_desc + 1;
  }
  return -1;
}

// TODO
int open(const char *file_name) {
  // Get lock to modify open_files
  // lock_acquire(fd_lock);
  struct file *file = filesys_open(file_name);
  if (file == NULL) {
    // lock_release(fd_lock);
    return -1;
  }
  int fd = add_to_open_files(file);

  // lock_release(fd_lock);
  return fd;
}

int filesize(int fd) {
  struct file *file = get_open_file(fd)->file;
  if (file != NULL) {
    return file_length(get_open_file(fd)->file);
  }
  return 0;
}

int read(int fd, void *buffer, unsigned size) {
  if (fd == STDIN_FILENO) {
    return input_getc();
  } else {
    return file_read(get_open_file(fd)->file, buffer, size);
  }
}

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

void seek(int fd, unsigned position) {
  //TODO
  struct file *file = get_open_file(fd)->file;
  // Position is above 0 as it is unsigned, assertion will not fail
  if (file != NULL) {
    file_seek(file, position);
  }
}

unsigned tell(int fd) {
  // TODO
  struct file *file = get_open_file(fd)->file;
  if (file != NULL) {
    return file_tell(file);
  }
  return -1;
}

struct open_file * get_open_file(int fd) {
  struct list_elem *e; 
  for (e = list_begin (&open_files);
    e != list_end (&open_files); e = list_next (e)) {
    struct open_file *file = list_entry(e, struct open_file, elem);
    if (file->file_desc == fd) {
      return file;
    }
  }
  return NULL;
}

void close(int fd) {
  // lock_acquire(fd_lock);
  struct open_file *file = get_open_file(fd);
  if (file != NULL) {
    list_remove(&(file->elem));
    file_close(file->file);
  }
  // lock_release(fd_lock);
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
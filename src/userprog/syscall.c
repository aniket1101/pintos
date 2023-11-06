#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/timer.h"
#include "userprog/pagedir.h"
#include "threads/vaddr.h"
#include <string.h>
#include "debug.h"

#define MAX_SIZE 100

static void syscall_handler (struct intr_frame *);
static int get_num_args(int syscall_num);
static void check_pointer(void *ptr);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_num = *((int *) (f->esp));
  f->esp -= sizeof(int);
  
  int num_args = get_num_args(syscall_num);
  void *args[3];
  for (int i = 0; i < num_args; i++) {
    args[i] = f->esp;
    f->esp -= sizeof(*args[i]);
  }

  switch (syscall_num) {
    case SYS_EXIT:
      int status = *((int *) args[0]);
      exit(status);
      break;
    case SYS_WAIT:
      pid_t pid = *((pid_t *) args[0]);
      f->eax = wait(pid);
      break;
    case SYS_WRITE:
      int fd = *((int*) args[0]);
      void *buff = *((void **) args[1]);
      check_pointer(buff);
      unsigned size = *((unsigned *) args[2]);
      f->eax = write(fd, buff, size);
      break;
  }
}

void check_pointer(void *ptr) {
  struct thread *thread = thread_current();
  bool valid = true;
  if (ptr == NULL) {
    valid = false;
  } else if (is_kernel_vaddr(ptr)) {
    valid = false;
  } else if (pagedir_get_page(thread->pagedir, ptr)) {
    valid = false;
  }
  if (!valid) {
    thread_exit();
  }
}

int wait(pid_t pid UNUSED) {
  // while (true) {
  //   barrier();
  // }

  timer_sleep(600);
  return -1;
}

void exit(int status) {
  struct thread *thread = thread_current();
  thread->exit_code = status;
  
  char buf[MAX_SIZE]; 
  int cnt;
  
  cnt = snprintf(buf, MAX_SIZE, "%s: exit(%d)", thread->name, thread->exit_code);
  write(1, buf, cnt);
  thread_exit();
}

int write(int fd, const void *buffer, unsigned size) {
  if (fd == STDOUT_FILENO) {
    putbuf(buffer, size);
  }
  
  return size;
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
      return -1;
  }
}
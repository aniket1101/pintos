#include "userprog/syscall.h"
#include "lib/user/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/timer.h"

static void syscall_handler (struct intr_frame *);
static int get_num_args(int syscall_num);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  int syscall_num = (int) f->esp;
  f->esp -= sizeof(int);
  
  int num_args = get_num_args(syscall_num);
  void *args[3];
  for (int i = 0; i < num_args; i++) {
    args[i] = f->esp;
    f->esp -= sizeof(*args[i]);
  }

  switch (syscall_num) {
    case SYS_EXIT:
      exit((int) args[0]);
      break;
    case SYS_WAIT:
      f->eax = wait((pid_t) args[0]);
      break;
    case SYS_WRITE:
      f->eax = write((int) args[0], (const void *) args[1], (unsigned) args[2]);
      break;
  }
}

int wait(pid_t pid) {
  // while (true) {
  //   barrier();
  // }

  timer_sleep(500);
  return -1;
}
void exit(int status) {
  char buf[] = "Status is ";
  putbuf(buf, 10);
  thread_exit();
}

int write(int fd, const void *buffer, unsigned size) {
  if (fd == 1) {
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
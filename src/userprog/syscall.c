#include <syscall-nr.h>
#include <string.h>
#include <stdio.h>
#include "lib/user/syscall.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "userprog/debug.h"
#include "devices/timer.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"

#define MAX_SIZE 100
#define POP_STACK(type, esp) (*((type *) check_pointer(esp)))
#define POP_STACK_ARG(type, argnum) POP_STACK(type, f->esp + ((argnum + 1) * WORD_SIZE))

#define handle0(func) ({\
  func();\
  })

#define handle1(func, type1) ({\
  type1 a = POP_STACK_ARG(type1, 0);\
  func(a);\
  })

#define handle2(func, type1, type2) ({\
  type1 a = POP_STACK_ARG(type1, 0);\
  type2 b = POP_STACK_ARG(type2, 1);\
  func(a, b);\
  })

#define handle3(func, type1, type2, type3) ({\
  type1 a = POP_STACK_ARG(type1, 0);\
  type2 b = POP_STACK_ARG(type2, 1);\
  type3 c = POP_STACK_ARG(type3, 2);\
  func(a, b, c);\
  })

static void syscall_handler (struct intr_frame *);
static void call1(int syscall_num, struct intr_frame *f);
static void call2(int syscall_num, struct intr_frame *f);
static void call3(int syscall_num, struct intr_frame *f);
static int get_num_args(int syscall_num);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

typedef void (*call_func)(int syscall_num, struct intr_frame *f);

static void
syscall_handler (struct intr_frame *f) 
{
  PUTBUF("Start syscall:");
  HEX_DUMP_ESP(f->esp);  

  int syscall_num = POP_STACK(int, f->esp);
  PUTBUF_FORMAT("\tpopped syscall num = %d off at %p. moved stack up by %d", 
    syscall_num, f->esp, sizeof(int *)); 

  call_func call;
  
  switch (syscall_num) {
    case SYS_HALT:
      PUTBUF("Call halt()");
      handle0(halt);

    case SYS_EXIT:
    case SYS_EXEC:
    case SYS_WAIT:
    case SYS_REMOVE:
    case SYS_OPEN:
    case SYS_FILESIZE:
    case SYS_TELL:
    case SYS_CLOSE:
      call = &call1;
      break;

    case SYS_CREATE:
    case SYS_SEEK:
      call = &call2;
      break;

    case SYS_WRITE:
      call = &call3;
      break;

    default:
      exit(-1);
  }

  call(syscall_num, f);

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

static void call1(int syscall_num, struct intr_frame *f) {
  switch (syscall_num) {
    case SYS_EXIT:
      PUTBUF("Call exit()");
      handle1(exit, int);
      break;

    case SYS_WAIT:
      PUTBUF("Call wait()");
      f->eax = handle1(wait, pid_t);
      break;
  }
}

static void call2(int syscall_num, struct intr_frame *f) {
  switch (syscall_num) {
  }
}

static void call3(int syscall_num, struct intr_frame *f) {
  switch (syscall_num) {
    case SYS_WRITE:
      PUTBUF("Call write()");
      f->eax = handle3(write, int, void *, unsigned);
      break;
  }
}

void halt() {
  shutdown_power_off();
}

void exit(int status) {
  struct thread *thread = thread_current();
  thread->exit_code = status;
  
  char buf[MAX_SIZE]; int cnt;
  cnt = snprintf(buf, MAX_SIZE, 
    "%s: exit(%d)\n", thread->name, thread->exit_code);
  
  write(1, buf, cnt);
  thread_exit();
}

int wait(pid_t pid UNUSED) {
  return process_wait(pid);
}

int write(int fd, const void *buffer, unsigned size) {
  if (fd == STDOUT_FILENO) {
    putbuf((const char *) buffer, size);
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
      exit(-1);
  }
}
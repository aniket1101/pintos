#include <syscall-nr.h>
#include <string.h>
#include <stdio.h>
#include <user/syscall.h>
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

#define pop_stack(esp, type) *((type *) check_pointer(esp))
#define pop_arg(argnum, type) pop_stack(f->esp + ((argnum + 1) * WORD_SIZE), type)

#define NUM_SYSCALLS 13

static void syscall_handler (struct intr_frame *);

static void syscall_halt(struct intr_frame *f);
static void syscall_exit(struct intr_frame *f);
static void syscall_exec(struct intr_frame *f);
static void syscall_wait(struct intr_frame *f);
static void syscall_create(struct intr_frame *f);
static void syscall_remove(struct intr_frame *f);
static void syscall_open(struct intr_frame *f);
static void syscall_filesize(struct intr_frame *f);
static void syscall_read(struct intr_frame *f);
static void syscall_write(struct intr_frame *f);
static void syscall_seek(struct intr_frame *f);
static void syscall_tell(struct intr_frame *f);
static void syscall_close(struct intr_frame *f);

typedef void (*syscall_func)(struct intr_frame *f); 
syscall_func syscalls[NUM_SYSCALLS] = {
  &syscall_halt, 
  &syscall_exit, 
  &syscall_exec, 
  &syscall_wait, 
  &syscall_create,
  &syscall_remove, 
  &syscall_open, 
  &syscall_filesize, 
  &syscall_read, 
  &syscall_write, 
  &syscall_seek, 
  &syscall_tell, 
  &syscall_close
}; 

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f) 
{
  PUTBUF("Start syscall:");
  HEX_DUMP_ESP(f->esp);  

  int syscall_num = pop_stack(f->esp, int);
  PUTBUF_FORMAT("\tpopped syscall num = %d off at %p. moved stack up by %d", 
    syscall_num, f->esp, sizeof(int *)); 

  if (syscall_num < 0 || syscall_num >= NUM_SYSCALLS) {
    exit(-1);
  } 

  syscalls[syscall_num](f);

  HEX_DUMP_ESP(f->esp);
  PUTBUF("End syscall");
}

void *check_pointer(void *ptr) {
  if (is_user_vaddr(ptr) 
      && pagedir_get_page(thread_current()->pagedir, ptr)) {
    return ptr;
  } 

  exit(-1);
}

static void syscall_halt(struct intr_frame *f UNUSED) {
  PUTBUF("Call halt syscall");
  shutdown_power_off();
}

static void syscall_exit(struct intr_frame *f) {
  PUTBUF("Call exit syscall");
  thread_current()->exit_code = pop_arg(0, int);
  exit(thread_current()->exit_code);
}

void exit(int status) {
  char buf[MAX_SIZE]; int cnt;
  cnt = snprintf(buf, MAX_SIZE, "%s: exit(%d)\n", 
    thread_current()->name, status);
  putbuf(buf, cnt);

  process_exit();
  thread_exit();
}

static void syscall_exec(struct intr_frame *f UNUSED) {
  PUTBUF("Call exec syscall");
}

static void syscall_wait(struct intr_frame *f UNUSED) {
  PUTBUF("Call wait syscall");
  pid_t pid = pop_arg(0, pid_t);
  f->eax = process_wait(pid);
}

static void syscall_create(struct intr_frame *f UNUSED) {
  PUTBUF("Call create syscall");
}

static void syscall_remove(struct intr_frame *f UNUSED) {
  PUTBUF("Call remove syscall");
}

static void syscall_open(struct intr_frame *f UNUSED) {
  PUTBUF("Call open syscall");
}

static void syscall_filesize(struct intr_frame *f UNUSED) {
  PUTBUF("Call filesize syscall");
}

static void syscall_read(struct intr_frame *f UNUSED) {
  PUTBUF("Call read syscall");
}

static void syscall_write(struct intr_frame *f) {
  PUTBUF("Call write syscall");
  int fd = pop_arg(0, int);
  const void *buffer = pop_arg(1, const void *);
  unsigned size = pop_arg(2, unsigned);
  
  if (fd == STDOUT_FILENO) {
    putbuf((const char *) buffer, size);
  }
  
  f->eax = size;
}

static void syscall_seek(struct intr_frame *f UNUSED) {
  PUTBUF("Call seek syscall");
}

static void syscall_tell(struct intr_frame *f UNUSED) {
  PUTBUF("Call tell syscall");
}

static void syscall_close(struct intr_frame *f UNUSED) {
  PUTBUF("Call close syscall");
}
#include "threads/thread.h"
#include <stdlib.h>
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "devices/timer.h"
#ifdef USERPROG
  #include "userprog/process.h"
  #include "userprog/fd.h"
  #include "userprog/debug.h"
#endif
#ifdef VM
  #include "vm/page.h"
  #include "vm/mmap.h"
#endif


/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

// Clamp a value between its minimum and maximum
#define CLAMP_PRI(val) (CLAMP(val, PRI_MIN, PRI_MAX)) // Clamp a priority

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-mlfqs". */
bool thread_mlfqs;

static fp_t load_avg;           /* load_avg global fixed point variable */

/* Stores threads that have run during the current time slice, so that priority
updates aren't lost for threads that don't run for the entire slice */
static struct thread *currents[4]; 

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

static void recalculate_thread_priority(struct thread *, void * UNUSED);
static void recalculate_thread_load_avg (void);
static void update_recent_cpu(struct thread *, void * UNUSED);
static void recalculate_scheduler_values (void);
static int is_thread_greater(const void *, const void *);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  /* Initialise nice value to 0 for starting thread*/
  initial_thread->nice = NICE_DEFAULT;  
  /* Initialise recent_cpu value to 0 for starting thread*/
  initial_thread->recent_cpu = 0;
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
  /* Initialise load_avg to 0 at the start of the program */
  load_avg = 0; 
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void) 
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();

  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Returns the number of threads currently in the ready list. 
   Disables interrupts to avoid any race-conditions on the ready list. */
size_t
threads_ready (void)
{
  enum intr_level old_level = intr_disable ();
  return list_size (&ready_list);
  intr_set_level (old_level);
  
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void) 
{
  struct thread *t = thread_current ();
  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else 
    kernel_ticks++;

  if (thread_mlfqs) {
    /* Recalculate all the priority, recent_cpu and load_avg as necessary. */
    recalculate_scheduler_values(); 
  }

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
    intr_yield_on_return ();
}

/* Compares threads by their memory*/
int is_thread_greater(const void *t1, const void *t2) {
  return t1 > t2;  
}

/* Recalculates the priority, recent_cpu and load_avg at each timer 
   interrupt. */
void
recalculate_scheduler_values (void)
{
  struct thread *current = thread_current();

  /* Each time a timer interrupt occurs, recent cpu is incremented by 1 for 
     the running thread only, unless the idle thread is running. Also, the
     thread that is running for the tick is added to the currents list */
  if (current != idle_thread) {
    current->recent_cpu = ADD_FP_AND_INT(current->recent_cpu, 1);
    currents[timer_ticks() % TIME_SLICE] = current;
  } 

  /* Recalculate recent_cpu and load _avg when when the system tick counter  
     reaches a multiple of a second. Also updates the priority of all threads, 
     which is called inside update_recent_cpu to only iterate through all
     threads once */ 
  if (timer_ticks() % TIMER_FREQ == 0) {
    recalculate_thread_load_avg();
    thread_foreach(&update_recent_cpu, NULL);

    /* Recalculate priority for all threads that have run this time slice on 
    every fourth clock tick, noting that the priority for a thread only changes 
    when its recent_cpu changes, which is every second for threads that have not 
    run, so they don't need to have their priority updated every slice */
  } else if (timer_ticks() % TIME_SLICE == 0) {
    /* Sorts currents to group timer ticks where the same thread has run */ 
    qsort(currents, TIME_SLICE, sizeof(struct thread *), is_thread_greater);
    /* Current[0] will always need to be updated */
    recalculate_thread_priority(currents[0], NULL);
    
    /* Updates the rest of threads that have run */
    for (int i = 1;  i < TIME_SLICE; i++) {
      /* Checks whether we have already updated the thread*/
      if (currents[i] != currents[i - 1] && currents[i] != idle_thread) {
        recalculate_thread_priority(currents[i], NULL);
      }
    }
  } 

}

/* Prints thread statistics. */
void
thread_print_stats (void) 
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority, 
               thread_func *function, void *aux) 
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread values for advanced scheduler */
  if (thread_mlfqs) {
    t->nice = thread_current()->nice;
    t->recent_cpu = thread_current()->recent_cpu;
    recalculate_thread_priority(t, NULL);
    priority = t->base_priority; 
  } 

  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  intr_set_level (old_level);

  /* Add to run queue. */
  thread_unblock (t);

#ifdef USERPROG
  fd_hash_init(t);
#endif

  #ifdef VM
    if (t->tid > 1) {
      supp_page_table_init(t);
      mmap_init(&t->mmap_table);
      t->map_id = 0;
    }
    t->esp = NULL;
  #endif

  try_yield();  
  
  return tid;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void) 
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);

  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Removes maximal element from a list and returns it */
struct list_elem *list_pop_max(struct list *list, list_less_func *less, 
    void *aux) {
  struct list_elem *elem = list_max(list, less, aux);
  list_remove(elem);
  return elem;
}

static int choose_correct_priority(struct thread *thread) {
  return (thread_mlfqs) ? 
    thread->base_priority : thread->eff_priority;
}

/* Compares a threads effective priority from its locks. */
bool thread_less(const struct list_elem *a, 
    const struct list_elem *b, void *aux UNUSED) {
  return choose_correct_priority(ELEM_TO_THREAD(a)) 
    < choose_correct_priority(ELEM_TO_THREAD(b));
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  // Insert current thread into ready_list in correct priority position 
  list_push_back(&ready_list, &(t->elem));  
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  ASSERT (!intr_context ());

  DISABLE_INTR(
    if (cur != idle_thread) { 
      list_push_back(&ready_list, &cur->elem);
    }

    cur->status = THREAD_READY;
    schedule ();
  );
}

/* Yield if not in an interrupt context and 
   if current thread should be preempted */
void try_yield(void) {
  DISABLE_INTR(
    struct thread *next_thread 
      = ELEM_TO_THREAD(list_max(&ready_list, &thread_less, NULL));
    
    // If next thread's priority >= current priority
    if (choose_correct_priority(thread_current()) 
        <= choose_correct_priority(next_thread)) {
      // Preempt
      if (intr_context()) {
        intr_yield_on_return();
      } else {
        thread_yield(); 
      }
    }
  );
}

/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority) 
{
  // If we're using advanced scheduler, ignore calls to thread_set_priority
  if (thread_mlfqs) { return; }

  DISABLE_INTR(
    // Set thread's priority 
    thread_current ()->base_priority = CLAMP_PRI(new_priority);
    thread_set_eff_priority(thread_current());
    try_yield();
  );
}

/* Sets the effective priority of a particular thread to either its base
priority or the highest priority of its held locks (donated priority) */
void thread_set_eff_priority(struct thread *thread) {
  DISABLE_INTR(
    int temp_eff_priority;
    struct list *held_locks = &(thread->held_locks);

    if (list_empty(held_locks)) {
      temp_eff_priority = PRI_MIN;
    } else {
      struct lock *lock = ELEM_TO_LOCK(list_max(held_locks, &lock_less, NULL));
      temp_eff_priority = lock->eff_priority;      
    }

    thread->eff_priority = MAX(thread->base_priority, temp_eff_priority);
  );
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return thread_current ()->eff_priority;
}

/* Recalculates the priority based on the formula:
priority = PRI_MAX - (recent_cpu / 4) - (nice * 2) */
void recalculate_thread_priority(struct thread *thread, void *aux UNUSED) {
  fp_t recent_scaled = DIV_FP_BY_INT(thread->recent_cpu, 4);
  int nice_scaled = thread->nice * 2;
  fp_t temp_priority = 
    MULT_FP_BY_INT(SUB_FP_AND_INT(recent_scaled, PRI_MAX - nice_scaled), -1);

  thread->base_priority = CLAMP_PRI(FP_TO_INT_ROUND_ZERO(temp_priority)); 
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice) 
{
  /* Check that a valid niceness value has been passed in */
  ASSERT(thread_mlfqs);
  ASSERT(nice >= NICE_MIN && nice <= NICE_MAX);
  
  thread_current()->nice = nice; // Set the thread's niceness
  recalculate_thread_priority(thread_current (), NULL); // Recalculate priority
  
  try_yield();
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current ()->nice;
}

/* Calculates new value of load_avg according to the formula: 
   (59/60)*load_avg + (1/60)*ready_threads
   where (59/60) is load_avg_coeff and (1/60) is ready_threads_coeff */
void
recalculate_thread_load_avg(void) {
  fp_t load_avg_coeff = DIV_FP_BY_INT(INT_TO_FP(59), 60);
  fp_t ready_threads_coeff = DIV_FP_BY_INT(INT_TO_FP(1), 60);

  int ready_threads = threads_ready();
  if (thread_current() != idle_thread) {
    ready_threads++;
  }

  load_avg_coeff = MULT_FPS(load_avg_coeff, load_avg);
  ready_threads_coeff = MULT_FP_BY_INT(ready_threads_coeff, ready_threads);

  load_avg = ADD_FPS(load_avg_coeff, ready_threads_coeff);
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{
  return FP_TO_NEAREST_INT(MULT_FP_BY_INT(load_avg, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  return FP_TO_NEAREST_INT(MULT_FP_BY_INT(thread_current()->recent_cpu, 100));
}

/* Updates the recent_cpu value of the specific thread
recent_cpu = (2*load_avg)/(2*load_avg + 1) * recent_cpu + nice */
void update_recent_cpu(struct thread *thread, void *aux UNUSED) {
  fp_t avg_doubled = MULT_FP_BY_INT(load_avg, 2); 
  fp_t recent_coeff = DIV_FPS(avg_doubled, ADD_FP_AND_INT(avg_doubled, 1));

  thread->recent_cpu = 
    ADD_FP_AND_INT(MULT_FPS(recent_coeff, thread->recent_cpu), thread->nice);

  recalculate_thread_priority(thread, NULL);
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->base_priority = priority;
  t->eff_priority = priority;
  list_init(&t->held_locks);
  t->magic = THREAD_MAGIC;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else {
    return ELEM_TO_THREAD(list_pop_max(&ready_list, &thread_less, NULL));
  }
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);

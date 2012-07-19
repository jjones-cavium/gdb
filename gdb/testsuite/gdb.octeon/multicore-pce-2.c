/* Debugger test case to test "uuload" performance counter event. */
#include <cvmx.h>
#include <cvmx-spinlock.h>

volatile long long x = 0;
static void
foo (void)
{
  volatile long long *ptr;
  int i;

  struct {
    unsigned char i;
    long long j;
  } __attribute__ ((packed)) __attribute__ ((aligned(4))) xyz;

  int core_num = cvmx_get_core_num ();

  ptr = (long long *) &xyz.j;
  if (core_num == 1)
    *ptr = 3;
  else
    x = *ptr + 2;
}

int
main (void)
{
  CVMX_SHARED static cvmx_spinlock_t core_lock = 
			CVMX_SPINLOCK_UNLOCKED_INITIALIZER;

  foo ();

  /* Check here the performance counter value. */
  cvmx_spinlock_lock (&core_lock);
  if (x != 3) x = 3; /* set common breakpoint here */
  cvmx_spinlock_unlock (&core_lock);

  while (1); 
}

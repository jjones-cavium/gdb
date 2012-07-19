/* Debugger test case to test performance counter events in two cores. */

#include <cvmx.h>
#include <cvmx-spinlock.h>

/* This test requires 2 cores but CN30XX has only one core, generate an error. */
#ifndef OCTEON_MODEL
#error OCTEON_MODEL is not defined
#endif

#if (OCTEON_MODEL == OCTEON_CN3010 \
	|| OCTEON_MODEL == OCTEON_CN3010_PASS1  \
	|| OCTEON_MODEL == OCTEON_CN3010_PASS1_1 \
	|| OCTEON_MODEL == OCTEON_CN3005 \
	|| OCTEON_MODEL == OCTEON_CN3005_PASS1 \
	|| OCTEON_MODEL == OCTEON_CN3005_PASS1_1)
#error CN3010/CN3005 has only one core
#endif

static void
foo (void)
{
  volatile long i, j = 0;
  long x;

  int core_num = cvmx_get_core_num ();
  if (core_num) 
    {
      j += 2;  /* core1 break here */
      x = 10;
    } 
  else 
    {
      j += 4;  /* core0 break here */
      x = 20;
    }
  i += j + x; 
}

int
main (void)
{
  CVMX_SHARED static cvmx_spinlock_t core_lock = 
			CVMX_SPINLOCK_UNLOCKED_INITIALIZER;

  /* Used to control the sequence of the program. There are changes of 
     hitting the hardware breakpoint by both the cores at the same time.  */
  cvmx_spinlock_lock (&core_lock);
  foo ();
  cvmx_spinlock_unlock (&core_lock);

  while (1); /* set common breakpoint here */
}

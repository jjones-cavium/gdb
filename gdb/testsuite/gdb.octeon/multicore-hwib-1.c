/* Debugger test case to test multicore instruction hardware breakpoints. */

#include <stdio.h>
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

static int count = 0;

static void
foo (void)
{
  int core_num;
 
  core_num = cvmx_get_core_num ();
 
  if (core_num == 1)
    count = count + 4; /* set core1 hbreak here */
  else 
    count++; /* set core0 hbreak here */
}

int
main (void)
{
  CVMX_SHARED static cvmx_spinlock_t core_lock = 
			CVMX_SPINLOCK_UNLOCKED_INITIALIZER;

  if (cvmx_get_core_num () == 1)
  {
    volatile int a;
    for(a=0;a<100;a++)
      ;
  }
  /* Used to control the sequence of the program. There are changes of 
     hitting the hardware breakpoint by both the cores at the same time.  */
  cvmx_spinlock_lock (&core_lock);
  foo ();
  cvmx_spinlock_unlock (&core_lock);
  if (cvmx_get_core_num () == 0)
  {
    volatile int a;
    for(a=0;a<1000;a++)
      ;
  }
  cvmx_spinlock_lock (&core_lock);
  cvmx_spinlock_unlock (&core_lock);

  printf ("The value of count is %d\n", count);

  while (1); /* set common breakpoint here */
}

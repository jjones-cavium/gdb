/* Debugger test case to test hardware watchpoints in single core. */

#include <cvmx.h>
#include <cvmx-spinlock.h>
#include <cvmx-sysinfo.h>

/* This test requires 2 cores but CN30XX has only one core, generate
   an error. */
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

volatile long g1 = 0;
volatile long g0 = 0;

foo (void)
{
  int core_num;

  core_num = cvmx_get_core_num ();

  if (core_num)
    g1 += 3; 
  else
    g0 += 9;
}

int
main (void)
{
  CVMX_SHARED static cvmx_spinlock_t core_lock = 
			CVMX_SPINLOCK_UNLOCKED_INITIALIZER;
  int j;
  cvmx_sysinfo_t *sysinfo;

  sysinfo = cvmx_sysinfo_get();

  for (j = 0; j < 4; j++)
    {
      /* Used to sync up the cores, otherwise the same core hits the hardware
	 watchpoint again and again on continue commands.  */
      cvmx_coremask_barrier_sync (sysinfo->core_mask);
      /* Used to control the sequence of the program. There are chances of 
         hitting the hardware breakpoint by both the cores at the same time. */
      cvmx_spinlock_lock (&core_lock);
      foo ();
      cvmx_spinlock_unlock (&core_lock);
    }

  while (1); /* set common breakpoint here */
}

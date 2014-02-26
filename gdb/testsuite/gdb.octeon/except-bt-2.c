#include <cvmx.h>
#include <stdlib.h>
#include <stdio.h>
#include <execinfo.h>

int *i = 0;

extern char fault_addr[];

static void octeon_debug_handler(uint64_t registers[32])
{

  printf ("In user defined exception handler\n");
  /* Print some useful registers. */
  printf ("RA = %llx, SP = %llx\n", (unsigned long long)registers[31], (unsigned long long) registers[30]);
}

int main (void)
{
  volatile int x = 100;
  cvmx_user_app_init ();

  cvmx_interrupt_set_exception (octeon_debug_handler);
  printf ("fault_addr: %p\n", fault_addr);
  asm volatile ("fault_addr: lw $2, %0" :: "m"(*i));

  return 0;
}

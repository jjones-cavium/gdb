/* Debugger test case to test hardware instruction breakpoints on single 
   core. */
#include <stdio.h>

static int count = 0;

static void
foo (void)
{
  int i, j;

  for (j = 0; j < 2; j++)
    {
      for (i = 0; i < 2; i++) 
        count += 1; /* set hbreak1 here */
      count += 2; /* set hbreak2 here */
    }
}

int
main (void)
{
  foo ();

  printf ("The value of count is %d\n", count);  /* set hbreak3 here */

  while(1); /* set common breakpoint here */
}

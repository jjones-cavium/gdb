/* Debugger test case to test hardware watchpoints in single core. */

volatile int g1 = 0, g4 = 0;
static int g2, g3; 	/* Dummy variable to check watchpoint limits.  */

static void
foo (void)
{
  volatile long l1 = 0;
  int j; 	/* Dummy variable to check watchpoint limits.  */

  for (j = 0; j < 3; j++)
    {
      l1 += 2;  /* set break here 1  */
      g1 += 3;
      g4 += 4;
    }
    g4 += g2;
}

int
main (void)
{
  foo ();

  return 0; /* set break here 2 */
}

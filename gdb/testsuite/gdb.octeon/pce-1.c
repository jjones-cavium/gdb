/* Debugger test case to test performance counter events on single core. */
static void
foo (void)
{
  volatile long i, j;
  long x;

  for (j = 0; j < 4; j++)
    {
      x++;
      i += j + x; /* set break1 here */
    }
}

int
main (void)
{
  foo ();
}

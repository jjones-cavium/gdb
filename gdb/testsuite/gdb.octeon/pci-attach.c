#include <stdio.h>

int
main ()
{
  unsigned long long a = 0, b = 0, i = 0;
  while (1)
    {
      do
	{
	  asm ("rdhwr %0, $31" : "=r"(b));
	}
      while (b - a < 500 * 1024 * 1024);
      a = b;

      printf ("iteration: %d\n", i++);
    }
  return 0;
}

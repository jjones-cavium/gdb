#include <cvmx.h>

int global_data = 5;	/* In Data section */
const int global_ro = 201;	/* In Read-Only Data section */
volatile long global_arr[4] = { 200, 400, 600, 800 };
volatile char *invalid = 0; 

__attribute__ ((noinline,noclone)) void 
func2 (int x2)
{
  volatile int local[5];
  int i;
  volatile int y = 20;

  asm ("");
  for (i = 0; i < 5; i++)
    local[i] = x2 + i;
  *invalid = x2;
  y += 10 * x2 + global_data + local[3] + global_ro;
}

__attribute__ ((noinline,noclone)) void 
func1 (int x1)
{
  int y = 100 + x1;
  asm ("");
  func2 (y);
  global_arr[3] += x1;
  printf ("in func1\n");
}

int main ()
{
  volatile int y = 10;
  cvmx_user_app_init ();
  global_arr[1] = 410;
  func1 (y);
  return 0;
}

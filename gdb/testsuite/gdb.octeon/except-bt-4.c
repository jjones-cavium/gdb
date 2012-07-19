#include <cvmx.h>

volatile char g = '6';
long g_arr[2] = { 11, 22 };
int *i = 0;

__attribute__ ((noinline,noclone)) static int 
convert_to_int (char x)
{
  volatile int y = 1;

  asm ("");
  while (x >= '0' && x <= '9')
    *i = *i * 10 + (x++ - '0') + y++;

  printf ("atoi of %c is %d\n", x, *i);
  return y;
}

__attribute__ ((noinline,noclone)) int
factorial (char val)
{
  volatile char c = val + '3';
  int a = convert_to_int (c);
  asm ("");
  if (a > 1)
     a *= factorial (a) + (val + '0');
  return a;
}

int main ()
{
  volatile int y = 100;
  cvmx_user_app_init ();
  y = factorial (g);
  printf ("factorial of %c is %d\n", g, y);
  return 0;
}

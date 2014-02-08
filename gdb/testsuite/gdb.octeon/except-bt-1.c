#include <cvmx.h>
#include <unistd.h>

int *i = 0;

void foo (void)
{
  *i = 0;
}

void (*p) (void) = foo;

int main (void)
{
  cvmx_user_app_init ();
  p ();
  return 0;
}

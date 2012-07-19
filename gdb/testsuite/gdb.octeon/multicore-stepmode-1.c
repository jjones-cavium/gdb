#include <stdio.h>

static int count = 0;

int main(void)
{
  while (1) {
    int core;
    asm ("rdhwr %0,$0" : "=r"(core));
    printf("Hello from %d\n", core);
  }
  return 0;
}

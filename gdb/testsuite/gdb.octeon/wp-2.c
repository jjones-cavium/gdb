/* Testcase to test if watchpoint stops when accessing parts of the memory 
   location of the variable the watchpoint is applied to.  
   Also check accessing the memory location outside the boundary should not 
   make the debugger stop.  */

struct {
  int x;
  int y;
  int z;
} wp;
  
char *ch;

void foo (void)
{
  /* Test accessing outside the boundary.  */
  wp.x = 10;  /* not stop here1 */ 
  wp.z = 30;  /* not stop here2 */
  wp.y = 20;

  /* Test accessing parts of the memory location.  */
  ch = (char *) &wp.y;
  *(ch + 3) += 'B';
  *(ch) += 'A' + wp.z;
}

main()
{
  foo();
  return wp.z; /* break here */
}

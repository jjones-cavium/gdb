/* Test debug-mode exception.  */
int a;

int foo (char *t)
{
  if (a == 10)
    return 1; 
  else
    return -1;   /* arrive here after next. */
}

main()
{
  char *c = "-1";

  return foo (c);
}


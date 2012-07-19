/* For Control-C to work, the corresponding interrupts needs to be registered.
   This is done in cvmx-app-init.c. The Control-C works properly in the 
   Simple Exec Application.  */

#include <stdio.h>

main()
{
   int i = 0;

   do {
     printf ("Hello World %d\n", i++);
   } while (1);
}

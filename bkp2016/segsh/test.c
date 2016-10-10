#include <sys/mman.h>
#include <stdio.h>

int main(void)
{
  printf ("%d %d %d %d\n", PROT_READ, PROT_WRITE, PROT_EXEC, PROT_NONE);
  
  return 0;
}

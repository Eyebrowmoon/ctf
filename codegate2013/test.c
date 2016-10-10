#include <string.h>
#include <stdlib.h>

char nullstr[10];

int main() {
  nullstr[0] = (char)0;

  strcpy((char *)0xdeadbeef, nullstr);  

  return 0;
}

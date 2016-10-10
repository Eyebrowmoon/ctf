#include <unistd.h>
#include <stdio.h>

#define BUFF_SIZE 512

char gbuf[BUFF_SIZE];

int main(int argc, char *argv[]) {
  long long rdi = 0, rsi = 0, rdx = 0, rip = 0;

  read(0, gbuf, BUFF_SIZE);

  read(0, &rdi, 8);
  read(0, &rsi, 8);
  read(0, &rdx, 8);
  read(0, &rip, 8);

  __asm__(
  "mov -0x20(%rbp), %rdi\n\t"
  "mov -0x18(%rbp), %rsi\n\t"
  "mov -0x10(%rbp), %rdx\n\t"
  "mov -0x8(%rbp), %rax\n\t"
  "call *%rax"
  );

  return 0;
}

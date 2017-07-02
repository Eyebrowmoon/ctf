#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  struct user_regs_struct regs;
  int ret, pid, i, fd;
  unsigned int data;
  char *addr = (char *) atoi(argv[2]);

  pid = atoi(argv[1]);
  ret = ptrace(PTRACE_ATTACH, pid, 0, 0);

  ptrace(PTRACE_GETREGS, pid, 0, &regs);

  printf("ebx = %p\n", (char *) regs.ebx);
  printf("ecx = %p\n", (char *) regs.ecx);
  printf("edx = %p\n", (char *) regs.edx);
  printf("esi = %p\n", (char *) regs.esi);
  printf("edi = %p\n", (char *) regs.edi);
  printf("esp = %p\n", (char *) regs.esp);
  printf("ebp = %p\n", (char *) regs.ebp);
  printf("eax = %p\n", (char *) regs.eax);

  fd = open("dump", O_RDWR | O_CREAT, 0644);

  for (i = 0; i < 0x800; i++) {
    data = ptrace(PTRACE_PEEKDATA, pid, addr + 4*i, 0);
    write(fd, &data, 4);  
  }

  close(fd);

  ret = ptrace(PTRACE_DETACH, pid, 0, 0);

  return 0;
}

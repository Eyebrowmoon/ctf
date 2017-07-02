#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

char buf[0x2000];

int main(int argc, char *argv[]) {
  int fd;
  char *addr = mmap(0, 0x2000, 7, 34, -1, 0);
  int (*funcptr) (char *, int, int, int);
  int len = atoi(argv[2]);
  int retval;
  char buffff[0x8000] = {'a'};

  funcptr = addr;

  fd = open("buf", O_RDONLY | O_CREAT, 0644);
  read(fd, buf, 0x2000);
  close(fd);

  fd = open("buffer", O_RDONLY | O_CREAT, 0644);
  read(fd, addr, 0x2000);
  close(fd);

  fd = open(argv[1], O_RDONLY);
  read(fd, addr, len);
  close(fd);

  retval = funcptr(buf, 0, len, len);

  fd = open("result", O_RDWR | O_CREAT | O_TRUNC, 0644);
  write(fd, &retval, 4);
  write(fd, buf, retval);
  close(fd);

  fd = open("buffer", O_RDWR);
  write(fd, addr, 0x2000);
  close(fd);

  fd = open("buf", O_RDONLY | O_CREAT, 0644);
  read(fd, buf, 0x2000);
  close(fd);

  return 0;
}

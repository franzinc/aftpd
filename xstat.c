#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define SOFF(field) (((char *)&s.field) - ((char *)&s))

#define PSOFF(field) printf("%02d  " #field "\n", SOFF(field))

int main() {
  struct stat s;

  PSOFF(st_dev);
  PSOFF(st_ino);
  PSOFF(st_mode);
  PSOFF(st_nlink);
  PSOFF(st_uid);
  PSOFF(st_gid);
  PSOFF(st_rdev);
  PSOFF(st_size);
  PSOFF(st_blksize);
  PSOFF(st_blocks);
  PSOFF(st_atime);
  PSOFF(st_mtime);
  PSOFF(st_ctime);

  printf("struct size is %d bytes\n", sizeof(s));
    
  return 0;
}

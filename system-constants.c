#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define show(constant) printf("(defconstant " #constant " #x%08x)\n", constant)

int main() {
    show(TIOCNOTTY);
    show(O_RDWR);

    return 0;
}

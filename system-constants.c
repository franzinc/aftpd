#include <unistd.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/termios.h> /* Solaris */
#include <sys/wait.h>


#define show(constant) printf("(defconstant " #constant " #x%08x)\n", constant)
#define SIZEOF(thing) printf("Sizeof " #thing " is %d\n", sizeof(thing))

int main() {
    show(TIOCNOTTY);
    show(O_RDWR);
    show(WNOHANG);

    SIZEOF(uid_t);
    SIZEOF(gid_t);
    SIZEOF(char *);
    SIZEOF(long);

    return 0;
}

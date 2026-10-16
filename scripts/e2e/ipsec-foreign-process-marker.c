#define _GNU_SOURCE
#include <sys/prctl.h>
#include <unistd.h>

// Compiled on the GitHub Actions runner, executed ONLY in a disposable
// PID1-systemd guest. Mimics an additional foreign strongSwan process
// identity without binding sockets, opening files, or modifying host state.
int main(void) {
    if (prctl(PR_SET_NAME, "charon", 0, 0, 0) != 0) return 2;
    for (;;) pause();
}

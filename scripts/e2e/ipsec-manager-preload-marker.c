/*
 * DISPOSABLE GUEST NEGATIVE FIXTURE ONLY. This shared library is loaded
 * through a deliberately hostile manager-wide LD_PRELOAD setting in a
 * disconnected PID1-systemd Docker guest. Never preload it on a real host.
 */
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) static void stl_mark_foreign_charon_exec(void) {
    char exe[256];
    ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n < 0)
        return;
    exe[n] = '\0';
    const char *name = strrchr(exe, '/');
    name = name ? name + 1 : exe;
    if (strcmp(name, "charon-systemd") != 0)
        return;
    int fd = open("/run/stl-manager-env-charon-executed",
                  O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0)
        close(fd);
}

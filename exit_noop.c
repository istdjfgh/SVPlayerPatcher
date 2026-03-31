#include <unistd.h>

// Override exit functions to prevent anti-tamper kill
void exit(int status) {
    // Infinite pause instead of exit - keeps process alive
    while(1) { 
        usleep(1000000); // sleep 1s
    }
}

void _exit(int status) {
    while(1) { usleep(1000000); }
}

void _Exit(int status) {
    while(1) { usleep(1000000); }
}

void abort(void) {
    while(1) { usleep(1000000); }
}

int tgkill(int tgid, int tid, int sig) {
    return 0;  // Pretend success but don't actually kill
}

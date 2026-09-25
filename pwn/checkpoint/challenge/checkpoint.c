/* Checkpoint - a border access terminal.
 * There's a grant_access() routine that reads the flag, but nothing calls it. The name prompt
 * reads more than it should. build: gcc checkpoint.c -o checkpoint -fno-stack-protector -no-pie -O0
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void grant_access(void) {
    char buf[80];
    FILE *f = fopen("/flag", "r");
    if (!f) { puts("[!] flag file missing - tell an admin"); return; }
    fgets(buf, sizeof buf, f);
    fclose(f);
    printf("ACCESS GRANTED: %s\n", buf);
    fflush(stdout);
}

void checkpoint(void) {
    char name[64];
    puts("=== Sparrow Freight border checkpoint ===");
    puts("State your name for the log:");
    read(0, name, 256);                     /* buffer is 64 bytes - overflow */
    printf("Access denied, %s. Turn back.\n", name);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    checkpoint();
    return 0;
}

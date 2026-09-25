/* Manifest - freight manifest terminal.
 * Viewing the manifest needs admin clearance (is_admin). The feedback form prints your message
 * back with printf(buf) - a format-string bug. build: gcc manifest.c -o manifest -no-pie -O0
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int is_admin = 0;

void view_manifest(void) {
    if (!is_admin) {
        puts("[!] admin clearance required.");
        return;
    }
    char buf[128];
    FILE *f = fopen("/flag", "r");
    if (!f) { puts("[!] flag file missing"); return; }
    fgets(buf, sizeof buf, f);
    fclose(f);
    printf("[manifest] clearance code: %s\n", buf);
}

void feedback(void) {
    char buf[200];
    memset(buf, 0, sizeof buf);
    puts("Leave feedback for the terminal operators:");
    read(0, buf, sizeof buf - 1);
    printf("You said: ");
    printf(buf);                 /* format-string vulnerability */
    puts("");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    char line[16];
    while (1) {
        puts("\n1) leave feedback\n2) view manifest\n3) exit");
        if (!fgets(line, sizeof line, stdin)) break;
        int c = atoi(line);
        if (c == 1) feedback();
        else if (c == 2) view_manifest();
        else break;
    }
    return 0;
}

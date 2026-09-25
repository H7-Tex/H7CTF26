/* Ledger - freight note manager. Classic use-after-free: delete() frees but keeps the pointer, and
 * view()/edit() still work on freed notes. There's an audit() routine that prints /flag, never called.
 * build: gcc ledger.c -o ledger -no-pie -z lazy -O0   (no PIE, partial RELRO -> GOT writable)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAXN 16
#define SZ 0x50
static char *notes[MAXN];

void audit(void) {
    char buf[80];
    FILE *f = fopen("/flag", "r");
    if (!f) { puts("[!] flag missing"); return; }
    fgets(buf, sizeof buf, f); fclose(f);
    printf("[audit] %s\n", buf);
}

static int menu(void) {
    char line[16];
    puts("\n1) add  2) delete  3) edit  4) view  5) exit");
    printf("> ");
    if (!fgets(line, sizeof line, stdin)) exit(0);
    return atoi(line);                     /* atoi@got is our overwrite target */
}

static int idx(void) {
    char line[16];
    printf("index: ");
    if (!fgets(line, sizeof line, stdin)) exit(0);
    int i = atoi(line);
    return (i < 0 || i >= MAXN) ? -1 : i;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    while (1) {
        switch (menu()) {
        case 1: { int i = idx(); if (i < 0) break; notes[i] = malloc(SZ);
                  printf("note: "); read(0, notes[i], SZ); break; }
        case 2: { int i = idx(); if (i < 0) break; free(notes[i]); break; }   /* UAF: no null */
        case 3: { int i = idx(); if (i < 0 || !notes[i]) break; printf("note: ");
                  read(0, notes[i], SZ); break; }                             /* edit after free */
        case 4: { int i = idx(); if (i < 0 || !notes[i]) break;
                  write(1, notes[i], SZ); break; }                            /* view (leak) */
        case 5: return 0;
        default: puts("?");
        }
    }
}

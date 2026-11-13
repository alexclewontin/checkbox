#!/usr/bin/env python3
"""
Examine the kernel log of the current boot for module loads that
kernel lockdown or module signature enforcement rejected.

This script examines only the current boot (-b 0). The
contrib/pc-sanity/bin/check-error-string.sh script examines all boots.
The installed kernel and initramfs cause a module load rejection, and
the rejection occurs again at each boot. If the script examines old
boots, it can show rejections from an initramfs that you replaced.

Each rejection causes the test to fail. The report shows two groups of
rejected modules:

- Modules that are in /proc/modules now. Usually, this is not a
  problem. The initramfs contained an unsigned copy, and a correctly
  signed copy loaded later from the root filesystem.
- Modules that are not in /proc/modules. Possibly, the system does
  not have the driver.
"""

import re
import subprocess

# These four kernel messages show that the kernel rejected a module
# load. The journalctl -g filter and find_rejections() use the same
# strings. This prevents differences between the two.
#
# This list does not include 'module verification failed: signature
# and/or required key missing'. With that message, the kernel loads
# the module and only taints the kernel. The
# miscellanea/kernel_taint_test job examines that condition.
_REJECTION_REGEXES = (
    r"Lockdown: \S+: unsigned module loading is restricted",
    r"Loading of unsigned module is rejected",
    r"Loading of module with unavailable key is rejected",
    r"Loading of module with unsupported crypto is rejected",
)

# journalctl -g receives these PCRE alternations, and journald filters
# the log. On a system that operates for a long time, the kernel log
# can have millions of lines.
_KERNEL_LOG_GREP = "|".join(_REJECTION_REGEXES)
_INSERT_LOG_GREP = r"could not insert '|Failed to insert module '"

REJECTION_PATTERNS = tuple(re.compile(regex) for regex in _REJECTION_REGEXES)

_INSERT_PATTERNS = (
    re.compile(r"could not insert '(?P<module>[^']+)'"),
    re.compile(r"Failed to insert module '(?P<module>[^']+)'"),
)


def get_lockdown_state():
    """Return the active lockdown mode.

    If the file is not available, return 'unavailable'. If the file
    has no mode in brackets, return 'unknown'.
    """
    try:
        with open("/sys/kernel/security/lockdown") as fh:
            content = fh.read()
    except OSError:
        return "unavailable"
    match = re.search(r"\[(\S+)\]", content)
    if match:
        return match.group(1)
    return "unknown"


def get_sig_enforce_state():
    """Return the sig_enforce value ('Y' or 'N').

    If the file is not available, return 'unavailable'.
    """
    try:
        with open("/sys/module/module/parameters/sig_enforce") as fh:
            return fh.read().strip()
    except OSError:
        return "unavailable"


def _grep_journal(args, pattern):
    """Run journalctl with -g *pattern* and return its stdout.

    journalctl exits with 0 if a line matches the pattern. journalctl
    exits with 1 if no line matches the pattern. journalctl also exits
    with 1 if it rejects the command, for example an unrecognized
    option. This occurs if journalctl has no PCRE support for -g.
    Stderr is empty only if no line matches the pattern. If the return
    code is 1 and stderr has text, raise SystemExit. Do not return an
    empty result, because that result shows a boot without rejections.
    """
    result = subprocess.run(
        ["journalctl"] + args + ["--no-pager", "-g", pattern],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )
    if result.returncode == 0:
        return result.stdout
    if result.returncode == 1 and not result.stderr.strip():
        return ""
    raise SystemExit(
        "Could not search the journal ({}): {}".format(
            result.returncode, result.stderr.strip()
        )
    )


def get_kernel_log():
    """Return the kernel log lines that match a rejection pattern.

    If journalctl cannot search the kernel log, raise SystemExit. If
    the journal is not readable, the test must fail. The test must not
    pass.
    """
    return _grep_journal(["-k", "-b", "0"], _KERNEL_LOG_GREP)


def find_rejections(log):
    """Return the lines in *log* that match a REJECTION_PATTERNS item."""
    results = []
    for line in log.splitlines():
        for pattern in REJECTION_PATTERNS:
            if pattern.search(line):
                results.append(line)
                break
    return results


def get_module_insert_log():
    """Return the userspace journal lines about failed module inserts.

    The kernel messages do not identify the rejected modules. These
    lines give only the module names. If journalctl cannot search the
    journal, return an empty string. The test continues, because the
    module names are only additional data.
    """
    try:
        return _grep_journal(["-b", "0"], _INSERT_LOG_GREP)
    except SystemExit:
        return ""


def find_failed_module_inserts(log):
    """Return a sorted list of module names from failed insert messages.

    Each name occurs one time only.
    """
    modules = set()
    for line in log.splitlines():
        for pattern in _INSERT_PATTERNS:
            m = pattern.search(line)
            if m:
                modules.add(m.group("module"))
                break
    return sorted(modules)


def get_loaded_modules():
    """Return the names of the modules that are loaded now.

    This function changes all hyphens in the names to underscores.
    /proc/modules always uses underscores. The userspace error messages
    use the name that the caller gave, for example 'snd-hda-intel'.
    """
    try:
        with open("/proc/modules") as fh:
            content = fh.read()
    except OSError:
        return set()
    return {
        line.split()[0].replace("-", "_")
        for line in content.splitlines()
        if line.strip()
    }


def main():
    print("Kernel lockdown mode: {}".format(get_lockdown_state()))
    print(
        "Module signature enforcement (module.sig_enforce): {}".format(
            get_sig_enforce_state()
        )
    )

    rejections = find_rejections(get_kernel_log())
    if not rejections:
        print(
            "No lockdown or module-signature rejections found"
            " in the current boot's kernel log."
        )
        return

    failed_modules = find_failed_module_inserts(get_module_insert_log())
    loaded = get_loaded_modules()
    missing = [
        mod for mod in failed_modules if mod.replace("-", "_") not in loaded
    ]
    recovered = [
        mod for mod in failed_modules if mod.replace("-", "_") in loaded
    ]

    report = ["Kernel lines indicating module load rejections:"]
    for line in rejections:
        report.append("  {}".format(line))
    if missing:
        report.append(
            "Rejected and not in /proc/modules now, so no later load"
            " recovered them: {}".format(", ".join(missing))
        )
    if recovered:
        report.append(
            "Rejected but in /proc/modules now, so a properly signed"
            " copy loaded later, typically from the root filesystem"
            " rather than the initramfs: {}".format(", ".join(recovered))
        )
    if not failed_modules:
        report.append(
            "No userspace module insert failures were logged, so the"
            " rejected modules cannot be named from this boot's"
            " journal; the kernel messages never name them."
        )
    report.append(
        "Rejections are reported whatever their impact: they can break"
        " functionality outright, and they cost test coverage twice"
        " over, because the driver-provided attributes the device"
        " resource exports go missing. Template jobs filtered on those"
        " attributes are never instantiated and so are absent from the"
        " run entirely, while ordinary jobs that require them are"
        " reported as skipped (unmet resource). A module absent from"
        " /proc/modules is not proof of breakage on its own, because"
        " the same functionality may be built into the kernel or"
        " simply unused on this system."
    )
    raise SystemExit("\n".join(report))


if __name__ == "__main__":
    main()

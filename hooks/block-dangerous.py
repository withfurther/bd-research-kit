#!/usr/bin/env python3
"""Command-position parser for block-dangerous.sh (OPS-523).

Reads a shell command on stdin and prints exactly one verdict:

    BLOCK     a dangerous command was found in COMMAND position (or nesting exceeded the budget)
    ALLOW     parsed cleanly; nothing dangerous in command position
    FALLBACK  could not parse (unbalanced quotes, shlex error); the hook's legacy strip-and-match
              matcher decides, preserving the old over-blocking behavior

Kept as a sibling module rather than a heredoc inside the hook: this source is ~67KB, which exceeds
the pipe buffer, so bash spools a heredoc that large through a TEMP FILE. On a host with a
read-only /tmp the assignment silently produced an EMPTY parser and the hook degraded to the legacy
matcher — re-blocking the data cases OPS-523 exists to allow, and failing OPEN on the parser-only
protections (`bash <<EOF … rm -rf / … EOF`). Codex #26 r22 F1.

The hook resolves this file next to itself and DENIES if it is missing or unreadable, so a partial
install fails closed and loudly rather than silently losing the parser.
"""
import re, shlex, sys

MAX_DEPTH = 8

# Redirection onto a RAW BLOCK DEVICE destroys the disk. The original pattern only knew `/dev/sd*`,
# so `> /dev/nvme0n1` (the common name on modern Linux), `/dev/vda` (virtio/cloud VMs), `/dev/xvda`
# (Xen/EC2), `/dev/mmcblk0` (SD/eMMC), and macOS `/dev/disk0` all failed open (Codex #26 r21 F1).
# Character devices that are NOT disks — `/dev/null`, `/dev/stdout`, `/dev/tty`, `/dev/fd/N` — must
# stay allowed, so this enumerates disk families rather than matching `/dev/` wholesale. `md[0-9]`
# and `r?disk[0-9]` carry a digit so `/dev/mdX`-style non-disks and `/dev/diskette` are not caught.
# The raw BLOCK-DEVICE families. Character devices that are not disks — `/dev/null`, `/dev/zero`,
# `/dev/stdout`, `/dev/tty`, `/dev/fd/N` — are deliberately absent: writing them is routine, and a
# `dd … of=/dev/null` benchmark must not be denied (Codex #26 r24 F4). Shared by the redirection
# rule and by `dd`'s `of=` target, so the two can never drift apart.
# `mapper/` (LVM/crypt), `disk/by-*` (udev symlinks) and `md/` name the very same disks by another
# path (Codex #26 r25 F3). `>|` is the noclobber-override redirection — still a write.
DEVICE_FAMILY = (r"(sd|nvme|vd|hd|xvd|mmcblk|loop|dm-|md[0-9]|md/|mapper/|disk/"
                 r"|r?disk[0-9])")
RAW_DEVICE_PAT = r">\|?\s*/dev/" + DEVICE_FAMILY

# `git` accepts GLOBAL options before its subcommand: `git -C /tmp push --force main`,
# `git --no-pager push …`, `git -c core.pager=less push …` all force-push, but every pattern
# required `push` immediately after `git` (self-audit, r24 sweep). Only OPTION-shaped words (and the
# one operand an option may take) may sit in between, so `git log --grep=push --force main` — where
# the first word after `git` is a subcommand, not an option — is not matched.
GIT_GLOBAL_OPTS = r"(-[^\s;&|]*(\s+[^\s;&|]+)?\s+)*"

# The path after a home/cwd base: a run of `/.`/`/..` dot-segments (or a bare `/` — a trailing slash)
# then an optional `/`-glob. Each real subdir name stops the run, so `~/build/*` is not a wipe while
# `~/./*` and `~/../*` are (Codex #26 r42 F1). The glob content excludes shell separators so a match
# never crosses a statement boundary.
_HOME_GLOB_SUFFIX = r"(/(\.\.?|[*?][^\s;&|]*)?)*"

# Anchored at COMMAND POSITION: matched against a statement reconstructed from its tokens
# (shlex has already removed quoting), beginning at the resolved command word.
CMD_PATTERNS = [
    r"rm\s+-rf\s+/([^a-zA-Z]|$)",
    # Home ITSELF (`~`, `~/`, `~/.`) or a glob wipe of it (`~/*`) — not an ordinary path beneath it.
    # Without the boundary these prefixes denied `rm -rf ~/tmp/scratch` (self-audit, r27 sweep). A run
    # of `/.`/`/..` dot-segments before the glob normalizes back to the same wipe (`~/./*`, `~/../*` —
    # Codex #26 r42 F1); `_HOME_GLOB_SUFFIX` matches that run then the optional glob, so `~/build/*`
    # (a real subdir) still stops the run and stays allowed.
    r"rm\s+-rf\s+~([+-]|[A-Za-z_][A-Za-z0-9_.-]*)?" + _HOME_GLOB_SUFFIX + r"(\s|;|&|\||$)",
    r"rm\s+-rf\s+\$\{?(HOME|PWD|OLDPWD)\}?" + _HOME_GLOB_SUFFIX + r"(\s|;|&|\||$)",
    r"rm\s+-rf\s+\." + _HOME_GLOB_SUFFIX + r"(\s|;|&|\||$)",
    # Destructive-device/permission commands in ANY argument order (Codex #26 r18 F1): bare `mkfs`
    # is the same formatter as `mkfs.ext4`; `dd` destroys the device whenever `of=/dev/…` appears,
    # regardless of where (or whether) `if=` sits; `chmod 777 -R /` == `chmod -R 777 /` (mode and
    # flag order are interchangeable, `-R` may be clustered, `0777` == `777`; `1777` is NOT 777).
    # The root target need not sit immediately after the mode: chmod accepts intervening options
    # and a `--` end-of-options terminator (`chmod -R --no-preserve-root 777 -- /` — Codex #26 r19
    # F2), and any later operand can be the root. Token walks exclude `;`/`&`/`|` so a match never
    # crosses a statement boundary (`chmod -R 777 ./x && cd /tmp` stays allowed).
    # `mkfs` formats the DEVICE it is given: the `mkfs.<fs>` spelling is destructive by name (its
    # pre-existing rule), while bare `mkfs` needs a `/dev/` operand — otherwise `mkfs --help` and
    # `mkfs -V` were denied (Codex #26 r24 F4). `dd` destroys only when its OUTPUT is a raw disk;
    # `of=/dev/null` and `of=/dev/stdout` are ordinary.
    r"mkfs\.",
    r"mkfs\s+[^;&|]*/dev/",
    r"dd\s+[^;&|]*of=/dev/" + DEVICE_FAMILY,
    r"chmod\s+([^\s;&|]+\s+)*(-[A-Za-z]*R[A-Za-z]*|--recursive)\s+([^\s;&|]+\s+)*0?777\s+([^\s;&|]+\s+)*/",
    r"chmod\s+([^\s;&|]+\s+)*0?777\s+([^\s;&|]+\s+)*(-[A-Za-z]*R[A-Za-z]*|--recursive)\s+([^\s;&|]+\s+)*/",
    # A force flag in ANY argument position blocks a push naming a protected ref. Long `--force`
    # (and `--force-with-lease`, which still rewrites the remote ref) anywhere before the ref;
    # short `-f` anywhere before the ref — `git push -f origin main` AND the between-remote-and-
    # refspec position `git push origin -f HEAD:main`, which the old pattern missed by anchoring
    # `-f` to `push` (Codex #26 r16 F1) — including a short-option cluster (`-fu`: git bundles
    # short options and its only push short containing `f` IS --force); and a force flag AFTER
    # the branch/refspec (`git push origin main --force` / `-f` — Codex #26 r11 F1).
    # The protected ref is a BOUNDED token — bare `main`, a refspec dst (`HEAD:main`), or a
    # qualified `refs/heads/main` — never a substring: `main-backup`, `domain`, `maintenance`,
    # `my-main`, and a `main:dev` refspec (dst is dev) are different refs and must not match
    # (Codex #26 r18 F2). Token walks use [^\s;&|]* so a match never crosses a statement
    # separator, and the trailing boundary accepts one so `…main; echo` still matches.
    r"git\s+" + GIT_GLOBAL_OPTS + r"push(\s[^\s;&|]*)*\s--force(-with-lease(=\S*)?)?(\s[^\s;&|]*)*\s([^\s;&|]*[:/])?(main|master)([\s;&|]|$)",
    r"git\s+" + GIT_GLOBAL_OPTS + r"push(\s[^\s;&|]*)*\s-[A-Za-z0-9]*f[A-Za-z0-9]*(\s[^\s;&|]*)*\s([^\s;&|]*[:/])?(main|master)([\s;&|]|$)",
    r"git\s+" + GIT_GLOBAL_OPTS + r"push(\s[^\s;&|]*)*\s([^\s;&|]*[:/])?(main|master)(\s[^\s;&|]*)*\s(--force(-with-lease(=\S*)?)?|-[A-Za-z0-9]*f[A-Za-z0-9]*)([\s;&|]|$)",
    # A leading `+` on a refspec is a forced update. `+main` is the short form; the full form names
    # the destination explicitly — `+HEAD:main`, `+HEAD:refs/heads/main`, `+feature:refs/heads/master`
    # — all force-update a protected branch and previously slipped the bare-`+main` pattern (Codex
    # #26 r15b F2). Only the DESTINATION (after the last `:`) is protected: `+main:dev` and
    # `+refs/heads/main:refs/heads/dev` push main's commits TO dev and must be allowed, so `:` is
    # not a terminator for the matched ref (Codex #26 r20 F2). `+main-backup` stays out via the
    # same boundary rule as the force patterns, and the token walk cannot cross a statement.
    r"git\s+" + GIT_GLOBAL_OPTS + r"push(\s[^\s;&|]*)*\s\+([^\s;&|]*:)?(refs/heads/)?(main|master)([\s;&|]|$)",
    r"git\s+" + GIT_GLOBAL_OPTS + r"reset\s+--hard\s+origin/(main|master)",
]
CMD_RE = re.compile("^(" + "|".join(CMD_PATTERNS) + ")", re.IGNORECASE)

# `rm -rf /` is the same removal as `rm -r -f /`, `rm -fr /`, `rm --recursive --force /`, and
# `rm -rf -- /` — but the `rm\s+-rf\s+TARGET` patterns above only see the clustered `-rf` with the
# target immediately after, so every split/reordered/long/`--`-separated form slipped through
# (Codex #26 r15b F1). The parser has real tokens, so recursion+force is decided by inspecting the
# flags and the `--`-terminated target token set rather than by a fragile permutation regex.
# The HOME forms are the home directory itself (`~`, `~/`, `~/.`, `~/..`) or a glob wipe of it
# (`~/*`) — NOT an ordinary path beneath it. `~.*` matched every one of them, so the everyday
# `rm -rf ~/tmp/scratch` was denied while the equivalent `rm -rf $HOME/tmp/scratch` was allowed
# (self-audit, r27 sweep). `$HOME` gets the same shape, which also closes `rm -rf $HOME/` — a home
# wipe the old exact-token match let through.
# A tilde PREFIX names a directory too: `~+` is the cwd, `~-` the previous one, and `~user` that
# user's home (`~root` → /var/root). `rm -rf ~+` is the same wipe as `rm -rf .`, and `rm -rf ~root`
# the same as `rm -rf ~` for another account — both were allowed (Codex #26 r32 F1). As with `~`,
# only the directory ITSELF or a glob wipe of it counts; `~+/build` is an ordinary path.
# `$PWD`/`$OLDPWD` are the current / previous directory — removing them recursively is the same
# wipe as `.` or `~` (Codex #26 r34 F1). Grouped with the HOME/tilde forms since the rule (the
# directory itself or a glob wipe of it) is identical.
# A dir followed by any run of `/.`/`/..` dot-segments normalizes back to that dir (or an ancestor),
# so `~/./*`, `$HOME/./*`, `$PWD/../*`, `~/../../*` are the SAME home/cwd glob wipe as `~/*` — the
# single-segment suffix matched only `~/*` and let the dot-segment forms through (Codex #26 r42 F1).
# `~/build/*` still names a real subdir (the run stops at a non-dot segment), so it stays allowed.
_TARGET_SUFFIX = r"(?:/\.\.?)*(?:/(?:[*?].*)?)?"
HOME_TARGET = (r"(?:~(?:[+-]|[A-Za-z_][A-Za-z0-9_.-]*)?|\$\{?(?:HOME|PWD|OLDPWD)\}?)"
               + _TARGET_SUFFIX)
RM_TARGET_RE = re.compile(
    r"^(?:/([^A-Za-z].*)?|" + HOME_TARGET + r"|\." + _TARGET_SUFFIX + r")$")

# The base of a path whose `..` segments could pop it back to root / home / cwd.
_WIPE_BASE_RE = re.compile(r"~(?:[+-]|[A-Za-z_][A-Za-z0-9_.-]*)?|\$\{?(?:HOME|PWD|OLDPWD)\}?|\.|/")


def normalizes_to_wipe(target):
    """True when `target` RESOLVES to `/`, a home/cwd directory, or an ANCESTOR of one, ending in a
    glob — the same wipe as `/*` or `~/*` even when a REAL subdir and `..` sit in the path:
    `/tmp/../*` = `/*`, `~/build/../*` = `~/*`, `/a/b/../../*` = `/*` (Codex #26 r44 F1 / r42 boundary).
    `~/a/b/../*` = `~/a/*` keeps a real subdir and is NOT a wipe. bash resolves `..` lexically against
    the preceding segment, so this counts pushes (real dirs) and pops (`..`): a wipe iff nothing but
    `..` ancestor-markers remain before the glob. The dot-segment-only forms are already caught by
    RM_TARGET_RE; this adds the cases with a real subdir in the path (which a regex cannot balance).
    Only the parser has this — the legacy regex matchers cannot count, so a real-subdir normalization
    stays a documented weaker-fallback gap on the no-python path."""
    m = _WIPE_BASE_RE.match(target)
    if not m:
        return False
    base, rest = m.group(0), target[m.end():]
    if base == "/":
        segs = rest.split("/")
    else:
        if not rest.startswith("/"):
            return False
        segs = rest[1:].split("/")
    # A trailing glob (`/tmp/../*`) is a glob-wipe of the RESOLVED dir; a path with NO glob
    # (`/tmp/..`, `~/build/..`) targets the resolved dir ITSELF — an explicit-absolute/home delete
    # of root/home/cwd, e.g. `rm -rf --no-preserve-root /tmp/..` = `/` (Codex #26 r48 F1; the r44
    # form only handled the glob suffix). Both are a wipe iff the path pops back to the base
    # (root/home/cwd) or an ancestor, i.e. nothing but `..` ancestor-markers remain.
    if segs and segs[-1] and segs[-1][0] in "*?":
        body = segs[:-1]
    else:
        body = segs
    stack = []
    for seg in body:
        if seg in ("", "."):
            continue
        if seg == "..":
            if stack and stack[-1] != "..":
                stack.pop()          # pop a real subdir
            else:
                stack.append("..")   # already at/above the base — go higher
        else:
            stack.append(seg)
    return all(s == ".." for s in stack)


def is_wipe_target(value):
    """True when a variable's stored value is a root/home/cwd rm target (`/`, `~`, `$PWD`, or a
    `..`-normalized wipe). Used to keep a CONDITIONAL assignment from clearing such a value (r60 F1)."""
    return isinstance(value, str) and bool(RM_TARGET_RE.match(value) or normalizes_to_wipe(value))


def rm_is_destructive(cmd, args):
    """True when a resolved `rm` invocation is a recursive-force removal of a root/home/cwd target,
    in any flag arrangement (`-rf`, `-r -f`, `-fr`, `--recursive --force`) and past an optional `--`
    end-of-options marker. Token-based, so ordering and clustering do not matter."""
    if cmd.rsplit("/", 1)[-1] != "rm":
        return False
    has_r = has_f = False
    targets = []
    seen_ddash = False
    for a in args:
        if seen_ddash:
            targets.append(a)          # past `--` every word is a FILENAME, incl. `-rf` (r60 F3)
            continue
        if a == "--":
            seen_ddash = True
            continue
        if a == "--recursive":
            has_r = True
        elif a == "--force":
            has_f = True
        elif a.startswith("--"):
            continue
        elif a.startswith("-") and len(a) > 1:
            letters = a[1:]
            if "r" in letters or "R" in letters:
                has_r = True
            if "f" in letters:
                has_f = True
        else:
            targets.append(a)
    if not (has_r and has_f):
        return False
    return any(RM_TARGET_RE.match(t) or normalizes_to_wipe(t) for t in targets)


RM_WORD_RE = re.compile(r"(?:^|[^\w/])rm(?=\s)")


def legacy_rm_destructive(text):
    """The unanchored counterpart to rm_is_destructive, for the fallback path. A construct that
    executes argument DATA (a git alias/pager, an interpreter code string, a runner, tar/rsync/
    submodule) hands that data to the legacy matcher, whose clustered-`-rf` regexes miss `rm -r -f /`
    (Codex #26 r15c F1). So when a fallback is about to fire, scan the flattened text for an `rm` with
    recursive+force flags (any arrangement) and a root/home/cwd target. Quotes are removed and shell
    separators isolated so a glued `;`/`&`/`|` ends one rm's argument scan; `rm` is found even when
    glued to a `(`/quote (`os.system('rm -r -f /')`)."""
    flat = re.sub(r"([;&|()])", r" \1 ", re.sub(r"[\"']", "", deobfuscate(text)))
    for m in RM_WORD_RE.finditer(flat):
        has_r = has_f = False
        targets = []
        seen_ddash = False
        for w in flat[m.end():].split():
            if w in (";", "&", "|", "(", ")"):
                # `(`/`)` are grouping / call delimiters, so a target ends at one: the code string
                # `os.system('rm -rf /tmp/..')` flattens to `… ( rm -rf /tmp/.. )`, and without this
                # break the target was `/tmp/..)` — the trailing `)` defeated normalizes_to_wipe.
                break
            if seen_ddash:
                targets.append(w)          # past `--` every word is a FILENAME, incl. `-rf` (r60 F3)
                continue
            if w == "--":
                seen_ddash = True
            elif w == "--recursive":
                has_r = True
            elif w == "--force":
                has_f = True
            elif w.startswith("--"):
                continue
            elif w.startswith("-") and len(w) > 1:
                if "r" in w[1:] or "R" in w[1:]:
                    has_r = True
                if "f" in w[1:]:
                    has_f = True
            else:
                targets.append(w)
        # normalizes_to_wipe mirrors rm_is_destructive: a `..`-normalized root/home delete
        # (`rm -rf /tmp/..` = `/`) in an EXECUTED/unmodeled body (a case/watch/`python3 -c` payload)
        # reaches this python fallback, which CAN count `..` — only the no-python `.sh` matcher can't,
        # so that stays the documented weaker-fallback gap (Codex #26 r57 F1).
        if has_r and has_f and any(RM_TARGET_RE.match(t) or normalizes_to_wipe(t) for t in targets):
            return True
    return False

# The legacy unanchored matcher, mirrored in python. Applied to shell-EXECUTED script bodies
# (`-c`, herestring, heredoc-to-shell, eval, source) — the bash legacy matcher strips
# heredoc/herestring content before grep, so deferring an executed script to it loses the literal
# (Codex #26 r13 F1). In a script (not top-level data) an unanchored match is the right call.
LEGACY_RE = re.compile("|".join(CMD_PATTERNS + [
    RAW_DEVICE_PAT, r":\(\)\{\s*:\|:&\s*\};:",
    r"curl\s+.*\|\s*(sh|bash|zsh)", r"wget\s+.*\|\s*(sh|bash|zsh)",
]), re.IGNORECASE)


def interpreter_program_is_dangerous(text):
    """Unanchored match for an INTERPRETER program body (a heredoc handed to `python3`/`perl`/…).
    The body is not shell, so it cannot be parsed here; its quotes are STRIPPED rather than blanked
    because the destructive command lives inside them — `os.system("rm -rf /")`. This is the same
    (over-blocking) reading the legacy matcher already applies to `python3 -c "…"`, so it keeps the
    two forms consistent: a program that merely PRINTS the string is denied either way."""
    flat = re.sub(r"[\"']", "", deobfuscate(text))
    return bool(LEGACY_RE.search(flat)) or legacy_rm_destructive(text)


def interpreter_program_consumer(intro):
    """True when ANY pipeline stage of the heredoc's introducing statement is an interpreter taking
    its PROGRAM from stdin. Checking only the stage that owns the heredoc missed the common
    `cat <<EOF | python3 … EOF`, where `cat` reads the body and python EXECUTES it (Codex #26 r25 F1)
    — the same reason `has_shell_command_word` scans every stage for `cat <<EOF | bash`."""
    try:
        _, redacted, _ = extract_subs(intro)
    except Unparsable:
        return True                     # fail-safe: scan the body
    for pipeline in split_pipelines(strip_redirections(redacted)):
        for stage in pipeline:
            try:
                tokens = shlex.split(stage, posix=True)
            except ValueError:
                return True
            resolved = command_head_and_args(tokens)
            if resolved is None:
                continue
            cmd, args = resolved
            base = cmd.rsplit("/", 1)[-1]
            if INTERP_CMD_RE.match(base) and interpreter_reads_stdin_program(base, args):
                return True
    return False


def python_legacy(text):
    """Unanchored dangerous-pattern match for EXECUTED script bodies. Quoted regions are BLANKED
    (not stripped), so a dangerous literal that is DATA — a commit message in `bash -c "git commit
    -m '…'"` — stays allowed (Codex #26 r15d F2), while an UNQUOTED dangerous command in the body
    (`case x in *) rm -rf /;; esac`, `rm -rf /` on the live line before an unbalanced quote) still
    matches. Both the raw and the backslash-removed spellings are tested: deobfuscation resolves
    `r\\m` to `rm`, but it also eats the boundary in `rm -rf /\\n`, which `/([^a-zA-Z]|$)` then misses
    (Codex #26 r15 F2). Union, never weaker."""
    def hit(s):
        return bool(LEGACY_RE.search(blank_quoted(s)))
    return hit(text) or hit(deobfuscate(text))


# Effects with no command word of their own: redirection onto a raw device, and the fork bomb.
# Evaluated against text whose quoted regions are blanked, so a quoted mention stays data.
RAW_RE = re.compile(RAW_DEVICE_PAT + r"|:\(\)\{\s*:\|:&\s*\};:", re.IGNORECASE)

SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
FETCHERS = {"curl", "wget"}
FIND_CMDS = {"find", "gfind"}
FIND_EXEC_ACTIONS = {"-exec", "-execdir", "-ok", "-okdir"}
# find PREDICATES / options that consume the NEXT token as a VALUE, so a `-delete`/`-exec` sitting
# there is DATA (a search value), not the action: `find / -name -delete` looks for a file named
# `-delete` (Codex #26 r62 F4). The walker skips each such operand before deciding on an action.
FIND_VALUE_PREDICATES = {
    "-name", "-iname", "-path", "-ipath", "-wholename", "-iwholename", "-lname", "-ilname",
    "-regex", "-iregex", "-regextype", "-type", "-xtype", "-newer", "-anewer", "-cnewer",
    "-newermt", "-newerat", "-newerct", "-perm", "-user", "-uid", "-group", "-gid", "-size",
    "-inum", "-links", "-mtime", "-atime", "-ctime", "-mmin", "-amin", "-cmin", "-fstype",
    "-used", "-samefile", "-context", "-maxdepth", "-mindepth",
    # print predicates consume operands too — `find / -printf -delete` prints the format `-delete`,
    # it does not delete (Codex #26 r63 F3). `-fprintf FILE FORMAT` takes TWO (handled in the walk).
    "-printf", "-fprint", "-fprint0", "-fls",
}
# `-fprintf` consumes TWO operands (the output FILE then the FORMAT), unlike the single-operand
# predicates above — so `find / -fprintf out -delete` prints, it does not delete (Codex #26 r63 F3).
FIND_2VALUE_PREDICATES = {"-fprintf"}
# Wrappers that merely prefix another command: drop them and re-resolve the command behind.
PREFIXES = {"sudo", "doas", "nohup", "command", "builtin", "exec", "time",
            "stdbuf", "nice", "ionice", "setsid", "env", "xargs", "taskset", "chrt"}

# Options that take a SEPARATE operand. Dropping the flag but not its operand would leave the
# operand sitting in command position (`sudo -u root rm -rf /` → command word "root"), hiding the
# real command behind it (Codex #26 F2).
WRAPPER_OPERAND_OPTS = {
    "sudo": {"-u", "-g", "-p", "-C", "-D", "-h", "-R", "-T", "--user", "--group",
             "--prompt", "--close-from", "--chdir", "--host", "--chroot", "--timeout"},
    "doas": {"-u", "-C"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid"},
    # env `-S`/`--split-string` is NOT here: its operand is a command string that must be SCANNED,
    # not dropped (`env -S 'rm -rf /'` executes rm) — handled specially in resolve (Codex #26 r5 F3).
    "env": {"-u", "--unset", "-C", "--chdir"},
    # `-i` / `--replace` are NOT here: xargs `-i[R]` / `--replace[=R]` take only an ATTACHED optional
    # operand, never a separate one, so listing them made strip_wrapper_options eat the CHILD COMMAND
    # as their operand (`xargs -i rm -rf {}` / `xargs --replace rm -rf {}` → the `rm` was dropped —
    # Codex #26 r50 F1). `-I` does take a separate one and stays.
    "xargs": {"-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a",
              "--max-lines", "--max-args", "--max-procs", "--max-chars", "--delimiter",
              "--eof", "--arg-file"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "taskset": {"-p", "-c", "--cpu-list", "--pid"},
    "chrt": {"-p", "--pid"},
    "exec": {"-a"},
    "timeout": {"-k", "-s", "--signal", "--kill-after"},
}

# Wrappers that take a mandatory POSITIONAL numeric operand (CPU mask, priority, niceness) before
# the command: `taskset 0x1 rm -rf /`, `chrt -o 0 rm -rf /`, `nice 10 rm -rf /`. Left in command
# position, the operand hides the real command (Codex #26 r5 F3).
POSITIONAL_NUM_WRAPPERS = {"nice", "taskset", "chrt"}
NUM_OPERAND_RE = re.compile(r"^[+-]?(?:0[xX][0-9a-fA-F]+|[0-9]+)$")

# Standard single-char ANSI-C ($'...') escapes. Hex/octal/unicode handled numerically below.
ANSIC_SIMPLE = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n",
                "r": "\r", "t": "\t", "v": "\v", "\\": "\\", "'": "'", '"': '"', "?": "?"}

# Reserved words and group delimiters are not command words. Bash still runs what follows them
# (`if rm -rf /; then …`, `( rm -rf / )`, `{ rm -rf /; }`, `! rm -rf /`) — Codex #26 F1.
RESERVED = {"if", "then", "elif", "else", "fi", "while", "until", "for", "do", "done",
            "case", "esac", "in", "select", "function", "coproc",
            "!", "{", "}", "(", ")", "[[", "]]", ";;"}

# Constructs the command-position model does NOT cover: `case` bodies (the `pat)` word is not
# reserved, so its statement resolves to the pattern word and the body hides behind it),
# select/function/coproc grammars, and a function DEFINITION (`f() { … }` / `f () { … }` — the
# body is invisible to statement-level resolution but runs on call; the `()` pair is the one
# shape every definition shares). When the parser finds nothing and one of these is present,
# defer to the legacy unanchored matcher rather than allowing. The spaced reserved words
# (if/then/elif/else/fi, while/until/for/do/done, `!`, `{ …; }`, `( … )`) and a glued leading
# `(`/`{` ARE modeled — resolve() skips/strips them to the real command word — so they no longer
# defer: deferring EVERY construct sent `if true; then echo "rm -rf /"; fi` to the quote-stripping
# legacy matcher, reintroducing the quoted-data false positive OPS-523 removes (Codex #26 r16 F2).
# The other construct-shaped unknown — a `$var` in command position, which the old blanket
# deferral caught by accident inside loops — is deferred explicitly by scan().
CONSTRUCT_RE = re.compile(
    r"(^|[\s;&|])(case|esac|select|function|coproc)(\s|;|$)"
    r"|\(\s*\)"
)

# A function-definition opener: `NAME()` (paren form), optionally GLUED to the body's `{`/`(`
# (`f(){`). The NAME is not a command word — the compound body that follows runs on call, so it is
# stripped and the body is scanned like a bare `{ … }` (Codex #26 r67 F1). Group 1 is the glued body
# opener (`{`/`(`), fed back so the reserved-word handling strips it too.
FUNC_DEF_OPENER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\(\)([({]?)$")
FUNC_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\+?=")
# `name+=value` APPENDS to the variable's current value (`d=/; d+=tmp` → `d=/tmp`), so a base that
# WAS a protected target may no longer be — and, worse, one that was NOT can become one (`d=; d+=/`
# → `d=/`, a fail-open the model missed). Detected before the plain `=` partition (self-audit).
APPEND_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)\+=(.*)$", re.DOTALL)
# extract_subs' placeholder for a command/process substitution. In COMMAND position it means the
# command is the OUTPUT of another command — statically unresolvable, deferred like a `$var`.
# The placeholder is spliced in WITHOUT padding, so that `x=$(echo hi)` stays the single assignment
# token bash sees instead of splitting into `x=` plus a synthetic command word (which deferred, and
# denied `x=$(echo "rm -rf /")` — Codex #26 r21 F2). Dropping the padding also means adjacent
# fragments stay glued exactly as bash concatenates them (`$(printf r)$(printf m)` → one word), which
# is what UNRESOLVABLE_CMD_RE / inline_command_word rely on (r23 F2).

# ---------------------------------------------------------------------------------------------
# TOKEN-LEVEL fallback guards. These four classes — interpreter code strings, command-runner
# wrappers, tools given a command as option data, and find's -exec family — used to be TEXT
# regexes, but text cannot answer "is this the command word?" once quoting is in play. Matching
# them on the RAW text over-blocked quoted DATA (`git commit -m "… find . -exec rm -rf / \;"` —
# r18 F3); matching them on the quote-BLANKED probe under-blocked a quoted COMMAND word, because
# bash removes quotes during word formation and `"python3" -c …` / `"watch" rm -rf /` /
# `git -c 'alias.p=!rm -rf /' p` all execute (Codex #26 r20 F1). Neither text view can be right:
# the distinction is positional. shlex has already removed the quoting, so the resolved command
# word and args decide instead — the same signal `resolve()` uses. Text regexes remain ONLY for
# shapes that cannot be quoted and still work (shell sinks, reserved words, process substitutions).
# Interpreters execute a code string handed to them as an ARGUMENT (`python3 -c "os.system(…)"`,
# `perl -e '…'`). The destructive command never reaches shell command position, and the code is not
# shell, so parsing it here would be wrong — defer to the legacy matcher. Only when the interpreter
# is actually given CODE, though: `python3 script.py "rm -rf /"` passes an ordinary argv string to a
# script file, and deferring it denied plain script arguments (Codex #26 r21 F4). Flags are listed
# per-family because they collide — python's `-E` ignores the environment, it does not eval.
INTERP_CMD_RE = re.compile(
    r"^(python[\d.]*|perl|ruby|node|nodejs|php|lua|tclsh|osascript|awk|gawk|mawk|Rscript|deno|bun)$")
INTERP_CODE_FLAGS = {
    "python": {"-c"},
    "perl": {"-e", "-E"},
    "ruby": {"-e"},
    "node": {"-e", "--eval", "-p", "--print"},
    "nodejs": {"-e", "--eval", "-p", "--print"},
    "deno": {"-e", "--eval"},
    "bun": {"-e", "--eval"},
    "php": {"-r"},
    "lua": {"-e"},
    "osascript": {"-e"},
    "Rscript": {"-e"},
}
# Short options CLUSTER, so the code flag need not be its own token: `python3 -Ec '…'`, `perl -le
# '…'`, `node -pe '…'` all evaluate (Codex #26 r24 F1). Matching only the exact `-c`/`-e` tokens let
# them through. The letters are per-family because they collide across interpreters — python's `-E`
# ignores the environment, perl's `-E` evaluates. Over-matching a cluster (perl's `-Mmodule`
# contains an `e`) only defers to the legacy matcher, which needs a dangerous literal to block.
INTERP_CODE_LETTERS = {
    "python": "c", "perl": "eE", "ruby": "e", "node": "ep", "nodejs": "ep",
    "deno": "e", "bun": "e", "php": "r", "lua": "e", "osascript": "e", "Rscript": "e",
}
# Short options that consume the REST of the cluster as an ATTACHED operand, so a code letter AFTER
# them is that operand's text, not an eval flag: perl `-MEncode`/`-Idir`, ruby `-rlib`, python
# `-mpkg`. Scanning past them read the `e` in `Encode` as `-e` and over-blocked a safe script-file
# call with a quoted argument (Codex #26 r44 F2). Only UNAMBIGUOUSLY-attached options are listed —
# perl `-l` (optional octal) / `-i` (optional ext) can be bare flags before `-e`, so they are excluded.
INTERP_ATTACHED_LETTERS = {
    "python": "m", "perl": "MmICDF", "ruby": "rICFKE", "node": "r", "nodejs": "r",
    "php": "dc", "lua": "l", "osascript": "l",   # -d/-c define/config, -l library/language (self-audit)
}
# Options that consume a SEPARATE operand. Without this the operand looks like the script file, so
# `python3 -W ignore <<EOF … EOF` was read as "runs the script `ignore`" and its stdin PROGRAM was
# never scanned (Codex #26 r24 F1).
INTERP_OPERAND_OPTS = {
    "python": {"-W", "-X", "--check-hash-based-pycs"},
    "perl": {"-I", "-x"},
    "ruby": {"-I", "-r", "-C", "-F", "-K", "-E"},
    "node": {"-r", "--require", "--import", "--experimental-loader", "--max-old-space-size"},
    "nodejs": {"-r", "--require", "--import", "--experimental-loader", "--max-old-space-size"},
    "php": {"-d", "-c"},
    "deno": set(), "bun": set(), "lua": set(), "osascript": set(), "Rscript": set(),
}


def interp_family(base):
    """`python3.13` → `python`; every other interpreter names its own family."""
    return re.sub(r"[\d.]+$", "", base) if base.startswith("python") else base
# awk's program is the first non-option ARGV word unless `-f progfile` supplies it, so there is no
# code FLAG to look for: `awk 'BEGIN{system("rm -rf /")}'` carries the code positionally.
AWK_CMDS = {"awk", "gawk", "mawk"}


def interpreter_runs_code(base, args):
    """True when this interpreter invocation carries a CODE STRING (rather than a script file plus
    ordinary argv). The code is not shell, so the caller defers to the legacy matcher."""
    if base in AWK_CMDS:
        # gawk also spells the script-file option `--file=progfile`; without it a safe script-file
        # call with a dangerous-looking argv was denied as if the argv were code (Codex #26 r31 F3).
        return not any(a in ("-f", "--file") or a.startswith("-f") or a.startswith("--file=")
                       for a in args)
    if base in ("deno", "bun") and args and args[0] == "eval":
        return True
    family = interp_family(base)
    flags = INTERP_CODE_FLAGS.get(family, set())
    letters = INTERP_CODE_LETTERS.get(family, "")
    for a in args:
        if a in flags or any(a.startswith(f + "=") for f in flags if f.startswith("--")):
            return True
        # A short-option cluster carrying the family's code letter: `-Ec`, `-Bc`, `-le`, `-pe`. Scan
        # left-to-right and STOP at an attached-operand option — `perl -MEncode` is a module load, so
        # the `e` in `Encode` is not `-e` (Codex #26 r44 F2).
        if letters and a.startswith("-") and not a.startswith("--") and len(a) > 1:
            attached = INTERP_ATTACHED_LETTERS.get(family, "")
            for c in a[1:]:
                if c in letters:
                    return True
                if c in attached:
                    break
    return False


def interpreter_reads_stdin_program(base, args):
    """True when the interpreter takes its PROGRAM from stdin: `python3 <<EOF …`, `python3 - <<<…`,
    `echo <code> | perl`. The code never appears as an argument, so `interpreter_runs_code` says no
    and the destructive command was ALLOWED (Codex #26 r23 F1). A script FILE plus a heredoc is the
    opposite case — the heredoc is stdin DATA to that script (`python3 script.py <<EOF … EOF`) — and
    must stay allowed, as must `-m module`.

    An interpreter reads its program from stdin when no script file is named, or when the file is
    the explicit `-` placeholder. awk never does (its program is an argument or `-f progfile`)."""
    if base in AWK_CMDS or interpreter_runs_code(base, args):
        return False
    fam = interp_family(base)
    operand_opts = INTERP_OPERAND_OPTS.get(fam, set())
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False   # this word is the previous option's operand, not the script
            continue
        if a == "-" or a == "<<<":
            return True         # explicit stdin, or a herestring supplying the program
        # python `-m module` RUNS the module (stdin is the module's DATA), spaced or ATTACHED
        # (`python3 -mjson.tool`). perl `-m`/`-M` only LOAD a module and still read the program from
        # stdin, so the attached form is python-scoped (Codex #26 r52 F3).
        if a == "-m" or a == "--module":
            return False
        if fam == "python" and ((a.startswith("-m") and len(a) > 2) or a.startswith("--module=")):
            return False
        if a in operand_opts:
            skip_next = True
            continue
        if not a.startswith("-"):
            # A script-FILE operand that IS stdin (`python3 /dev/stdin <<EOF`, `perl /dev/fd/0`) runs
            # the heredoc/pipe body AS the program, exactly like the bare `-` above (Codex #26 r62 F3).
            return a in ("/dev/stdin", "/dev/fd/0")
    return True


def interpreter_script_file(base, args):
    """The operand an interpreter executes as its SCRIPT FILE — the first non-option word, skipping
    options and their operands (`python3 -W ignore <file>` skips `ignore`) — or None when it instead
    runs a code string, reads its program from stdin, or names a `-m` module. `python3 <(printf …)`
    returns the process-sub placeholder, so the caller can scan that file's OUTPUT as the interpreter
    program a split literal hides from the legacy matcher (Codex #26 r36 F2)."""
    if base in AWK_CMDS or interpreter_runs_code(base, args) or interpreter_reads_stdin_program(base, args):
        return None
    fam = interp_family(base)
    operand_opts = INTERP_OPERAND_OPTS.get(fam, set())
    skip_next = False
    for a in args:
        if skip_next:
            skip_next = False
            continue
        if a in ("-m", "--module"):
            return None
        if fam == "python" and ((a.startswith("-m") and len(a) > 2) or a.startswith("--module=")):
            return None
        if a in operand_opts:
            skip_next = True
            continue
        if not a.startswith("-"):
            return a
    return None
# Command-runner wrappers execute the command that follows them, but each has its own option grammar
# (`strace -o f cmd`, `su -c cmd`, `flock file cmd`, `gdb --args cmd`) that is not worth modelling
# one-by-one. `ssh`/`trap` also execute a command supplied as data (a remote command / a deferred
# handler). `sed` is deliberately NOT listed: `sed 's|rm -rf /|x|'` is a common DATA substitution
# OPS-523 exists to allow, and sed's exec (`1e …`) can't be told apart cheaply — documented boundary.
RUNNER_CMD_RE = re.compile(
    r"^(watch|unbuffer|torsocks|torify|catchsegv|firejail|strace|ltrace|valgrind|ssh-agent|ssh|"
    r"flock|chroot|su|runuser|script|gdb|lldb|perf|proot|rlwrap|systemd-run|optirun|primusrun|"
    r"numactl|cpulimit|daemonize|nsenter|unshare|parallel|qemu-[\w-]+|retry|expect|entr|trap)$")
# Tools that take a COMMAND as option DATA and then execute it (`tar --checkpoint-action=exec=…`,
# `rsync --rsh=…`). Scoped to the tools that actually OWN these options, so `echo
# --checkpoint-action=exec=…` stays data. Accepted boundary (same status as the `sed` exec form):
# interactive-editor shell escapes (`vim -c '!…'`) and short-option transports (`rsync -e`, `scp -S`)
# are not modelled — low real-world hook exposure, high false-positive risk on benign filenames.
DATA_EXEC_CMDS = {"git", "tar", "gtar", "bsdtar", "rsync", "cpio", "pax"}
DATA_EXEC_OPT_RE = re.compile(
    r"^--(checkpoint-action|to-command|use-compress-program|rsh|rsh-command"
    r"|rsync-path|upload-pack|receive-pack)(=|$)")
# A `git -c <key>=<val>` executes only when <key> is a config key that CARRIES a command — an alias
# (`!`-prefixed shell), a pager, an editor, an ssh command, or a credential/filter/diff/merge helper.
# A benign per-command config (`-c color.ui=always`, `-c user.name=x`) does NOT, so treating every
# `git -c …` as executing over-blocked a dangerous string sitting in the COMMIT MESSAGE — the exact
# false positive OPS-523 removes (Codex #26 r15b F4). The section/name is case-insensitive in git.
GIT_EXEC_CFG_KEY_RE = re.compile(
    r"^(?:(?:alias|pager|credential)\.|[^\s=]*\."
    r"(?:pager|editor|sshcommand|helper|external|driver|clean|smudge|process"
    r"|fsmonitor|packobjectshook))", re.IGNORECASE)


def git_runs_an_argument(args):
    """True when a resolved `git` invocation hands a COMMAND to git as option/subcommand DATA:
    `-c alias.x='!rm -rf /'`, `--config-env`, `submodule foreach`, `bisect run`, `rebase -x`,
    `filter-branch`. `git commit -m` / `git log --grep` do NOT execute and are not listed."""
    for i, a in enumerate(args):
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a in ("-c", "--config-env") and GIT_EXEC_CFG_KEY_RE.match(nxt):
            return True
        for opt in ("-c=", "--config-env="):
            if a.startswith(opt) and GIT_EXEC_CFG_KEY_RE.match(a[len(opt):]):
                return True
        if a == "filter-branch":
            return True
        if a == "foreach" and "submodule" in args[:i]:
            return True
        if a == "run" and "bisect" in args[:i]:
            return True
        if a in ("-x", "--exec") and "rebase" in args[:i]:
            return True
    return False


def runs_unmodelled_command(cmd, args):
    """True when this resolved command EXECUTES something the command-position model cannot see:
    an interpreter CODE STRING, a command-runner wrapper, or a tool given a command as option data.
    The caller defers to the legacy unanchored matcher, which over-blocks on a dangerous literal —
    so on THIS path the verdict is the union of the two matchers. (Where the parser instead resolves
    the command and returns ALLOW, that answer is authoritative — see the module docstring.)

    `find -exec` is deliberately absent: resolve() already PARSES the exec child and scans it as a
    real command, so deferring afterwards only re-denied the child's quoted data
    (`find . -exec echo "rm -rf /" \\;` — Codex #26 r21 F3). The child's own command word is what
    decides, exactly as it does at the top level."""
    base = cmd.rsplit("/", 1)[-1]
    # A consumer that EXECUTES a process substitution's output rather than reading it: `make -f
    # <(…)`, `awk -f <(…)`, `source <(…)`. The substitution's own command was already scanned, so
    # only this output path is unmodelled (Codex #26 r24 F3).
    if base in PROCSUB_FILE_EXEC_CMDS and any(PROCSUB_ARG_RE.search(a) for a in args):
        return True
    if INTERP_CMD_RE.match(base):
        # An interpreter handed a process substitution as its SCRIPT FILE executes that file's
        # contents (`python3 <(printf '…rm -rf /…')`). The substitution's own command word is
        # `printf`, so scanning it proves nothing about what the interpreter then runs — defer
        # (Codex #26 r25 F2).
        if any(PROCSUB_ARG_RE.search(a) for a in args):
            return True
        # …or when it reads its program from STDIN (`echo <code> | python3`, `python3 - <<<…`).
        return interpreter_runs_code(base, args) or interpreter_reads_stdin_program(base, args)
    if RUNNER_CMD_RE.match(base):
        return True
    if base in DATA_EXEC_CMDS:
        if any(DATA_EXEC_OPT_RE.match(a) for a in args):
            return True
        if base == "git" and git_runs_an_argument(args):
            return True
    return False


def leading_env(tokens, subs, assigns):
    """The command-LOCAL environment a stage sets via leading `NAME=VALUE` prefixes (`FOO=bar cmd …`),
    resolved against the shell state and layered over the persistent shell vars. bash exports these to
    the command's environment, so `git --config-env` reads them (Codex #26 r69 F2)."""
    env = {name: scalar_of(v) for name, v in assigns.items()}
    for t in tokens:
        if not ASSIGN_RE.match(t):
            break
        name, _, val = t.partition("=")
        if name:
            env[name.rstrip("+")] = resolve_assignment_value(val, subs, assigns)
    return env


def unmodelled_shell_payloads(cmd, args, env=None):
    """The SHELL-command strings a command executes as option/argument DATA — values the legacy
    fallback sees only as quoted TEXT, so a split-literal SINK inside them slipped through: `git -c
    alias.x='!printf %s r m " -rf /" | sh' x` assembles `rm -rf /` into `sh`, but the contiguous
    matcher never saw it (Codex #26 r43 F2). Returns the payloads to scan_executed. `env` maps the
    stage's in-scope variables to their values, so `git --config-env` (which reads the config value
    from an ENVIRONMENT variable) resolves it. Interpreter CODE strings (`python3 -c …`) are a
    different language and stay on the interpreter path."""
    base = cmd.rsplit("/", 1)[-1]
    out = []

    def cfg_val(kv):
        _, _, v = kv.partition("=")
        return v[1:] if v.startswith("!") else v   # a git alias's `!` prefix runs a shell command

    def cfg_env_val(kv):
        # `--config-env KEY=ENVVAR` sets KEY to the VALUE of the environment variable ENVVAR, so a
        # same-command `ENVVAR='!…'` feeds the alias (Codex #26 r69 F2). An unknown (ambient) ENVVAR is
        # not statically resolvable — return "" so nothing is scanned, the documented boundary.
        _, _, name = kv.partition("=")
        val = (env or {}).get(name)
        if val is None:
            return ""
        return val[1:] if val.startswith("!") else val

    if base == "git":
        for i, a in enumerate(args):
            nxt = args[i + 1] if i + 1 < len(args) else ""
            if a == "-c" and GIT_EXEC_CFG_KEY_RE.match(nxt):
                out.append(cfg_val(nxt))
            elif a == "--config-env" and GIT_EXEC_CFG_KEY_RE.match(nxt):
                out.append(cfg_env_val(nxt))
            if a.startswith("-c=") and GIT_EXEC_CFG_KEY_RE.match(a[len("-c="):]):
                out.append(cfg_val(a[len("-c="):]))
            elif a.startswith("--config-env=") and GIT_EXEC_CFG_KEY_RE.match(a[len("--config-env="):]):
                out.append(cfg_env_val(a[len("--config-env="):]))
            if ((a == "foreach" and "submodule" in args[:i])
                    or (a == "run" and "bisect" in args[:i])
                    or (a in ("-x", "--exec") and "rebase" in args[:i])):
                out.append(nxt)
    if base in DATA_EXEC_CMDS:
        # `--checkpoint-action=exec=CMD` (glued) AND `--checkpoint-action exec=CMD` (separate operand)
        # both run CMD; reading only the text after `=` dropped the separate form (Codex #26 r69 F1).
        i = 0
        while i < len(args):
            a = args[i]
            if DATA_EXEC_OPT_RE.match(a):
                _, sep, v = a.partition("=")
                if not sep and i + 1 < len(args):
                    v = args[i + 1]
                    i += 1
                if v:
                    out.append(v[len("exec="):] if v.startswith("exec=") else v)
            i += 1
    if RUNNER_CMD_RE.match(base):
        # Command-runner wrappers EXECUTE a shell command handed to them as DATA — `su -c CMD`,
        # `flock f -c CMD`, `strace bash -c CMD` (the `-c` is the wrapped shell's), `trap 'H' SIG`,
        # `watch 'CMD'`, `ssh host 'CMD'`. runs_unmodelled_command() already marks the wrapper as
        # executing, but only the legacy CONTIGUOUS matcher saw the payload, so a split-literal sink
        # inside it (`trap 'printf … | sh' EXIT`) slipped the gate (Codex #26 r45 F1).
        for i, a in enumerate(args):
            if a == "-c" and i + 1 < len(args):
                out.append(args[i + 1])              # su/flock/runuser/bash -c command string
        if base == "trap":
            for a in args:                            # `trap 'HANDLER' SIG` — the handler is the
                if not a.startswith("-"):             # first non-option word
                    out.append(a)
                    break
        # watch/ssh/entr and kin take the shell command as a POSITIONAL quoted arg. Only scan an arg
        # that carries a shell list/pipe operator or an embedded substitution — a split-literal sink
        # always does (`… | sh`, `$(printf %s rm) -rf /`) — so a plain data arg (`strace echo "rm
        # -rf /"`) is not force-scanned here. `$(…)`/backtick are already `__SUB\d+__` placeholders
        # by this point (extract_subs runs before shlex), so match the placeholder, not the source.
        for a in args:
            if any(op in a for op in ("|", ";", "&&", "\n", "__SUB", "$(", "`")):
                out.append(a)
    return list(dict.fromkeys(p for p in out if p))
# A short-option cluster CONTAINING `c` runs the next argv as its script — `-c`, `-lc`, and also
# `-cx`/`-ic` where `c` is not last (bash `-cx` = `-c -x`). Matching only clusters ending in `c`
# missed `-cx "rm -rf /"` (Codex #26 r6-sweep).
DASH_C_RE = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")

# A heredoc delimiter is a WORD, not an identifier: `<<EOF.txt`, `<<EOF-1`, `<<'EOF.txt'` are all
# legal. Capturing only the leading `EOF` of `<<EOF.txt` made split_heredocs hunt for a terminator
# that never appears, swallowing every following line — including a trailing `rm -rf /` that bash
# runs after the real `EOF.txt` terminator (Codex #26 r15 F1). The unquoted form may START with a
# DIGIT — bash accepts `<<1` (Codex #26 r71 F2); an arithmetic shift (`$((x << 2))`) is excluded not
# by the delimiter's first char but by `inert_mask`, which blanks `$((…))`/`((…))` before matching,
# and the lookarounds keep `<<<` (herestring) from ever matching as a heredoc.
# Group 1 captures the `-` of `<<-`, which strips leading TABS (not spaces) from body lines and
# from the terminator — verified against bash (Codex #26 r31 F2).
HEREDOC_RE = re.compile(
    r"(?<!<)<<(?!<)(-?)[ \t]*"
    r"(?:(['\"])([^'\"]+)\2|([A-Za-z0-9_][^\s;&|<>()'\"`$]*))")

# A `<<` inside a COMMENT or an arithmetic expansion is not a heredoc operator: bash runs the lines
# that follow, but the scanner swallowed them as a body and never saw the live command
# (`# <<EOF` ⏎ `rm -rf /` — Codex #26 r31 F1). `$(( 1 <<EOF ))` is a left-shift, not a redirection.
ARITH_OPEN_RE = re.compile(r"\$\(\(|\(\(")


def inert_mask(line, quoted):
    """Extend a quote mask with the regions where a `<<` cannot be a heredoc operator: everything
    after an unquoted `#` that starts a word, and anything inside `$((…))` / `((…))`."""
    mask = list(quoted)
    n = len(line)
    for i, ch in enumerate(line):
        if quoted[i] or ch != "#":
            continue
        if i == 0 or line[i - 1] in " \t;&|(":
            for j in range(i, n):
                mask[j] = True
            break
    for m in ARITH_OPEN_RE.finditer(line):
        if quoted[m.start()] or mask[m.start()]:
            continue
        depth, j = 0, m.end() - 2      # start at the first `(` of the pair
        while j < n:
            if line[j] == "(":
                depth += 1
            elif line[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        for k in range(m.start(), min(j + 1, n)):
            mask[k] = True
    return mask

# A process substitution becomes a FILE. Its CONTENTS are scanned as a command (that is how
# `diff <(rm -rf /)` blocks), so the only thing left unmodelled is a consumer that executes the
# substitution's OUTPUT rather than reading it: `make -f <(printf '…')`, `awk -f <(…)`, `source <(…)`.
# Deferring on the mere PRESENCE of `<(` sent `echo <(echo "rm -rf /")` and `diff <(echo "rm -rf /") x`
# to the quote-stripping legacy matcher and denied them, even though the substitution's own command
# was proven benign — the data-flip this hook exists to preserve (Codex #26 r24 F3). So the defer is
# scoped to those consumers. `bash <(…)` / `sh <(…)` stay covered by SINK_RE.
PROCSUB_FILE_EXEC_CMDS = {"make", "gmake", "bmake", "gnumake", "awk", "gawk", "mawk", "source", "."}
MAKE_CMDS = {"make", "gmake", "bmake", "gnumake"}
PROCSUB_ARG_RE = re.compile(r"__SUB\d+__")


def procsub_program_file(base, args, ph):
    """True when process-sub `ph` is the PROGRAM / MAKEFILE file a make/awk-family consumer executes
    as text: `make -f <(…)`, `awk -f <(…)`, `gawk --file=<(…)`. make runs the makefile's recipes and
    awk runs the program (whose `system("…")` is shell), so a split literal the producer assembled
    (`printf '%s%s -rf /' r m`) is only visible in that file's OUTPUT — the caller scans it (Codex #26
    r55 F1). The procsub must be the `-f`/`--file` (make also `--makefile`) operand: `awk 'prog' <(…)`
    reads it as INPUT DATA and `make <(…)` names a target — neither executes the substitution."""
    file_opts = {"-f", "--file"}
    if base in MAKE_CMDS:
        file_opts.add("--makefile")
    i = 0
    while i < len(args):
        a = args[i]
        if a in file_opts:
            return i + 1 < len(args) and args[i + 1] == ph
        if a.startswith("-f") and len(a) > 2 and a[2:] == ph:          # attached `-f<ph>`
            return True
        for opt in file_opts:
            if opt.startswith("--") and a.startswith(opt + "=") and a[len(opt) + 1:] == ph:
                return True
        i += 1
    return False

# A "shell sink" feeds arbitrary TEXT to a shell, so the destructive command never appears in
# command position: `echo rm -rf / | bash`, `bash <(printf ...)`, `bash <<< "..."`, `bash -s`.
# Command-position analysis cannot see through these (the text may even be computed at runtime),
# so when the parser finds nothing we hand the command to the legacy unanchored matcher, which
# over-blocks. Parser BLOCK still wins, so this is strictly a union of the two decisions.
# The `<(`/`<<<`/`<<` stdin operators only make the shell a SINK when nothing but OPTIONS sits between
# the shell word and the operator — `bash <<< '…'`, `bash -x <<< '…'`. `bash deploy.sh <<< '…'` runs
# the FILE and reads the herestring as its DATA, so it must NOT route to the over-blocking legacy
# matcher (Codex #26 r51 F1). `-s`/`/dev/stdin` stay permissive (they are themselves stdin-script
# signals a file operand cannot mask).
SINK_RE = re.compile(
    r"\|\s*(?:[A-Za-z_]\w*=\S+\s+)*(?:sudo\s+|env\s+|command\s+|exec\s+|nohup\s+|xargs\s+)*"
    r"(?:[\w./-]*/)?(?:sh|bash|zsh|dash|ksh)\b"
    r"|(?:^|[\s;&|])(?:[\w./-]*/)?(?:sh|bash|zsh|dash|ksh)\b(?:[ \t]+[-+][^\s;&|]*)*[ \t]*(?:<\(|<<<|<<)"
    r"|(?:^|[\s;&|])(?:[\w./-]*/)?(?:sh|bash|zsh|dash|ksh)\b[^;&|\n]*(?:\s-s\b|/dev/stdin)"
)

# A `bash -c` / `eval` whose script is built from an expansion (`$(...)`, `$var`, backtick) runs a
# string that cannot be resolved statically — the parser scanned the expansion's COMMAND, not its
# output/value. A dangerous literal in the surrounding text is the signal, so route to the legacy
# unanchored matcher (Codex #26 r6 F1). Checked on deobfuscated-but-unblanked text so a `$()` inside
# double quotes is still seen; benign expansions (`bash -c "echo $HOME"`) fall through legacy clean.
EXPANSION_RE = re.compile(r"[$`]")
EVAL_RE = re.compile(r"(^|[\s;&|(])eval(\s|$)")
SHELL_DASH_C_RE = re.compile(
    r"(^|[\s;&|(])(?:[\w./-]*/)?(?:sh|bash|zsh|dash|ksh)\b[^\n|;&]*\s[-+][A-Za-z]*c[A-Za-z]*\b")


class Dangerous(Exception):
    """A dangerous command was found inside a wrapped script."""


class TooDeep(Exception):
    """Nesting exceeded the parse budget; fail closed."""


class Unparsable(Exception):
    """Input cannot be parsed; defer to the legacy matcher."""


class NeedsFallback(Exception):
    """A fallback guard (sink / interpreter / runner / dynamic-exec) fired — possibly inside a
    recursively-scanned script — so defer the whole command to the legacy matcher (Codex #26 r12)."""


def decode_ansic(body):
    """Decode the body of a bash $'...' string. Bash interprets \\xHH, \\NNN octal, \\uHHHH/\\U…,
    and the standard C escapes, so `$'\\x72\\x6d'` is the word `rm`. Decoding reveals a command word
    spelled in escapes (Codex #26 r5 F2)."""
    out, i, n = [], 0, len(body)
    while i < n:
        c = body[i]
        if c != "\\" or i + 1 >= n:
            out.append(c)
            i += 1
            continue
        nxt = body[i + 1]
        if nxt in ANSIC_SIMPLE:
            out.append(ANSIC_SIMPLE[nxt])
            i += 2
            continue
        if nxt == "x":
            j, h = i + 2, ""
            while j < n and len(h) < 2 and body[j] in "0123456789abcdefABCDEF":
                h += body[j]
                j += 1
            if h:
                out.append(chr(int(h, 16)))
                i = j
                continue
        if nxt in "01234567":
            j, o = i + 1, ""
            while j < n and len(o) < 3 and body[j] in "01234567":
                o += body[j]
                j += 1
            out.append(chr(int(o, 8) & 0xFF))
            i = j
            continue
        if nxt in ("u", "U"):
            width = 4 if nxt == "u" else 8
            j, h = i + 2, ""
            while j < n and len(h) < width and body[j] in "0123456789abcdefABCDEF":
                h += body[j]
                j += 1
            if h:
                try:
                    out.append(chr(int(h, 16)))
                except (ValueError, OverflowError):
                    pass
                i = j
                continue
        out.append(nxt)
        i += 2
    return "".join(out)


# Stands in for a backslash-escaped `$` between deobfuscation and the substitution scanner. A NUL
# cannot appear in a bash command line, so it can never collide with real input.
DOLLAR_ESC = "\x00"


def unescape_dollar(text):
    """Turn the escaped-`$` sentinel back into a live `$`. Called the moment a string becomes an
    EXECUTED script, because the layer that produced it consumed the escape: `bash -c "rm \\$1 \\$2"
    _ -rf /` hands bash the script `rm $1 $2`, whose positional params are then substituted."""
    return text.replace(DOLLAR_ESC, "$")


def deobfuscate(text):
    """Undo the quote removal bash performs on the command word before lookup, so `r\\m -rf /`,
    `$'rm' -rf /`, and `$'\\x72\\x6d' -rf /` cannot hide the command from the matcher. Single-quoted
    regions are literal to bash, so they are left alone; $'...' regions are decoded and emitted
    unquoted so the revealed command word tokenizes on its own."""
    out, i, n, in_sq = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_sq:
            out.append(c)
            if c == "'":
                in_sq = False
            i += 1
            continue
        if c == "$" and i + 1 < n and text[i + 1] == "'":
            j, body = i + 2, []
            while j < n:
                if text[j] == "\\" and j + 1 < n:
                    body.append(text[j:j + 2])
                    j += 2
                    continue
                if text[j] == "'":
                    break
                body.append(text[j])
                j += 1
            # Re-quote the decoded value so it stays ONE argv word — `$'rm -rf /'` is a single arg
            # (a `-c` script), which unquoted emission would split into `rm` + trailing args (Codex
            # #26 r12 F3). shlex.quote leaves a bare word (`$'\x72\x6d'`→`rm`) unquoted so it still
            # surfaces as a command word.
            out.append(shlex.quote(decode_ansic("".join(body))))
            i = j + 1 if j < n else j
            continue
        if c == "'":
            in_sq = True
            out.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            nxt = text[i + 1]
            # A backslash-newline is a line continuation: bash removes BOTH, joining the lines
            # (`rm -rf \<newline>/` is `rm -rf /`). An escaped quote/backtick is a LITERAL char to
            # bash, NOT a delimiter — emitting a bare quote would open a spurious quoted region and
            # hide following syntax such as a heredoc body from the parser (`bash -s \" <<EOF …` —
            # Codex #26 r9 F1); an escaped quote is never part of a dangerous command word, so drop
            # it. Any other escaped char resolves to the char itself (`r\m` → `rm`).
            # An escaped `$` does NOT introduce an expansion — `echo "\$(rm -rf /)"` prints the
            # literal text (Codex #26 r26 F1). Emitting a bare `$` here made extract_subs read it as
            # a live command substitution and deny the data. Emit a sentinel instead: it is inert to
            # every downstream matcher, and scan_executed() turns it back into `$` when the text is
            # handed to a shell, because THAT layer consumes the escape (`bash -c "\$(…)"`,
            # `eval "\$(…)"`, and an unquoted heredoc all really do execute the substitution).
            if nxt == "$":
                out.append(DOLLAR_ESC)
            elif nxt not in ("\n", "'", '"', "`"):
                out.append(nxt)
            i += 2
            continue
        out.append(c)
        i += 1
    return "".join(out)


def quote_mask(s):
    """Per-index mask: True where the character is inside (or is) a single/double quote. Used to
    tell a real heredoc operator (`cat <<EOF`, `<<` unquoted) from a quoted mention of one
    (`echo "<<EOF"`, `<<` inside a string argument)."""
    mask = [False] * len(s)
    in_sq = in_dq = False
    for i, c in enumerate(s):
        if in_sq:
            mask[i] = True
            if c == "'":
                in_sq = False
            continue
        if in_dq:
            mask[i] = True
            if c == '"':
                in_dq = False
            continue
        if c == "'":
            in_sq = True
            mask[i] = True
            continue
        if c == '"':
            in_dq = True
            mask[i] = True
            continue
    return mask


def sub_open_depths(line, start_depth):
    """Per-index command/process-substitution nesting depth for `line` (the depth just BEFORE each
    character), and the end-of-line depth, starting from `start_depth` so a substitution can span
    lines. `$(`/`<(`/`>(` open a level, `)` closes one, backticks toggle; a SINGLE-quoted region is
    inert (double quotes still allow `$(`). Lets split_heredocs skip a `<<` that is inside a
    substitution — extract_subs captures that heredoc with the sub instead (Codex #26 r52 F4)."""
    n = len(line)
    depths = [start_depth] * (n + 1)
    d = start_depth
    in_sq = in_bt = in_dq = False
    dq_stack = []                        # the double-quote state saved at each open substitution level
    j = 0
    while j < n:
        depths[j] = d
        c = line[j]
        if in_sq:
            if c == "'":
                in_sq = False
            j += 1
            continue
        if c == "\\":
            j += 2                       # escaped char — neither opens nor closes
            continue
        if c == "'" and not in_dq:       # a `'` inside double quotes is a literal, not a quote
            in_sq = True
            j += 1
            continue
        if c == '"':
            in_dq = not in_dq
            j += 1
            continue
        if c == "`":
            d = d + 1 if not in_bt else max(0, d - 1)
            in_bt = not in_bt
            j += 1
            continue
        # `$(…)` is a command substitution even inside double quotes, and its body has a FRESH quoting
        # context (the outer `"` does not reach in); `<(…)`/`>(…)` are process substitutions that do
        # NOT work inside double quotes — a quoted `"<("` is literal DATA, so it must not open a depth
        # or poison split_heredocs' `<<`-in-substitution skip (Codex #26 r61 F3).
        if not in_bt and line[j:j + 2] == "$(":
            dq_stack.append(in_dq)
            in_dq = False
            d += 1
            j += 2
            continue
        if not in_bt and not in_dq and line[j:j + 2] in ("<(", ">("):
            dq_stack.append(in_dq)
            in_dq = False
            d += 1
            j += 2
            continue
        if c == ")" and not in_bt and d > 0:
            d -= 1
            if dq_stack:
                in_dq = dq_stack.pop()
            j += 1
            continue
        j += 1
    depths[n] = d
    return depths, d


def split_heredocs(text):
    """Drop heredoc bodies (they are data) while keeping the commands on the introducing line.
    Returns (text_without_bodies, [(introducing_statement, body), ...]) — a body handed to a shell
    is a SCRIPT, not data, so the caller re-scans those. The intro is the STATEMENT that introduces
    the body, not the whole line: `cat <<A; bash <<B` hands body A to cat (data) and body B to bash
    (script) — attributing every body to the full line scanned cat's DATA as a script whenever a
    shell appeared in ANY other statement on it (Codex #26 r17 F1)."""
    lines = text.split("\n")
    out, bodies, i = [], [], 0
    sub_depth = 0
    while i < len(lines):
        line = lines[i]
        # Only an UNQUOTED `<<` is a heredoc redirection. A quoted `<<EOF` (`echo "<<EOF"`) is a
        # string argument, so treating it as a heredoc dropped the following command as body
        # (Codex #26 F3). The delimiter word itself may still be quoted (`cat <<'EOF'`), which the
        # capture group already handles — it's the `<<` operator's position we test.
        # A `<<` INSIDE an open command/process substitution ($(…), <(…), backticks) is that
        # substitution's OWN heredoc — extract_subs captures the sub with its body and it is scanned
        # in the right context, so `echo $(cat <<EOF … EOF)` stays data (Codex #26 r52 F4). Track the
        # substitution depth across lines (a sub can span them) and skip a `<<` while depth > 0.
        quoted = quote_mask(line)
        mask = inert_mask(line, quoted)
        depths, sub_depth = sub_open_depths(line, sub_depth)
        matches = [m for m in HEREDOC_RE.finditer(line)
                   if not mask[m.start()] and depths[m.start()] == 0]
        if matches:
            chars = list(line)
            for m in matches:
                for k in range(m.start(), m.end()):
                    chars[k] = " "
            cleaned = "".join(chars)
        else:
            cleaned = line
        out.append(cleaned)
        i += 1
        # Segment the cleaned line at unquoted statement separators: `;`, `&&`, `||`, and a
        # background/list `&`. NOT at `|`/`|&` — a downstream pipe stage still consumes the body
        # (`cat <<A | bash` executes it) — and not inside redirection operators (`2>&1`, `<&0`,
        # `&>log`), where splitting would detach a `bash 2>&1 <<B` body from its shell.
        segs, seg_start, k = [], 0, 0
        while k < len(cleaned):
            c = cleaned[k]
            if mask[k]:
                k += 1
                continue
            if c == "|":
                if k + 1 < len(cleaned) and cleaned[k + 1] == "|":
                    segs.append((seg_start, k))
                    k += 2
                    seg_start = k
                else:
                    k += 2 if k + 1 < len(cleaned) and cleaned[k + 1] == "&" else 1
                continue
            if c == ";":
                segs.append((seg_start, k))
                while k < len(cleaned) and cleaned[k] == ";":
                    k += 1
                seg_start = k
                continue
            if c == "&":
                if (k and cleaned[k - 1] in "<>") or (k + 1 < len(cleaned) and cleaned[k + 1] == ">"):
                    k += 1
                    continue
                segs.append((seg_start, k))
                while k < len(cleaned) and cleaned[k] == "&":
                    k += 1
                seg_start = k
                continue
            k += 1
        segs.append((seg_start, len(cleaned)))
        for m in matches:
            strip_tabs = m.group(1) == "-"
            delim = m.group(3) or m.group(4)
            intro = cleaned
            for s, e in segs:
                if s <= m.start() < e:
                    intro = cleaned[s:e]
                    break
            body = []
            # bash requires the terminator to be the line EXACTLY — `<<-` strips leading TABS only,
            # never spaces, and trailing whitespace never terminates. `.strip()` let ` EOF` close the
            # body early, so the real data lines after it were scanned as live shell (r31 F2).
            while i < len(lines):
                candidate = lines[i].lstrip("\t") if strip_tabs else lines[i]
                if candidate == delim:
                    break
                body.append(lines[i])
                i += 1
            if i < len(lines):
                i += 1
            bodies.append((intro, "\n".join(body)))
    return "\n".join(out), bodies


def extract_subs(text):
    """Pull the contents of $(...), backticks, and process substitutions <(...) / >(...) — all of
    them execute, and $(...) does so even inside double quotes. Single-quoted regions are literal.
    Returns (contents, redacted_text, input_procsubs) where input_procsubs is the set of 0-based
    indices that came from an INPUT process substitution `<(…)`. Those are the only subs whose OUTPUT
    a consumer executes as a script FILE (`bash <(…)`, `source <(…)`, `python3 <(…)`); a `$(…)` in the
    same argument position instead word-splits into argv (`bash $(printf 'rm -rf /')` runs `bash rm
    -rf /`, opening a file named `rm` — NOT the rm command), so the two must not be conflated
    (Codex #26 r36 F2)."""
    subs, out, i, n = [], [], 0, len(text)
    input_procsubs = set()
    in_sq = in_dq = False

    def take_paren(start):
        """Index of the ) matching the ( at `start`. Parens inside single/double quotes are literal
        text, not grouping, so a `)` in a substitution body (`$(printf ')'; … | sh)`) must not close
        the substitution early — doing so orphaned the real sink payload and it failed open (Codex #26
        r43 F1). The sub body has its own quoting context, independent of the outer text."""
        depth, j, t_sq, t_dq = 0, start, False, False
        while j < n:
            c = text[j]
            if t_sq:
                if c == "'":
                    t_sq = False
            elif t_dq:
                if c == '"':
                    t_dq = False
            elif c == "'":
                t_sq = True
            elif c == '"':
                t_dq = True
            elif c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
                if depth == 0:
                    return j
            j += 1
        raise Unparsable("unbalanced paren")

    while i < n:
        c = text[i]
        if in_sq:
            out.append(c)
            if c == "'":
                in_sq = False
            i += 1
            continue
        if c == "'" and not in_dq:
            in_sq = True
            out.append(c)
            i += 1
            continue
        if c == '"':
            in_dq = not in_dq
            out.append(c)
            i += 1
            continue
        if c == "$" and i + 1 < n and text[i + 1] == "(":
            j = take_paren(i + 1)
            subs.append(text[i + 2:j])
            out.append("__SUB%d__" % len(subs))
            i = j + 1
            continue
        # Process substitution runs its command whatever the outer command is: `diff <(rm -rf /)`.
        # Not honoured inside double quotes by bash, so only scan it outside them.
        if c in "<>" and i + 1 < n and text[i + 1] == "(" and not in_dq:
            j = take_paren(i + 1)
            subs.append(text[i + 2:j])
            if c == "<":
                input_procsubs.add(len(subs) - 1)
            out.append("__SUB%d__" % len(subs))
            i = j + 1
            continue
        if c == "`":
            j = text.find("`", i + 1)
            if j == -1:
                raise Unparsable("unbalanced backtick")
            subs.append(text[i + 1:j])
            out.append("__SUB%d__" % len(subs))
            i = j + 1
            continue
        out.append(c)
        i += 1
    if in_sq or in_dq:
        raise Unparsable("unbalanced quote")
    return subs, "".join(out), input_procsubs


def blank_quoted(text):
    """Blank quoted content so RAW_RE only sees unquoted, effective text."""
    out, in_sq, in_dq = [], False, False
    for c in text:
        if in_sq:
            out.append(c if c == "'" else " ")
            if c == "'":
                in_sq = False
            continue
        if in_dq:
            out.append(c if c == '"' else " ")
            if c == '"':
                in_dq = False
            continue
        if c == "'":
            in_sq = True
        elif c == '"':
            in_dq = True
        out.append(c)
    return "".join(out)


def space_herestrings(text):
    """Bash allows `bash<<<'rm -rf /'` with no spaces, which shlex would keep as ONE token and the
    legacy sed deletes outright (Codex #26 F3). Pad unquoted `<<<` so it tokenizes separately."""
    out, i, n = [], 0, len(text)
    in_sq = in_dq = False
    while i < n:
        c = text[i]
        if in_sq:
            out.append(c)
            if c == "'":
                in_sq = False
            i += 1
            continue
        if in_dq:
            out.append(c)
            if c == '"':
                in_dq = False
            i += 1
            continue
        if c == "'":
            in_sq = True
            out.append(c)
            i += 1
            continue
        if c == '"':
            in_dq = True
            out.append(c)
            i += 1
            continue
        if text[i:i + 3] == "<<<":
            out.append(" <<< ")
            i += 3
            continue
        out.append(c)
        i += 1
    return "".join(out)


def strip_redirections(text, targets=None):
    """Remove shell redirections (operator + target) so the command word cannot hide behind one:
    `</dev/null rm -rf /`, `rm</dev/null -rf /`, `git>out push …`, `rm >&2 -rf /`, `rm &>/dev/null
    -rf /` (Codex #26 r5/r8 F1). Runs on the WHOLE command before pipeline splitting, so `&` inside
    `>&`/`&>` is stripped before `split_pipelines` could mistake it for a separator. Quote-aware.
    `<<<` is left for the herestring path; `<(`/`>(` are already extracted before this runs; the
    real `&&`/`;`/`&`/`|` separators are preserved (only `&` immediately before `>` is a redirect).

    When `targets` is a list, each stripped FILENAME target is appended to it (fd-dup forms like
    `>&1` have no filename and contribute nothing). The caller resolves expansion-built targets and
    re-checks them for raw-device writes the literal text never names (Codex #26 r53 F4)."""
    out, i, n = [], 0, len(text)
    in_sq = in_dq = False
    while i < n:
        c = text[i]
        if in_sq:
            out.append(c)
            if c == "'":
                in_sq = False
            i += 1
            continue
        if in_dq:
            out.append(c)
            if c == '"':
                in_dq = False
            i += 1
            continue
        if c == "'":
            in_sq = True
            out.append(c)
            i += 1
            continue
        if c == '"':
            in_dq = True
            out.append(c)
            i += 1
            continue
        if text[i:i + 3] == "<<<":            # herestring: leave for shell_script_arg
            out.append("<<<")
            i += 3
            continue
        is_amp_redir = c == "&" and text[i + 1:i + 2] == ">"   # `&>` / `&>>` (stdout+stderr)
        if c in "<>" or is_amp_redir:
            if c in "<>":
                # Drop a standalone leading fd (`2` in `2>&1`, `cmd 2>f`) but keep digits that
                # belong to a word (`file2>out` → word `file2`, redirect `>out`).
                k = len(out) - 1
                while k >= 0 and out[k].isdigit():
                    k -= 1
                if k < len(out) - 1 and (k < 0 or out[k] in " \t\r\n|;&("):
                    del out[k + 1:]
            # The guard above guarantees one of these matches (`<`/`>` cover the single-char case,
            # `&>` the amp form), but default to the single char rather than leaving `op` None:
            # a None here would raise inside the parser and silently demote the verdict to FALLBACK.
            op = next((cand for cand in ("&>>", "&>", ">>", ">|", "<>", "<&", ">&", "<", ">")
                       if text.startswith(cand, i)), c)
            i += len(op)
            while i < n and text[i] in " \t":
                i += 1
            if i < n and text[i] == "&":       # dup form: >&1, <&-, >&-
                i += 1
                while i < n and (text[i].isdigit() or text[i] == "-"):
                    i += 1
            else:
                tstart = i
                tsq = tdq = False
                while i < n:
                    cc = text[i]
                    if tsq:
                        if cc == "'":
                            tsq = False
                    elif tdq:
                        if cc == '"':
                            tdq = False
                    elif cc == "'":
                        tsq = True
                    elif cc == '"':
                        tdq = True
                    elif cc in " \t\r\n|;&<>()":
                        # A newline ENDS the target. Omitting it let a target at end-of-line consume
                        # the separator and the next line's command word — `echo hi > f.txt\nrm -rf /`
                        # became `echo hi     -rf /` and was allowed (Codex #26 r15 self-audit).
                        break
                    i += 1
                if targets is not None and i > tstart:
                    targets.append(text[tstart:i])
            out.append(" ")
            continue
        out.append(c)
        i += 1
    return "".join(out)


def split_pipelines(text, seps=None):
    """Split on unquoted ; && || & newline into pipelines, then each on unquoted | into stages. When
    `seps` is a list, it receives the SEPARATOR PRECEDING each returned pipeline ('' for the first,
    else '&&'/'||'/';'/newline/'&') — the caller uses `&&`/`||` to distinguish a CONDITIONALLY-executed
    statement from a sequential one (Codex #26 r60 F1)."""
    pipelines, stages, cur = [], [], []
    in_sq = in_dq = False
    i, n = 0, len(text)
    pending = [""]

    def end_stage():
        stages.append("".join(cur))
        del cur[:]

    def end_pipeline(sep_after=""):
        end_stage()
        pipelines.append(list(stages))
        if seps is not None:
            seps.append(pending[0])
        pending[0] = sep_after
        del stages[:]

    while i < n:
        c = text[i]
        if in_sq:
            cur.append(c)
            if c == "'":
                in_sq = False
            i += 1
            continue
        if in_dq:
            cur.append(c)
            if c == '"':
                in_dq = False
            i += 1
            continue
        if c == "'":
            in_sq = True
            cur.append(c)
            i += 1
            continue
        if c == '"':
            in_dq = True
            cur.append(c)
            i += 1
            continue
        if text[i:i + 2] in ("&&", "||"):
            end_pipeline(text[i:i + 2])
            i += 2
            continue
        # `|&` pipes stdout+stderr into the next stage (bash shorthand for `2>&1 |`); it is a stage
        # separator, not `|` + background. Must precede the bare `&` and `|` checks (Codex #26 r5).
        if text[i:i + 2] == "|&":
            end_stage()
            i += 2
            continue
        if c in (";", "\n", "&"):
            end_pipeline(c)
            i += 1
            continue
        if c == "|":
            end_stage()
            i += 1
            continue
        cur.append(c)
        i += 1
    end_pipeline()
    return [[s for s in p if s.strip()] for p in pipelines]


def pipeline_conditionality(pipelines, seps):
    """Which pipelines are CONDITIONALLY executed — reached only through `&&`/`||` short-circuiting or
    an `if`/`while`/`until`/`for`/`case` BODY (`then`/`do`/`else`/`elif` … `fi`/`done`/`esac`). A
    conditional assignment may not run, so recording it as unconditional let a benign value mask a
    dangerous one the shell actually keeps: `d=/; true || d=./build; rm -rf $d` runs `rm -rf /`, and
    `d=/; if false; then d=./build; fi; rm -rf $d` too (Codex #26 r60 F1). Body tracking is a simple
    `then`/`do`/`case`-open, `fi`/`done`/`esac`-close counter — the CONDITION part of the construct
    (`if COND`, `while COND`) runs and stays unconditional; only the body is guarded."""
    cond, body_depth = [], 0
    for k, pl in enumerate(pipelines):
        first = ""
        for stage in pl:
            parts = stage.split()
            if parts:
                first = parts[0]
                break
        opener = first in ("then", "do", "case")
        closer = first in ("fi", "done", "esac")
        is_cond = (seps[k] in ("&&", "||")) or body_depth > 0 or opener or first in ("else", "elif")
        if opener:
            body_depth += 1
        elif closer:
            body_depth = max(0, body_depth - 1)
            is_cond = body_depth > 0
        cond.append(is_cond)
    return cond


def strip_wrapper_options(tokens, wrapper):
    """Drop a wrapper's options AND the operands they consume, so the operand can never land in
    command position."""
    operand_opts = WRAPPER_OPERAND_OPTS.get(wrapper, set())
    while tokens:
        tok = tokens[0]
        if ASSIGN_RE.match(tok):
            tokens = tokens[1:]
            continue
        # `--` ends option parsing; everything after it is the wrapped command, not an operand to
        # drop. Treating `--` as the command word let `env -- rm -rf /` resolve to "--" (Codex #26 F1).
        if tok == "--":
            return tokens[1:]
        if not tok.startswith("-") or tok == "-":
            break
        base = tok.split("=", 1)[0]
        tokens = tokens[1:]
        if base in operand_opts and "=" not in tok and tokens:
            tokens = tokens[1:]
    return tokens


# Positional-parameter references bash expands from the argv: `$N`/`${N}` (multi-digit), `$@`/`$*`/
# `${@}`/`${*}`, and slices `${@:k}` / `${@:k:n}` (Codex #26 r10/r13 F3).
POSITIONAL_RE = re.compile(r'"?\$\{?(?:([@*])(?::(\d+)(?::(\d+))?)?|(\d+))\}?"?')

# An implicit `for NAME; do …` / `for NAME do …` (no `in` list) iterates the POSITIONAL parameters
# ($@), so a `-c`/heredoc script whose argv is bound runs the body once per arg: `bash -c 'for d; do
# rm -rf $d; done' _ /` runs `rm -rf /` (Codex #26 r68 F1). Rewrite it to the explicit `for NAME in
# "$@"` so the argv substitution below binds the loop variable. This is NOT the `set -- … "$@"`
# boundary (which sets $@ at RUNTIME) — the argv here is passed literally and is statically resolvable.
IMPLICIT_FOR_RE = re.compile(r'(?<![\w./-])for\s+([A-Za-z_][A-Za-z0-9_]*)(?=\s*(?:;|\n|do\b))')


def substitute_positional(script, argv):
    """Substitute positional parameters in a `-c`/heredoc script with the literal argv bash assigns
    to them, so `bash -c 'rm "$@"' _ -rf /` and `${10}`/`${@:2}` are visible to the scan. argv[0] is
    $0; $@/$* join argv[1:]. The args are literal in the command, so this is a static substitution,
    not runtime evaluation. An implicit positional `for` is first made explicit so its loop variable
    binds the argv too (Codex #26 r68 F1)."""

    def _implicit_for(m):
        # The bare `for NAME do …` form has no separator before `do`; inserting the explicit list
        # right there needs a `;` so the result stays valid (`for NAME in "$@"; do …`).
        sep = ";" if re.match(r"\s*do\b", m.string[m.end():]) else ""
        return 'for %s in "$@"%s' % (m.group(1), sep)

    script = IMPLICIT_FOR_RE.sub(_implicit_for, script)

    def repl(m):
        start, length, num = m.group(2), m.group(3), m.group(4)
        if num is not None:
            idx = int(num)
            return argv[idx] if idx < len(argv) else ""
        if start is None:
            return " ".join(argv[1:])
        s = int(start)
        if length is not None:
            return " ".join(argv[s:s + int(length)])
        return " ".join(argv[s:])

    return POSITIONAL_RE.sub(repl, script)


SHELL_OPT_WITH_OPERAND = ("-o", "+o", "-O", "+O", "--rcfile", "--init-file")


def shell_operand_argv(tokens):
    """The positional params ($1,$2,…) a shell invocation exposes to its stdin/herestring script:
    the operands after option processing and an optional `--`, up to a herestring operator. tokens[0]
    is the shell. `bash -s -- -rf /` → `['-rf', '/']` — note a `--` makes even `-rf` an operand, not
    an option (Codex #26 r35). Stops at `<<<` so the herestring's own operand is not counted."""
    k, n = 1, len(tokens)
    while k < n:
        tok = tokens[k]
        if tok == "--":
            k += 1
            break
        if tok in SHELL_OPT_WITH_OPERAND:
            k += 2
            continue
        if tok.startswith("-") or tok.startswith("+"):
            k += 1
            continue
        break
    argv = []
    while k < n:
        tok = tokens[k]
        if tok == "<<<" or tok.startswith("<<<"):
            break
        argv.append(tok)
        k += 1
    return argv


_STMT_SEP_RE = re.compile(r"\|\||&&|;|&(?!>)|(?<!>)(?<!&)\|(?!\|)")


def procsub_stdin_shell_argv(redacted, n):
    """If `< __SUBn__` redirects a process substitution into a SHELL reading stdin, return that
    shell's positional argv (WITHOUT the $0 placeholder); else None. `bash -s -- -rf / < <(printf
    …)` — the shell runs the substitution's output with $@ = its operands (Codex #26 r35 F2)."""
    ph = "__SUB%d__" % n
    m = re.search(r"<\s*" + re.escape(ph), redacted)
    if not m:
        return None
    starts = [x.end() for x in _STMT_SEP_RE.finditer(redacted) if x.end() <= m.start()]
    ends = [x.start() for x in _STMT_SEP_RE.finditer(redacted) if x.start() > m.start()]
    seg = redacted[(max(starts) if starts else 0):(min(ends) if ends else len(redacted))]
    try:
        toks = shlex.split(strip_redirections(seg.replace(ph, " ")), posix=True)
    except ValueError:
        return None
    for idx, tok in enumerate(toks):
        if tok.rsplit("/", 1)[-1] in SHELLS:
            return shell_operand_argv(toks[idx:])
    return None


def procsub_script_argv(redacted, n):
    """When input process substitution `__SUBn__` is the SCRIPT-FILE argument of a consumer that
    EXECUTES that file's content, return a descriptor of how to scan the substitution's OUTPUT:
      ('shell', argv)  — scan the output as a shell script, `argv` bound to $@ ($0 placeholder first);
                         covers bash/sh/zsh/dash/ksh and `source`.
      ('interp', base) — scan the output as `base`'s interpreter program (`python3`, `perl`, …).
    Else None. The `< __SUBn__` STDIN-redirect form is procsub_stdin_shell_argv's, not this; a
    substitution that is only a positional arg to some OTHER script is excluded — `bash deploy.sh
    <(…)` runs deploy.sh with the procsub as $1, so the procsub is DATA, not the script (verified).
    The substitution's own command (printf) was scanned already; its OUTPUT is the script a split
    literal hides from the legacy matcher — the same printf reassembly the `printf … | sh`,
    `bash -c "$(printf …)"`, and `bash -s < <(printf …)` paths already model (Codex #26 r36 F2)."""
    ph = "__SUB%d__" % n
    # A bare-argument placeholder has no `<`/`>` before it; `command < <(…)` (stdin) is handled elsewhere.
    if re.search(r"[<>]\s*" + re.escape(ph), redacted):
        return None
    m = re.search(re.escape(ph), redacted)
    if not m:
        return None
    starts = [x.end() for x in _STMT_SEP_RE.finditer(redacted) if x.end() <= m.start()]
    ends = [x.start() for x in _STMT_SEP_RE.finditer(redacted) if x.start() > m.start()]
    seg = redacted[(max(starts) if starts else 0):(min(ends) if ends else len(redacted))]
    try:
        toks = shlex.split(strip_redirections(seg), posix=True)
    except ValueError:
        return None
    resolved = command_head_and_args(toks)
    if resolved is None:
        return None
    base, cargs = resolved
    if base in PROCSUB_FILE_EXEC_CMDS and base not in SHELLS and base not in ("source", ".") \
            and procsub_program_file(base, cargs, ph):
        # make/awk read the procsub as executable TEXT (a Makefile recipe / an awk program), not shell
        # or a `-c`/positional interpreter script — so the shell/interp branches below never catch them.
        # Scan its OUTPUT as an interpreter program: interpreter_program_is_dangerous strips quotes,
        # catching both an unquoted make recipe (`\trm -rf /`) and a quoted awk `system("rm -rf /")`
        # from a producer-assembled split literal (Codex #26 r55 F1). Checked AHEAD of the whole-token
        # guards below because make/awk may ATTACH the procsub to `-f` (`make -f<(…)` → the placeholder
        # is a SUBSTRING of the `-f__SUBn__` token, not its own word). awk is excluded from
        # interpreter_script_file (its `-f` handling is bespoke), so it is routed here explicitly.
        return ("interp", base)
    if ph not in toks:
        return None
    if ph not in cargs:                 # the placeholder must be an ARGUMENT, not the command word
        return None
    if base in SHELLS or base in ("source", "."):
        # A `-c`/herestring shell runs a DIFFERENT script; the procsub is not the executed text.
        if shell_script_arg([base] + cargs) is not None:
            return None
        operands = shell_operand_argv([base] + cargs)
        # The SCRIPT FILE is the FIRST operand; when the procsub is a later operand it is $1.. DATA
        # (`bash deploy.sh <(…)`), so require it to be first.
        if not operands or operands[0] != ph:
            return None
        return ("shell", ["_"] + operands[1:])
    if INTERP_CMD_RE.match(base) and interpreter_script_file(base, cargs) == ph:
        return ("interp", base)
    return None


def shell_reads_stdin_script(head, args):
    """True if a shell/source invocation executes its STDIN as the script, so a heredoc / herestring /
    pipe feeding it is a SCRIPT (not data). A real shell runs stdin iff it has no `-c` AND no
    script-file operand — `bash`, `bash -x`, `bash -s` (which forces stdin even with operands) — but
    NOT `bash deploy.sh`, which runs the FILE and reads stdin as that file's DATA. `source`/`.` run
    their operand FILE unless it is a /dev/stdin-like path. `args` may still carry `<<`/`<<<` redirect
    tokens (redirections are otherwise stripped upstream); those are not script-file operands (Codex
    #26 r51 F1, same class as r36 F2 / r25 F2 for interpreters)."""
    def is_redirect(t):
        return t.startswith(("<", ">")) or (t[:1].isdigit() and (">" in t or "<" in t))

    if head in ("source", "."):
        for a in args:
            if a == "--" or a.startswith(("-", "+")) or is_redirect(a):
                continue
            return a in ("/dev/stdin", "/dev/fd/0", "-")
        return False
    saw_s = False
    k = 0
    while k < len(args):
        tok = args[k]
        if tok == "--":
            k += 1
            break
        if tok in SHELL_OPT_WITH_OPERAND:
            k += 2
            continue
        if DASH_C_RE.match(tok):
            return False          # -c runs its script argument, not stdin
        if tok.startswith("-") or tok.startswith("+"):
            if "s" in tok.lstrip("-+"):
                saw_s = True       # bash -s reads stdin as the script even with operands ($@)
            k += 1
            continue
        break
    if saw_s:
        return True
    while k < len(args):
        tok = args[k]
        if tok == "<<<":
            k += 2                  # bare herestring operator + its content token
            continue
        if is_redirect(tok):
            k += 1
            continue
        # A script-file operand that IS stdin (`bash /dev/stdin <<EOF`, `sh /dev/fd/0`, `bash -`) runs
        # the heredoc/pipe body AS the script — the operand resolves to the shell's own stdin (Codex
        # #26 r62 F2). An ordinary file operand runs the FILE and reads stdin as that file's data.
        return tok in ("/dev/stdin", "/dev/fd/0", "-")
    return True


def shell_script_arg(tokens):
    """For a shell invocation, return (script, positional_argv) — the script it executes plus the
    argv bash assigns to $1,$2,… — or None. The caller substitutes positional params in the script
    from that argv (Codex #26 r10 F1). Handles a `-c` script and a herestring script; a script read
    from a pipe/redirected stdin is not in the tokens, so this returns None and the pipe-to-shell
    path supplies the argv there (Codex #26 r35 F2)."""
    k = 1
    while k < len(tokens):
        tok = tokens[k]
        if tok == "--":
            break
        if tok in SHELL_OPT_WITH_OPERAND:
            k += 2
            continue
        if DASH_C_RE.match(tok):
            return (tokens[k + 1], tokens[k + 2:]) if k + 1 < len(tokens) else None
        if tok.startswith("-"):
            k += 1
            continue
        break
    # No `-c`. A herestring's script is its operand, and the positional argv is the operands BEFORE
    # it — `bash -s -- -rf / <<< 'rm "$@"'` gives the script `-rf /` as $@ (Codex #26 r35 F1). The
    # old code returned the tokens AFTER `<<<` as argv, which was empty here. But a shell running a
    # SCRIPT FILE reads the herestring as that file's DATA, not its script (`bash deploy.sh <<< '…'`
    # runs deploy.sh — Codex #26 r51 F1), so there is no shell script here.
    if not shell_reads_stdin_script(tokens[0].rsplit("/", 1)[-1], tokens[1:]):
        return None
    for j, tok in enumerate(tokens[1:], start=1):
        # For `-s`/herestring the operands are $1.. and $0 is the shell — prepend a $0 placeholder,
        # unlike `-c` where the first operand IS $0 (verified against bash — Codex #26 r35 F1).
        if tok == "<<<":
            script = tokens[j + 1] if j + 1 < len(tokens) else ""
            return (script, ["_"] + shell_operand_argv(tokens[:j]))
        if tok.startswith("<<<"):
            return (tok[3:], ["_"] + shell_operand_argv(tokens[:j]))
    return None


def dash_c_operands(tokens):
    """For a shell invocation carrying a `-c SCRIPT`, return (script, operands-after-script); else
    None. Unlike shell_script_arg this is `-c`-ONLY (it returns None for a herestring script), so a
    caller can treat a printer's piped words as the script's positional params ONLY where xargs can
    actually append them — a herestring OVERRIDES stdin, so nothing is appended to it. tokens[0] is
    the shell (Codex #26 r49 F1)."""
    k = 1
    while k < len(tokens):
        tok = tokens[k]
        if tok == "--":
            return None
        if tok in SHELL_OPT_WITH_OPERAND:
            k += 2
            continue
        if DASH_C_RE.match(tok):
            return (tokens[k + 1], tokens[k + 2:]) if k + 1 < len(tokens) else None
        if tok.startswith("-"):
            k += 1
            continue
        return None
    return None


def strip_leading_prefixes(tokens):
    """Drop leading assignments and command-runner wrappers (`xargs`, `env`, `sudo`, `nice`,
    `timeout`, …) to surface a stage's underlying command tokens — MIRRORS resolve()'s wrapper
    front-end, used where the pipeline needs the real command of a stage that resolve() otherwise
    consumes (Codex #26 r49). A weaker subset missed `timeout`'s duration, `nice`/`taskset`/`chrt`'s
    positional operand, and `env -S`'s string split, so a wrapped `xargs` was never surfaced and its
    delimiter never applied (Codex #26 r67 F2)."""
    tokens = list(tokens)
    guard = 0
    while tokens and guard < 4 * MAX_DEPTH:
        guard += 1
        head = tokens[0]
        if ASSIGN_RE.match(head):
            tokens = tokens[1:]
            continue
        base = head.rsplit("/", 1)[-1]
        if base == "timeout":
            tokens = strip_wrapper_options(tokens[1:], "timeout")
            tokens = tokens[1:]  # the DURATION operand
            continue
        if base == "env":
            env_tokens = env_split_tokens(tokens[1:])
            if env_tokens is not None:
                tokens = env_tokens
                continue
            tokens = strip_wrapper_options(tokens[1:], "env")
            continue
        if base in POSITIONAL_NUM_WRAPPERS:
            tokens = strip_wrapper_options(tokens[1:], base)
            while tokens and NUM_OPERAND_RE.match(tokens[0]):
                tokens = tokens[1:]
            continue
        if base in PREFIXES:
            tokens = strip_wrapper_options(tokens[1:], base)
            continue
        break
    return tokens


def xargs_replace_token(prefix_tokens):
    """The `{}` replacement string an `xargs` invocation uses, or None for default append mode.
    `-I TOK` / `-ITOK` / `--replace TOK` / `--replace=TOK` set it; `-i` / `--replace` (no operand)
    default it to `{}`. Scans only AFTER `xargs` so a wrapper's own `-i` (`sudo -i xargs …`) is not
    mistaken for it, and skips operand-taking options so a later `-I` is still found (Codex #26 r50 F1)."""
    j = 0
    n = len(prefix_tokens)
    while j < n and prefix_tokens[j].rsplit("/", 1)[-1] != "xargs":
        j += 1
    j += 1
    opset = WRAPPER_OPERAND_OPTS.get("xargs", set())
    while j < n:
        t = prefix_tokens[j]
        if t == "--" or not t.startswith("-"):
            break
        base = t.split("=", 1)[0]
        # `-I` takes a SEPARATE (or attached) operand; `--replace`/`-i` take only an ATTACHED optional
        # one (`--replace=R`, `-iR`) and otherwise default to `{}` — so neither consumes the following
        # child-command token (Codex #26 r50 F1).
        if t == "-I":
            return prefix_tokens[j + 1] if j + 1 < n else "{}"
        if t.startswith("-I") and len(t) > 2:
            return t[2:]
        if t == "--replace":
            return "{}"
        if base == "--replace" and "=" in t:
            return t.split("=", 1)[1]
        if t == "-i":
            return "{}"
        if t.startswith("-i") and len(t) > 2 and t[2] != "-":
            return t[2:]
        j += 1
        if base in opset and "=" not in t and j < n:
            j += 1
    return None


def xargs_delimiter(prefix_tokens):
    """The stdin field delimiter an `xargs` invocation sets, or None for the default (split on blanks
    and newlines). `-0` / `--null` → NUL; `-d C` / `-dC` / `--delimiter C` / `--delimiter=C` → that
    (C-escape-decoded) char. A custom delimiter is what lets a producer smuggle a bare `/` past the
    default whitespace split — `printf '/X' | xargs -d X rm -rf` runs `rm -rf /` (Codex #26 r66 F1).
    Scans only AFTER `xargs` so a wrapper's own option is not mistaken for it, and skips operand-taking
    options so a `-d` after another value option is still found."""
    j = 0
    n = len(prefix_tokens)
    while j < n and prefix_tokens[j].rsplit("/", 1)[-1] != "xargs":
        j += 1
    j += 1
    opset = WRAPPER_OPERAND_OPTS.get("xargs", set())
    while j < n:
        t = prefix_tokens[j]
        if t == "--" or not t.startswith("-"):
            break
        if t in ("-0", "--null"):
            return "\0"
        if t in ("-d", "--delimiter"):
            return _xargs_decode_delim(prefix_tokens[j + 1]) if j + 1 < n else None
        if t.startswith("-d") and len(t) > 2:
            return _xargs_decode_delim(t[2:])
        if t.startswith("--delimiter="):
            return _xargs_decode_delim(t.split("=", 1)[1])
        base = t.split("=", 1)[0]
        j += 1
        if base in opset and "=" not in t and j < n:
            j += 1
    return None


def _xargs_decode_delim(s):
    """xargs `-d` takes ONE delimiter character, C-escapes allowed (`\\n`, `\\t`, `\\0`). Returns a
    single-character separator, or None when it decodes to empty (str.split rejects '')."""
    dec = decode_c_escapes(s)
    return dec[0] if dec else None


def xargs_fields(produced, delim):
    """The argv fields `xargs` appends from its stdin, honouring the input delimiter: the default
    splits on blanks+newlines; `-d`/`-0` split on the chosen delimiter, which can re-form a bare `/`
    the whitespace split would miss (`printf '/X' | xargs -d X rm -rf` — Codex #26 r66 F1)."""
    return produced.split(delim) if delim else produced.split()


def xargs_stage_info(tokens):
    """If a pipeline stage runs `xargs` — even behind wrappers (`timeout`/`nice`/`sudo`) or an
    `env -S` string split — return (child_tokens, delimiter, replace_token, arg_file); else None.
    Unwraps the same way resolve() does, so a WRAPPED xargs surfaces its options (a slice of the raw
    input could not, because `env -S` EXPANDS its string into more tokens — Codex #26 r67 F2). The
    delimiter/replace-token are read from the xargs invocation, and `arg_file` is its `-a`/`--arg-file`
    input source when it reads from a file instead of stdin (Codex #26 r67 F3)."""
    tokens = list(tokens)
    guard = 0
    saw_xargs = False
    delim = replace = arg_file = None
    while tokens and guard < 4 * MAX_DEPTH:
        guard += 1
        head = tokens[0]
        if ASSIGN_RE.match(head):
            tokens = tokens[1:]
            continue
        base = head.rsplit("/", 1)[-1]
        if base == "timeout":
            tokens = strip_wrapper_options(tokens[1:], "timeout")
            tokens = tokens[1:]
            continue
        if base == "env":
            env_tokens = env_split_tokens(tokens[1:])
            if env_tokens is not None:
                tokens = env_tokens
                continue
            tokens = strip_wrapper_options(tokens[1:], "env")
            continue
        if base in POSITIONAL_NUM_WRAPPERS:
            tokens = strip_wrapper_options(tokens[1:], base)
            while tokens and NUM_OPERAND_RE.match(tokens[0]):
                tokens = tokens[1:]
            continue
        if base == "xargs":
            saw_xargs = True
            delim = xargs_delimiter(tokens)
            replace = xargs_replace_token(tokens)
            arg_file = xargs_arg_file(tokens)
            tokens = strip_wrapper_options(tokens[1:], "xargs")
            continue
        if base in PREFIXES:
            tokens = strip_wrapper_options(tokens[1:], base)
            continue
        break
    return (tokens, delim, replace, arg_file) if saw_xargs else None


def xargs_arg_file(prefix_tokens):
    """The `-a FILE` / `--arg-file=FILE` input source of an xargs invocation, or None (reads stdin).
    xargs `-a` reads its items from FILE instead of stdin, so a process substitution there feeds the
    child — `xargs -a <(printf /) rm -rf` runs `rm -rf /` (Codex #26 r67 F3)."""
    j = 0
    n = len(prefix_tokens)
    while j < n and prefix_tokens[j].rsplit("/", 1)[-1] != "xargs":
        j += 1
    j += 1
    opset = WRAPPER_OPERAND_OPTS.get("xargs", set())
    while j < n:
        t = prefix_tokens[j]
        if t == "--" or not t.startswith("-"):
            break
        if t in ("-a", "--arg-file"):
            return prefix_tokens[j + 1] if j + 1 < n else None
        if t.startswith("-a") and len(t) > 2:
            return t[2:]
        if t.startswith("--arg-file="):
            return t.split("=", 1)[1]
        base = t.split("=", 1)[0]
        j += 1
        if base in opset and "=" not in t and j < n:
            j += 1
    return None


def procsub_output(token, subs):
    """The statically-known OUTPUT of a `__SUBn__` placeholder standing for a process/command
    substitution — `<(printf /)` prints `/`. Returns None when the token is not a placeholder or its
    producer's output is not statically knowable."""
    m = re.fullmatch(r"__SUB(\d+)__", token or "")
    if not m:
        return None
    idx = int(m.group(1)) - 1
    if 0 <= idx < len(subs):
        return sub_output_text(subs[idx])
    return None


def xargs_child_dangerous(sh_toks, delim, token, produced, depth, subs, assigns):
    """Whether an `xargs` child command, fed `produced` as its input items (delimiter-split), runs
    something destructive. Covers `-I{}` replace mode, a `sh -c "$@"` append, and a plain-command
    append (`rm -rf` / any CMD_RE hit). Shared by the pipe-fed and `-a`/`--arg-file` input paths so
    both honour the delimiter and the wrapper unwrapping (Codex #26 r66/r67)."""
    if not produced:
        return False
    if token is not None:
        items = produced.split(delim) if delim else [ln for ln in produced.split("\n") if ln]
        for line in items or [produced]:
            subbed = [t.replace(token, line) for t in sh_toks]
            if scan(" ".join(shlex.quote(t) for t in subbed), depth + 1):
                return True
        return False
    if sh_toks and sh_toks[0].rsplit("/", 1)[-1] in SHELLS:
        dc = dash_c_operands(sh_toks)
        if dc is not None and dc[0]:
            _script, _trailing = dc
            if scan_executed(substitute_positional(unescape_dollar(_script),
                                                   _trailing + xargs_fields(produced, delim)), depth):
                return True
        return False
    if sh_toks:
        base = sh_toks[0].rsplit("/", 1)[-1]
        cargs = [w for a in sh_toks[1:] for w in resolve_arg_words(a, subs, assigns)]
        fields = xargs_fields(produced, delim)
        if base == "rm" and rm_is_destructive("rm", cargs + fields):
            return True
        if CMD_RE.search(" ".join([base] + cargs + fields)):
            return True
    return False


# env options that consume a SEPARATE operand — skipped when scanning for -S so their operand is
# not mistaken for env's command word.
ENV_OPT_OPERAND = {"-u", "--unset", "-C", "--chdir", "-P"}


def env_split_tokens(args):
    """env `-S`/`--split-string` word-splits its string operand and then appends the argv that
    FOLLOWS it, each following arg kept as its OWN word — `env -S "bash -c" "rm -rf /"` runs
    `bash -c` with the script "rm -rf /" (one arg), so flattening the trailing argv into a string
    would lose that boundary (Codex #26 r8 F2). Only env's OWN options carry `-S`; once env reaches
    `--` or its command word, a later `-S` is the child command's data (`env echo -S "rm -rf /"`
    just prints it — Codex #26 r7 F2). Returns the composed token list, or None when there is no
    split-string option."""
    i = 0
    while i < len(args):
        tok = args[i]
        if tok == "--":
            return None
        split_str, trailing = None, []
        if tok in ("-S", "--split-string"):
            split_str = args[i + 1] if i + 1 < len(args) else ""
            trailing = args[i + 2:]
        elif tok.startswith("--split-string="):
            split_str = tok.split("=", 1)[1]
            trailing = args[i + 1:]
        elif (tok.startswith("-") and not tok.startswith("--") and "S" in tok[1:]
                and not any(c in "uCP" for c in tok[1:tok.index("S", 1)])):
            # A short-option CLUSTER carrying `S` also splits: `env -iS 'rm -rf /'` is `-i -S`, and
            # `-S` consumes either the rest of its own token or the next arg (Codex #26 r15b F3). Only
            # the operand-consuming env flags (`-u`, `-C`, `-P`) may NOT precede `S` — for those, the
            # `S` would be part of that flag's operand (`-Csomedir`). Any other prefix (`-i`, `-v`, an
            # unknown flag) treats `S` as the split option, which is the fail-safe reading.
            after = tok[tok.index("S", 1) + 1:]
            if after:
                split_str, trailing = after, args[i + 1:]
            else:
                split_str = args[i + 1] if i + 1 < len(args) else ""
                trailing = args[i + 2:]
        if split_str is not None:
            try:
                words = shlex.split(split_str, posix=True)
            except ValueError:
                words = split_str.split()
            return words + list(trailing)
        if ASSIGN_RE.match(tok):
            i += 1
            continue
        if tok in ENV_OPT_OPERAND:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        return None  # env's command word — options (and any -S) have ended
    return None




# `export`/`declare`/`readonly`/`typeset`/`local` set ordinary shell state, so `export d=/; rm -rf $d`
# deletes the root — but the recorder only accepted bare `name=value` tokens (Codex #26 r30 F3).
DECL_BUILTINS = {"export", "declare", "readonly", "typeset", "local"}
ARRAY_ASSIGN_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=\((.*)$")


class ArrayValue(list):
    """An array assignment (`a=(/)`), so `${a[0]}` / `${a[@]}` resolve to elements rather than to
    the literal text `(/)` (self-audit, r30 sweep)."""

    def scalar(self):
        return self[0] if self else ""


# Reserved words that INTRODUCE a same-shell context, so an assignment right after them persists in
# the current shell: `if d=/; then …`, `{ d=/; }`, `while d=/; do …`, `! d=/`. NOT `(` (a subshell —
# the assignment is local to it, `(d=/); rm -rf $d` leaves `d` unset) and NOT `for` (handled below by
# its variable binding). (Codex #26 r41 F2 — verified against bash.)
ASSIGN_LEADING_RESERVED = {"if", "then", "elif", "else", "while", "until", "do", "{", "!"}


def record_assignments(tokens, assigns, subs, conditional=False):
    """Record a statement's assignments so a later `$name` can be resolved back to its literal.
    shlex has already removed the quoting, so `c='rm -rf /'` stores `rm -rf /`.

    `conditional` (the statement is reached only via `&&`/`||` or an if/while/for/case body) applies
    the FAIL-SAFE merge below: a conditional assignment may not run, so it must not overwrite an
    existing DANGEROUS value with a benign one (Codex #26 r60 F1).

    Only an ASSIGNMENT-ONLY statement updates the shell's variables. A command-local assignment
    (`d=./dist rm -rf $d`) sets the variable for the command's ENVIRONMENT only, and bash expands the
    command's own arguments BEFORE applying it — verified: `d=/tmp; d=/etc echo $d` prints `/tmp`.
    Recording it would have masked the previous value and let `d=/; d=./dist rm -rf $d` delete the
    root (Codex #26 r30 F1). A leading declaration builtin — with its options — is still an
    assignment statement (`declare -x d=/`; self-audit, r30 sweep). A same-shell control construct
    (`if`/`{`/`while`/…) does not stop the binding after it from persisting, and a `for` loop binds
    its variable to each `in` word in the current shell (Codex #26 r41 F2)."""
    words = tokens
    # `for VAR in WORD…; do … $VAR …` binds VAR to each word in the CURRENT shell, so a dangerous word
    # reaches the body: `for d in /; do rm -rf $d; done`. The body runs once per word, so record VAR to
    # a dangerous-looking word if any (else the first) — the resolved arg check then sees the target.
    if len(words) >= 2 and words[0] == "for":
        var = words[1]
        if "in" in words[2:]:
            vals = [resolve_assignment_value(v, subs, assigns)
                    for v in words[words.index("in", 2) + 1:]]
            vals = [v for v in vals if v]
            if vals:
                # Prefer any dangerous word — a later iteration binds `d` to it and the body runs then:
                # `for d in ./build /tmp/..; do rm -rf $d; done` wipes root on the SECOND pass, so match
                # a `..`-normalized wipe too, not only a literal RM_TARGET_RE (Codex #26 r61 F1).
                assigns[var] = next((v for v in vals if is_wipe_target(v)), vals[0])
        return
    while words and words[0] in ASSIGN_LEADING_RESERVED:
        words = words[1:]
    if words and words[0] in DECL_BUILTINS:
        words = words[1:]
        while words and words[0].startswith("-"):
            # `-f`/`-F` name FUNCTIONS and `-p` PRINTS — none assigns a variable, so `export -f d=/`
            # and `declare -p d=/` leave `d` unset (verified). Recording them was a false positive
            # (Codex #26 r34 F3). Other flags (`-x`, `-i`, `-r`, …) do assign.
            if any(c in words[0][1:] for c in "fFp"):
                return
            words = words[1:]
    parsed = parse_assignments(words, subs, assigns)
    if parsed:
        if conditional:
            # A conditional assignment may not run, so keep an existing dangerous rm-target rather than
            # clear it with a benign value; a NEW dangerous value still applies (over-approximate toward
            # danger — the fail-safe direction). A benign→benign or absent-old case overwrites normally.
            for name, newval in parsed.items():
                if is_wipe_target(assigns.get(name)) and not is_wipe_target(newval):
                    continue
                assigns[name] = newval
        else:
            assigns.update(parsed)


def parse_assignments(words, subs, assigns):
    """Parse an assignment-ONLY statement into name → value, or return None. Array literals are
    reassembled across tokens, because shlex splits `a=( / )` into three (`a=(`, `/`, `)`) while
    `a=(/)` stays one — both assign the same array (self-audit, r30 sweep). Each value's expansions
    are resolved to what bash stores (`c=$(printf rm)` → `rm`) — Codex #26 r41 F1."""
    out, i = {}, 0
    while i < len(words):
        m = ARRAY_ASSIGN_RE.match(words[i])
        if m:
            name, rest, elems, closed = m.group(1), m.group(2), [], False
            if rest.endswith(")"):
                elems, closed, i = rest[:-1].split(), True, i + 1
            else:
                elems, i = rest.split(), i + 1
                while i < len(words):
                    word = words[i]
                    i += 1
                    if word.endswith(")"):
                        if word[:-1]:
                            elems.append(word[:-1])
                        closed = True
                        break
                    elems.append(word)
            if not closed:
                return None
            out[name] = ArrayValue([resolve_assignment_value(e, subs, assigns) for e in elems])
            continue
        if not ASSIGN_RE.match(words[i]):
            return None
        mp = APPEND_ASSIGN_RE.match(words[i])
        if mp:
            name, value = mp.group(1), mp.group(2)
            prev = scalar_of(assigns.get(name, out.get(name, "")))
            out[name] = prev + resolve_assignment_value(value, subs, assigns)
        else:
            name, _, value = words[i].partition("=")
            out[name] = resolve_assignment_value(value, subs, assigns)
        i += 1
    return out or None


UNRESOLVABLE_CMD_RE = re.compile(r"__SUB\d+__|\$")
SUB_ANY_RE = re.compile(r"__SUB(\d+)__")
VAR_ANY_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")
# `${a[0]}` / `${a[@]}` index an array; `${!v}` expands the variable NAMED by `v` (`v=d; d=/;
# rm -rf ${!v}` deletes the root). Both were left literal and matched nothing (self-audit, r30 sweep).
ARRAY_REF_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\[([^\]]*)\]\}")
VAR_INDIRECT_RE = re.compile(r"\$\{!([A-Za-z_][A-Za-z0-9_]*)\}")


def scalar_of(value):
    """Bash expands a bare `$a` on an array to its FIRST element."""
    return value.scalar() if isinstance(value, ArrayValue) else value
# `${var<op>WORD}` synthesizes a value, and WORD can be the dangerous target: `rm -rf ${d:-/}`
# deletes the root (self-audit, r27 sweep). The operators differ in ways that matter and were
# verified against bash (Codex #26 r30 F2) — a `:` makes NULL behave like UNSET, and `+` is the
# mirror image of `-`:
#
#     op    unset            set-but-null      set-and-non-null
#     -     WORD             value ("")        value
#     :-    WORD             WORD              value
#     =/:=  as -/:-
#     +     ""               WORD              WORD
#     :+    ""               ""                WORD
#
# Resolved before VAR_ANY_RE, which would otherwise consume the `${d` prefix and leave WORD behind
# as inert text.
VAR_DEFAULT_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(:?[-=+?])([^}]*)\}")


# Environment variables that are ALWAYS SET to a dangerous directory in a normal shell. A default
# expansion off one of them yields the directory, not the default: `${HOME:-/tmp}` is $HOME when
# HOME is set, so `rm -rf ${HOME:-/tmp}` wipes home (Codex #26 r34 F2). Treated as set-and-nonnull,
# with the literal `$NAME` as their value so the destructive-target regex catches it.
ALWAYS_SET_DIR_VARS = {"HOME": "$HOME", "PWD": "$PWD", "OLDPWD": "$OLDPWD"}

# IFS is set in every shell (default: space/tab/newline) even when never exported, and an UNQUOTED
# `$IFS` field-splits — bash breaks `rm -rf$IFS/` into `rm` `-rf` `/`, and `rm${IFS}-rf${IFS}/` the
# same, so the destructive argv reassembles from a token that holds no literal space (Codex #26 r65
# F1). Resolve it to a single space so the existing unquoted-expansion word-splitting reconstructs
# the argv; whitespace is the fail-safe approximation (a customised IFS is unknowable to a static
# hook, and an assigned IFS is honoured — the `in assigns` check wins). Only helps the destructive
# direction: an IFS split can only re-form a command that was already dangerous.
ALWAYS_SET_SPLIT_VARS = {"IFS": " "}


def expand_param_op(name, op, word, assigns):
    """Bash's parameter-expansion table above. A variable we never saw assigned is treated as UNSET
    for the `-`/`=` operators (which then yield WORD — the fail-safe direction), EXCEPT the
    always-set directory vars (HOME/PWD/OLDPWD), which yield their directory. For `+`/`:+` an unknown
    variable is treated as SET, again fail-safe: it may come from the environment (`rm -rf ${PWD:+/}`).
    `?`/`:?` error when unset/null and otherwise expand to the value."""
    known = name in assigns
    value = scalar_of(assigns.get(name, ""))
    if not known and name in ALWAYS_SET_DIR_VARS:
        known, value = True, ALWAYS_SET_DIR_VARS[name]
    if not known and name in ALWAYS_SET_SPLIT_VARS:
        known, value = True, ALWAYS_SET_SPLIT_VARS[name]
    if op in ("-", "="):
        return word if not known else value
    if op in (":-", ":="):
        return word if (not known or value == "") else value
    if op == "+":
        return word     # set (even null) → WORD; unknown assumed set
    if op == ":+":
        return "" if (known and value == "") else word
    if op in ("?", ":?"):
        # Errors (nothing runs) if unset/null; otherwise the value. We can only assert the value for
        # a known var — an unknown one either errors (safe) or is a runtime value we cannot predict.
        return value if known else ""
    return value

# Bash builds a command word by CONCATENATING adjacent fragments, so `$(printf r)$(printf m)`,
# `r$(printf m)`, and `a=r; b=m; $a$b` all resolve to `rm` — and none of them contains the literal
# anywhere in the text (Codex #26 r23 F2). When a word stays unresolvable we cannot know what it is,
# but we CAN ask whether its arguments would be destructive for any of the commands the patterns
# know about. `$(x) -rf /` is denied under this rule; `$(which ls) -la` is not.
#
# `mkfs`/`dd` are candidate heads only because r24 F4 narrowed their patterns to require a real
# device operand (`/dev/<disk>`). While `mkfs` matched "mkfs" followed by ANY word, using it as a
# candidate head denied every unresolvable command that took an argument — caught by probe, not by
# review. A dangerous `mkfs`/`dd` in the ARGV is caught regardless, because the argv is also tested
# against the patterns on its own.
HYPOTHETICAL_HEADS = ("rm", "chmod", "git", "mkfs", "dd")


def inline_command_word(cmd, args, subs, assigns):
    """Reconstruct the statement a statically-unresolvable command word would actually run, by
    replacing EVERY fragment of that word with the text it stands for: a command substitution's own
    source (`$(echo rm) -rf /` → `echo rm -rf /`), or a literal assignment's value (`c=rm; $c -rf /`
    → `rm -rf /`). Adjacent fragments concatenate, as bash does. Returns None when nothing in the
    word can be resolved (an unknown `$VAR`), leaving the caller's plain defer in charge.
    Documented boundary: a value computed at runtime (`c=$(…); $c`) stays unresolvable, exactly as
    in the sibling production-push hook."""
    resolved_any = False

    def sub_frag(m):
        nonlocal resolved_any
        idx = int(m.group(1)) - 1
        if 0 <= idx < len(subs):
            resolved_any = True
            return subs[idx]
        return m.group(0)

    def var_frag(m):
        nonlocal resolved_any
        name = m.group(1)
        if name in assigns:
            resolved_any = True
            return scalar_of(assigns[name])
        if name in ALWAYS_SET_SPLIT_VARS:
            resolved_any = True
            return ALWAYS_SET_SPLIT_VARS[name]
        return m.group(0)

    after_sub = SUB_ANY_RE.sub(sub_frag, cmd)
    after_ops = apply_param_operators(after_sub, assigns)
    if after_ops != after_sub:
        resolved_any = True
    head = VAR_ANY_RE.sub(var_frag, after_ops)
    if not resolved_any:
        return None
    return " ".join([head] + args)


# A printf conversion: flags, then a width (`*` takes it from an ARGUMENT, else digits), then an
# optional `.precision` (again `*` or digits), then the conversion letter. Each `*` consumes an EXTRA
# operand before the value (`printf '%*s%s' 0 r 'm -rf /'` = `rm -rf /`) — missing `%*s`/`%.*s` here
# desynchronised operand chunking and let that split literal through a printf-to-shell sink (r58 F1).
PRINTF_CONV_RE = re.compile(r"%[-+ #0]*(?:\*|[0-9]+)?(?:\.(?:\*|[0-9]+)?)?[sbdiouxXeEfgGqc]|%%")
_ESC_LETTER = {"n": "\n", "t": "\t", "r": "\r", "a": "\a", "b": "\b", "f": "\f",
               "v": "\v", "e": "\x1b", "E": "\x1b", "\\": "\\"}


def decode_c_escapes(text):
    """Decode the backslash escapes that `echo -e`, `printf` formats, and `printf %b` understand:
    `\\xHH` hex, `\\nnn` / `\\0nnn` octal, and the letter escapes. Bash decodes these BEFORE the
    output reaches a pipe, so `echo -e '\\x72\\x6d -rf /' | sh` runs `rm -rf /` (Codex #26 r33 F1).
    Octal is accepted with and without the leading `0` because the flavours (echo -e vs printf)
    differ — over-decoding only ever affects a `… | sh` pipeline, where the block direction is safe."""
    out, i, n = [], 0, len(text)
    while i < n:
        if text[i] != "\\" or i + 1 >= n:
            out.append(text[i])
            i += 1
            continue
        c = text[i + 1]
        if c == "x":
            j = i + 2
            while j < n and j < i + 4 and text[j] in "0123456789abcdefABCDEF":
                j += 1
            if j > i + 2:
                out.append(chr(int(text[i + 2:j], 16) & 0xFF))
                i = j
                continue
        if c in "01234567":
            # `\0nnn` (echo -e) — the up-to-3 octal digits follow the leading 0; `\nnn` (printf) —
            # the digits start at this one. Read the digit run either way and take up to 3 of it.
            start = i + 2 if c == "0" else i + 1
            k = start
            while k < n and k < start + 3 and text[k] in "01234567":
                k += 1
            octal = text[start:k] or "0"
            out.append(chr(int(octal, 8) & 0xFF))
            i = k
            continue
        out.append(_ESC_LETTER.get(c, c))
        i += 2
    return "".join(out)


def printer_output(head, args):
    """What `echo`/`printf` writes to stdout, when that is statically knowable.

    printf REUSES its format until the operands are consumed and puts nothing between them, so
    `printf '%s' r m ' -rf /'` prints `rm -rf /` and `printf %s c u r l` prints `curl` — the naive
    "drop the format, join the rest with spaces" reading produced neither (Codex #26 r30 F4). Escape
    sequences are DECODED — `echo -e`, the printf format, and a `%b` operand all interpret them, and
    bash does so before the output reaches a pipe (Codex #26 r33 F1). Returns None when the output is
    not statically knowable."""
    if head == "echo":
        # `-e` turns escape interpretation on, `-E` off; the last one seen wins, and flags cluster
        # (`-ne`, `-neE`). A benign `echo '\x72'` (no -e) stays literal.
        decode = False
        while args and re.fullmatch(r"-[neE]+", args[0]):
            for ch in args[0][1:]:
                if ch == "e":
                    decode = True
                elif ch == "E":
                    decode = False
            args = args[1:]
        text = " ".join(args)
        return decode_c_escapes(text) if decode else text
    if head != "printf" or not args:
        return None
    # POSIX option terminator: `printf -- '%s' r m ' -rf /'` makes the FORMAT the arg AFTER `--`,
    # not `--` itself — treating `--` as the format dropped the reassembled output and the whole
    # split literal slipped the sink check (Codex #26 r37 F1). bash `printf` accepts `--`.
    if args[0] == "--":
        args = args[1:]
        if not args:
            return None
    fmt, operands = args[0], args[1:]
    conv_list = [m.group(0) for m in PRINTF_CONV_RE.finditer(fmt) if m.group(0) != "%%"]
    if not conv_list:
        return decode_c_escapes(fmt)
    # Each `*` in a conversion (`%*s`, `%.*s`, `%*.*s`) pulls its width/precision from an operand that
    # PRECEDES the value operand, so a format cycle consumes 1 operand per conversion PLUS one per `*`.
    # Those width/precision operands only set padding (spaces, never inside the value) — the value
    # itself stays contiguous — so they are skipped for the output, and truncation is ignored (the
    # fail-safe over-approximation). `printf '%*s%s' 0 r 'm -rf /'` → skip `0`, value `r`, value
    # `m -rf /` → `rm -rf /`.
    per_cycle = sum(1 + c.count("*") for c in conv_list)
    if not operands:
        operands = [""] * per_cycle
    # Decode escapes in the FORMAT's literal segments only. A `%s` operand is inserted RAW
    # (`printf '%s' '\\x72'` prints `\\x72`), while a `%b` operand is escape-decoded like `echo -e`.
    out, idx = [], 0
    while idx < len(operands):
        chunk = operands[idx:idx + per_cycle]
        chunk += [""] * (per_cycle - len(chunk))
        rendered, pos, oi = [], 0, 0
        for m in PRINTF_CONV_RE.finditer(fmt):
            rendered.append(decode_c_escapes(fmt[pos:m.start()]))
            conv = m.group(0)
            if conv == "%%":
                rendered.append("%")     # a literal percent consumes no operand
            else:
                oi += conv.count("*")    # the * width/precision operands precede the value
                operand = chunk[oi] if oi < len(chunk) else ""
                # `%b` escape-decodes the operand; `%q` SHELL-QUOTES it into a single word that
                # re-parses to the operand verbatim — `printf '%q' 'rm -rf /'` prints `rm\ -rf\ /`,
                # which a downstream `| sh` runs as ONE inert argv word (a file named `rm -rf /`),
                # NOT the rm command. Rendering it raw denied that safe script (Codex #26 r65 F2).
                # shlex.quote yields an equivalent single-word quoting for the sink scanner.
                if conv[-1] == "b":
                    rendered.append(decode_c_escapes(operand))
                elif conv[-1] == "q":
                    rendered.append(shlex.quote(operand))
                else:
                    rendered.append(operand)
                oi += 1
            pos = m.end()
        rendered.append(decode_c_escapes(fmt[pos:]))
        out.append("".join(rendered))
        idx += per_cycle
    return "".join(out)


def sub_output_text(text):
    """The full TEXT a substitution prints, when that is statically knowable: `$(echo curl)` prints
    `curl`, `$(printf %s c u r l)` prints `curl`. Only trivial printers are resolved — anything else
    (`$(mktemp -d)`, `$(which curl)`) stays unknown. This is what the command actually produces,
    which is what its consumer sees: a pipeline head, an argument, or a `-c`/eval script."""
    try:
        toks = shlex.split(text, posix=True)
    except ValueError:
        return None
    if not toks:
        return None
    out = printer_output(toks[0].rsplit("/", 1)[-1], toks[1:])
    return out or None


def sub_output_literal(text):
    """The output of a substitution when it is a SINGLE word — a usable argument/target."""
    out = sub_output_text(text)
    if out is None or not out or len(out.split()) != 1:
        return None
    return out


def apply_param_operators(text, assigns):
    """Expand the array (`${a[0]}`/`${a[@]}`), indirect (`${!v}`), and default (`${v:-w}`) parameter
    operators to their literal value, leaving anything unresolvable unchanged. MUST run before the
    plain-`$var` pass (VAR_ANY_RE), which would otherwise consume the `${a`/`${v` prefix and strand
    the operator tail as inert text — `${a[0]}` became `rm[0]}`, matching nothing. resolve_arg_words
    already applied these to ARGUMENTS; the command-word resolvers (resolved_command_text /
    inline_command_word) did not, so an array/indirect/default command HEAD ran unrecognised
    (`a=(rm); ${a[0]} -rf /`, `v=c; c=rm; ${!v} -rf /`, `c=rm; ${c:-echo} -rf /` — Codex #26 r36 F1).
    Same operator order the argument resolver used (DEFAULT, ARRAY, INDIRECT)."""
    def repl_default(m):
        return expand_param_op(m.group(1), m.group(2), m.group(3), assigns)

    def repl_array(m):
        value = assigns.get(m.group(1))
        if not isinstance(value, ArrayValue):
            return m.group(0)
        idx = m.group(2)
        if idx in ("@", "*"):
            return " ".join(value)
        if idx.isdigit() and int(idx) < len(value):
            return value[int(idx)]
        return m.group(0)

    def repl_indirect(m):
        name = scalar_of(assigns.get(m.group(1), ""))
        if name and name in assigns:
            return scalar_of(assigns[name])
        return m.group(0)

    resolved = VAR_DEFAULT_RE.sub(repl_default, text)
    resolved = ARRAY_REF_RE.sub(repl_array, resolved)
    return VAR_INDIRECT_RE.sub(repl_indirect, resolved)


def resolve_arg_words(arg, subs, assigns):
    """The argv WORDS an argument expands to. An argument built from an expansion is what bash expands
    it to, and the dangerous flags/target hide there just as the command word can: `rm -rf $(echo /)`,
    `` rm -rf `echo /` ``, `d=/; rm -rf $d`. An UNQUOTED expansion also WORD-SPLITS, so `d='-r -f /';
    rm $d` and `rm $(printf -- '-r -f /')` expand to argv `-r`, `-f`, `/` — keeping the whole
    resolution as ONE string let a multi-word expansion smuggle rm's recursive/force flags AND its
    root target past rm_is_destructive as a single inert token (`-r -f /` matched no `--`-less target)
    — Codex #26 r40 F1. A token that cannot resolve (unknown `$VAR`, non-printer `$(mktemp -d)`) stays
    one word, and a pure literal is never split (its spaces were already quoted away by shlex).
    A QUOTED expansion does not word-split in bash, but shlex discarded the quoting, so a value that
    is literally `-r -f /` splits either way — an over-block only on an absurd (root-slash-in-a-name)
    value, the fail-safe direction."""
    def repl_sub(m):
        idx = int(m.group(1)) - 1
        if 0 <= idx < len(subs):
            out = sub_output_text(subs[idx])
            if out is not None:
                return out
        return m.group(0)

    def repl_var(m):
        name = m.group(1)
        if name not in assigns and name in ALWAYS_SET_SPLIT_VARS:
            return ALWAYS_SET_SPLIT_VARS[name]
        return scalar_of(assigns.get(name, m.group(0)))

    resolved = apply_param_operators(SUB_ANY_RE.sub(repl_sub, arg), assigns)
    resolved = VAR_ANY_RE.sub(repl_var, resolved)
    if resolved == arg:
        return [arg]
    return resolved.split() or [resolved]


def resolve_assignment_value(value, subs, assigns):
    """The literal an assignment's RHS holds after its expansions run. An assignment RHS is NOT
    word-split (`c=$(printf 'a b')` is the single value `a b`), but its `$(…)`/`$var`/operator
    expansions ARE evaluated before the value is stored — recording the raw `$(printf rm)` /
    `$(printf /)` placeholder left `c`/`d` unresolvable, so `c=$(printf rm); $c -rf /` and
    `d=$(printf /); rm -rf $d` ran a root removal the hook allowed (Codex #26 r41 F1). A fragment that
    cannot be resolved stays as-is."""
    def repl_sub(m):
        idx = int(m.group(1)) - 1
        if 0 <= idx < len(subs):
            out = sub_output_text(subs[idx])
            if out is not None:
                return out
        return m.group(0)

    def repl_var(m):
        name = m.group(1)
        if name not in assigns and name in ALWAYS_SET_SPLIT_VARS:
            return ALWAYS_SET_SPLIT_VARS[name]
        return scalar_of(assigns.get(name, m.group(0)))

    resolved = apply_param_operators(SUB_ANY_RE.sub(repl_sub, value), assigns)
    return VAR_ANY_RE.sub(repl_var, resolved)


def resolved_command_text(cmd, subs, assigns):
    """The real command TEXT an expansion-built word stands for, or None if any fragment is not
    statically knowable. Each `$(…)` contributes its OUTPUT and each `$var` its value, then the
    fragments CONCATENATE as bash builds one word — so `$(echo ch)$(echo mod)` → `chmod` and
    `r$(printf m)` → `rm`. Returning the real text (not the substitution SOURCE, which the old
    inliner used) is what lets the caller match it AT COMMAND POSITION: `$(echo echo rm)` resolves
    to `echo rm`, whose head is `echo`, so it is data (Codex #26 r32 F2). None → the word is
    unresolvable and the caller falls back to the argv heuristic."""
    ok = [True]

    def sub_frag(m):
        idx = int(m.group(1)) - 1
        out = sub_output_text(subs[idx]) if 0 <= idx < len(subs) else None
        if out is None:
            ok[0] = False
            return ""
        return out

    def var_frag(m):
        name = m.group(1)
        if name in assigns:
            return scalar_of(assigns[name])
        if name in ALWAYS_SET_SPLIT_VARS:
            return ALWAYS_SET_SPLIT_VARS[name]
        # HOME/PWD/OLDPWD are always set: keep the literal `$NAME` (resolve_arg_words does the same
        # for arguments) so a command word concatenated from one — `rm${IFS}-rf${IFS}$HOME` — resolves
        # to `rm -rf $HOME`, which the home-target check catches, instead of failing unresolved.
        if name in ALWAYS_SET_DIR_VARS:
            return ALWAYS_SET_DIR_VARS[name]
        ok[0] = False
        return ""

    resolved = apply_param_operators(SUB_ANY_RE.sub(sub_frag, cmd), assigns)
    text = VAR_ANY_RE.sub(var_frag, resolved)
    return text if ok[0] else None


def resolve_expansion_words(cmd, subs, assigns):
    """The FULL word list an expansion-built command word resolves to, head basename-normalised:
    `$c` with `c=curl` → `['curl']`; `$(echo echo rm)` and `c='echo rm'; $c` → `['echo', 'rm']`.
    Used for the pipeline `curl … | sh` / printer-to-shell checks, which compare command WORDS and
    reconstruct what flows into a downstream shell from the stage's (head, args). Keeping ONLY the
    head dropped the tail words of a multi-word command word, so `$(echo echo rm) -rf / | sh` (bash
    runs `echo rm -rf / | sh`, whose `echo` PRINTS `rm -rf /` into `sh`) and `c='echo rm'; $c -rf /
    | sh` lost the `rm` before the sink analysis — Codex #26 r36 F3. Returns None when unresolvable."""
    # A command word that IS a substitution runs its OUTPUT, not its source: `$(echo curl)` executes
    # `curl`, not `echo`. Inlining the source made the head `echo`, so the pipeline fetcher check
    # never saw the fetcher bash actually runs (Codex #26 r29 F2).
    m = re.fullmatch(r"__SUB(\d+)__", cmd)
    if m:
        idx = int(m.group(1)) - 1
        if 0 <= idx < len(subs):
            out = sub_output_text(subs[idx])
            if out:
                words = out.split()
                if words:
                    return [words[0].rsplit("/", 1)[-1]] + words[1:]
        return None
    # Resolve each `$(…)` to its OUTPUT and each `$var` to its value: a MIXED word `$(printf cur)l`
    # runs `curl`, so inlining the substitution SOURCE (`printf cur`) made the head `printf` and the
    # pipeline fetcher→shell check never saw `curl` (Codex #26 r70 F2). resolved_command_text uses the
    # output, exactly as the top-level command-word resolution does.
    resolved = resolved_command_text(cmd, subs, assigns)
    if not resolved:
        return None
    try:
        words = shlex.split(resolved, posix=True)
    except ValueError:
        return None
    return [words[0].rsplit("/", 1)[-1]] + words[1:] if words else None


def destructive_for_any_head(args):
    """True when this argv would be a destructive invocation of ANY command the patterns know —
    used when the command word itself cannot be resolved (concatenated expansions, unknown vars).
    `-rf /` is destructive under `rm`, `-R 777 /` under `chmod`, `push --force main` under `git`.

    The argv is also tested on its own, so a dangerous command sitting in the ARGUMENTS of an
    unresolvable word (`$(echo sudo) rm -rf /`, `$(x) mkfs /dev/sda`) is caught too."""
    tail = " ".join(args)
    if CMD_RE.search(tail):
        return True
    for head in HYPOTHETICAL_HEADS:
        if CMD_RE.search(head + " " + tail):
            return True
    return rm_is_destructive("rm", args)


def scan_executed(script, depth):
    """Scan an EXECUTED script body (a `-c`/eval/herestring/heredoc/source body). If it is unparsable
    — an unbalanced quote AFTER a complete command, which bash runs before reporting the error — do
    NOT let Unparsable escape to the top-level legacy matcher, which strips shell-fed bodies and would
    miss the live command's literal (Codex #26 r15d F1). Match the body's dangerous literals directly
    instead; python_legacy blanks quoted data so a benign body stays allowed.

    The escape on a `\\$` was consumed by the layer that produced this script, so the `$` is live
    here: `bash -c "\\$(rm -rf /)"`, `eval "\\$(…)"`, and an unquoted heredoc fed to a shell all
    execute the substitution (verified against bash). Restore it before scanning (Codex #26 r26 F1)."""
    script = unescape_dollar(script)
    try:
        return scan(script, depth + 1, is_script=True)
    except Unparsable:
        # bash runs the COMPLETE newline-terminated lines of this body before a later line's syntax
        # error, and the legacy matcher below only sees CONTIGUOUS literals — so a split-literal sink
        # (`printf … | sh`) on a runnable line would slip it. Scan the runnable-line prefix first
        # (Codex #26 r64 F1); fall back to the literal match for the rest.
        if scan_runnable_prefix(script, depth + 1, is_script=True):
            return True
        return python_legacy(script) or legacy_rm_destructive(script)


def resolve(tokens, depth, subs, assigns):
    """Strip env assignments, reserved words, and wrappers. Returns (command, args), or None when
    the stage was fully consumed by recursing into a wrapped script. `subs`/`assigns` let the wrapped
    shell/find handlers resolve a payload or search root that the PARENT shell built from expansions
    (`bash -c "$s $f $t"`, `find $d -delete`) before it reaches the child (Codex #26 r53 F1/F2)."""
    unwrapped = 0
    while tokens:
        unwrapped += 1
        if unwrapped > MAX_DEPTH:
            raise TooDeep("wrapper nesting")
        while tokens and ASSIGN_RE.match(tokens[0]):
            tokens = tokens[1:]
        # A function DEFINITION opener is not a command word — the body that follows runs on call, so
        # `f(){ printf … | sh; }` must expose the sink like a bare `{ … }` does (Codex #26 r67 F1).
        # `function` drops itself and, if the next token is a bare NAME, that too; a `NAME()` opener
        # (with or without the keyword) is stripped by FUNC_DEF_OPENER_RE, feeding back its glued body.
        if tokens and tokens[0] == "function":
            tokens = tokens[2:] if (len(tokens) >= 2 and FUNC_NAME_RE.match(tokens[1])) else tokens[1:]
            continue
        if tokens:
            fm = FUNC_DEF_OPENER_RE.match(tokens[0])
            if fm:
                tokens = ([fm.group(1)] + tokens[1:]) if fm.group(1) else tokens[1:]
                continue
        # `if`/`do`/`(`/`{`/`!` are not command words — the command follows them.
        while tokens and tokens[0] in RESERVED:
            tokens = tokens[1:]
        if tokens:
            bare = tokens[0].lstrip("({!")
            if bare != tokens[0]:
                tokens = ([bare] + tokens[1:]) if bare else tokens[1:]
                continue
        if not tokens:
            break
        # Basename-normalise `/bin/rm` → `rm` for classification, but NOT a word that still holds an
        # unresolved `$` expansion: `rm${IFS}-rf${IFS}/` word-splits to `rm` `-rf` `/` only AFTER the
        # expansion runs, and basenaming the raw token (which ends in `/`) collapsed it to `""`, so the
        # UNRESOLVABLE_CMD_RE path never resolved it and the root wipe slipped (Codex #26 r65 F1). Keep
        # such a word whole; the caller resolves `${IFS}`/`$var` and re-splits it at command position.
        head = tokens[0] if "$" in tokens[0] else tokens[0].rsplit("/", 1)[-1]
        if head in SHELLS or head == "source" or head == ".":
            # A shell's `-c`/herestring, and source/`.`'s herestring (`source /dev/stdin <<< "…"`),
            # are EXECUTED scripts (Codex #26 r13 F2). shell_script_arg picks up either.
            result = shell_script_arg(tokens)
            if result is not None:
                script, trailing = result
                if trailing:
                    script = substitute_positional(unescape_dollar(script), trailing)
                # The PARENT shell expands $var/$(…) in the script BEFORE the child runs it, so a
                # payload assembled from parent assignments (`s=rm f=-rf t=/; bash -c "$s $f $t"`)
                # executes `rm -rf /` though the raw script is inert (Codex #26 r53 F1).
                # resolve_assignment_value substitutes WITHOUT word-splitting — the no-split expansion
                # of a double-quoted `-c` string. Scan the RESOLVED form FIRST: the raw `$s …` script
                # has an unresolvable command word and defers to the legacy matcher (NeedsFallback),
                # which would escape before the resolved scan ran and miss the assembled command.
                resolved_script = resolve_assignment_value(script, subs, assigns)
                if resolved_script != script and scan_executed(resolved_script, depth):
                    raise Dangerous()
                if scan_executed(script, depth):
                    raise Dangerous()
                return None
            return head, tokens[1:]
        if head == "eval":
            joined = " ".join(tokens[1:])
            # eval concatenates its args and re-expands them, so a command built from parent
            # assignments (`s=rm f=-rf t=/; eval $s $f $t`) runs `rm -rf /`. Scan the resolved form
            # first for the same NeedsFallback-escape reason as the shell `-c` case (Codex #26 r53 F1).
            resolved_eval = resolve_assignment_value(joined, subs, assigns)
            if resolved_eval != joined and scan_executed(resolved_eval, depth):
                raise Dangerous()
            if scan_executed(joined, depth):
                raise Dangerous()
            return None
        if head == "timeout":
            tokens = strip_wrapper_options(tokens[1:], "timeout")
            tokens = tokens[1:]  # the DURATION operand
            continue
        if head == "env":
            # `env -S <str>` runs the split string composed with the trailing argv as a command.
            # Resolve the composed token list in place (rather than scanning and returning None) so a
            # bare shell it resolves to stays visible to the pipeline-level pipe-to-shell / fetcher
            # checks (`curl … | env -S bash` — Codex #26 r7 F1).
            env_tokens = env_split_tokens(tokens[1:])
            if env_tokens is not None:
                tokens = env_tokens
                continue
            tokens = strip_wrapper_options(tokens[1:], "env")
            continue
        if head in POSITIONAL_NUM_WRAPPERS:
            tokens = strip_wrapper_options(tokens[1:], head)
            # Drop the mandatory positional operand(s) (CPU mask / priority / niceness) so the
            # command word behind them surfaces: `taskset 0x1 rm -rf /` (Codex #26 r5 F3).
            while tokens and NUM_OPERAND_RE.match(tokens[0]):
                tokens = tokens[1:]
            continue
        if head in PREFIXES:
            tokens = strip_wrapper_options(tokens[1:], head)
            continue
        if head in FIND_CMDS:
            # `find … -exec <cmd> … ;|+` runs <cmd> — scan it (re-quoted to preserve arg boundaries)
            # so a nested `sh -c` and its positional args are resolved, not flattened (Codex #26 r11
            # F2). The `\;` terminator became `;` and was split into its own stage, so the exec
            # command runs to a `+` or end-of-stage.
            args = tokens[1:]
            # find's SEARCH PATHS precede the expression (the first `-predicate` / `(` / `!`), but
            # AFTER any GLOBAL options — `find -H / -delete`, `find -D tree / …`, `find -- / …` all
            # search `/`. Skipping only leading `-` words stopped at `-H` and defaulted to `.`, hiding
            # the root (Codex #26 r52 F1). find substitutes `{}` in an -exec command with each MATCHED
            # path, so a dangerous search root (`find / -exec rm -rf {}` = `rm -rf /`) is hidden behind
            # the literal `{}` — scan the exec command with `{}` replaced by each search path too
            # (Codex #26 r50 F2). No explicit path means find defaults to `.`.
            k0 = 0
            while k0 < len(args):
                a = args[k0]
                if a == "--":
                    k0 += 1
                    break
                if a == "-D":
                    k0 += 2                      # -D takes a debug-option operand
                    continue
                if a in ("-H", "-L", "-P", "-E", "-X", "-x", "-s", "-d") \
                        or (a.startswith("-D") and len(a) > 2) or re.fullmatch(r"-O[0-9]+", a):
                    k0 += 1
                    continue
                break
            expr = args[k0:]
            find_paths = []
            for a in expr:
                if a.startswith("-") or a in ("(", ")", "!"):
                    break
                find_paths.append(a)
            if not find_paths:
                find_paths = ["."]
            # A search ROOT built from an expansion (`d=/; find $d -delete`) is what find actually
            # walks, so resolve it before the -delete / -exec {} guards below — the raw `$d` matched
            # no absolute root (Codex #26 r53 F2). An unresolvable token stays itself, matching nothing.
            find_paths = [w for p in find_paths for w in resolve_arg_words(p, subs, assigns)]
            # find's own `-delete` action removes each matched path AND everything under it, so
            # `find / -delete` = `rm -rf /` and `find ~ -delete` wipes home — with no `rm` in sight.
            # Scan `rm -rf <search path>` for each ABSOLUTE-root/home path. Only the LITERAL cwd-relative
            # markers (`find . -delete`, `find ./build -delete`, `..`) are the documented allowed
            # boundary — the same cwd-vs-escaping boundary as bare `../*` (OPS-541). `$PWD`/`$OLDPWD`
            # expand to the ABSOLUTE current directory, and `rm -rf $PWD` blocks, so skipping them was
            # inconsistent — `find $PWD -delete` recursively deletes the cwd exactly like it (r60 F2);
            # the `rm -rf <path>` scan below decides them the same way it decides `rm -rf $PWD`.
            # Walk the find EXPRESSION, skipping each value-taking predicate's operand so a `-delete`
            # or `-exec` that is really the VALUE of `-name`/`-path`/… is not mistaken for the action
            # (`find / -name -delete` searches for a file named `-delete` — Codex #26 r62 F4).
            i = 0
            while i < len(args):
                a = args[i]
                if a in FIND_2VALUE_PREDICATES:
                    i += 3                          # skip the predicate's TWO value operands
                    continue
                if a in FIND_VALUE_PREDICATES:
                    i += 2                          # skip the predicate's value operand
                    continue
                if a == "-delete":
                    for p in find_paths:
                        if p in (".", "..") or p.startswith(("./", "../")):
                            continue
                        if scan("rm -rf " + shlex.quote(p), depth + 1):
                            raise Dangerous()
                    i += 1
                    continue
                if a in FIND_EXEC_ACTIONS:
                    sub = args[i + 1:]
                    for j, t in enumerate(sub):
                        if t in (";", "+"):
                            sub = sub[:j]
                            break
                    if sub:
                        variants = [sub]
                        if any("{}" in t for t in sub):
                            variants += [[t.replace("{}", p) for t in sub] for p in find_paths]
                        for v in variants:
                            if scan(" ".join(shlex.quote(t) for t in v), depth + 1):
                                raise Dangerous()
                    # advance past the exec command to its `;`/`+` terminator (its args are DATA)
                    j = i + 1
                    while j < len(args) and args[j] not in (";", "+"):
                        j += 1
                    i = j + 1
                    continue
                i += 1
            return head, args
        return head, tokens[1:]
    return None


def command_head(tokens):
    """The command word of one pipeline stage (basename), or None if fully consumed."""
    resolved = command_head_and_args(tokens)
    return resolved[0] if resolved else None


def command_head_and_args(tokens):
    """Resolve the command word AND its remaining args for one pipeline stage: strip env
    assignments, reserved words, and wrappers (with the operands they consume). No recursion into
    scripts, no Dangerous — this only answers "what runs here, with which arguments". Returns
    (basename, args), or None if fully consumed."""
    guard = 0
    while tokens:
        guard += 1
        if guard > MAX_DEPTH:
            return None
        while tokens and ASSIGN_RE.match(tokens[0]):
            tokens = tokens[1:]
        while tokens and tokens[0] in RESERVED:
            tokens = tokens[1:]
        if tokens:
            bare = tokens[0].lstrip("({!")
            if bare != tokens[0]:
                tokens = ([bare] + tokens[1:]) if bare else tokens[1:]
                continue
        if not tokens:
            return None
        head = tokens[0].rsplit("/", 1)[-1]
        if head == "timeout":
            tokens = strip_wrapper_options(tokens[1:], "timeout")
            tokens = tokens[1:]
            continue
        if head == "env":
            # env -S composes a command; a split-string shell must be visible to pipe-to-shell
            # detection (`… | env -S "sudo bash"` — Codex #26 r8 F2).
            env_tokens = env_split_tokens(tokens[1:])
            if env_tokens is not None:
                tokens = env_tokens
                continue
            tokens = strip_wrapper_options(tokens[1:], "env")
            continue
        if head in POSITIONAL_NUM_WRAPPERS:
            tokens = strip_wrapper_options(tokens[1:], head)
            while tokens and NUM_OPERAND_RE.match(tokens[0]):
                tokens = tokens[1:]
            continue
        if head in PREFIXES:
            tokens = strip_wrapper_options(tokens[1:], head)
            continue
        return head, tokens[1:]
    return None


def pipes_into_shell(text):
    """True when a pipeline feeds its output into a downstream shell that reads stdin as a script
    (`echo rm -rf / | bash`, `... | sudo -u root bash`, `... | env -i bash`). The piped text may be
    computed at runtime, so we do not model what runs — we route the whole command to the legacy
    unanchored matcher (fallback). SINK_RE catches the bare `| bash` shape, but not a shell behind
    wrapper OPTIONS (`-u root`, `-i`), whose operand grammar lives in the parser (Codex #26 F2)."""
    text = deobfuscate(text)
    text, _ = split_heredocs(text)
    try:
        _, redacted, _ = extract_subs(text)
    except Unparsable:
        return False
    redacted = space_herestrings(redacted)
    redacted = strip_redirections(redacted)
    for pipeline in split_pipelines(redacted):
        for stage in pipeline[1:]:
            try:
                tokens = shlex.split(stage, posix=True)
            except ValueError:
                continue
            if command_head(tokens) in SHELLS:
                return True
    return False


def has_stdin_redirect(text):
    """True if `text` has a stdin INPUT redirect (`< file`, `0< file`) that reads stdin from a FILE,
    which overrides any pipe input. `<<`/`<<<` (heredoc/herestring) and `<(` (process substitution)
    are NOT stdin-from-file, and `N<` for N≥1 redirects that fd, not stdin (Codex #26 r50 F3).
    Quote-aware."""
    i, n = 0, len(text)
    in_sq = in_dq = False
    while i < n:
        c = text[i]
        if in_sq:
            in_sq = c != "'"
            i += 1
            continue
        if in_dq:
            in_dq = c != '"'
            i += 1
            continue
        if c == "'":
            in_sq = True
            i += 1
            continue
        if c == '"':
            in_dq = True
            i += 1
            continue
        if c == "<":
            if text[i:i + 3] == "<<<":
                i += 3
                continue
            if text[i:i + 2] in ("<<", "<("):
                i += 2
                continue
            # The fd before `<` is the MAXIMAL preceding digit run. A single-char look-back read the
            # last digit of `10<` as fd 0 and mistook `bash 10< /dev/null <<EOF` for a stdin-from-file
            # redirect (Codex #26 r61 F2). A STANDALONE fd (digits preceded by a separator) redirects
            # stdin only when it is fd 0; `2<`/`10<`/… redirect another fd. No standalone fd — an
            # implicit `<` or digits glued to a WORD (`file10<`) — is fd 0 stdin.
            j = i - 1
            while j >= 0 and text[j].isdigit():
                j -= 1
            digits = text[j + 1:i]
            if digits and (j < 0 or text[j] in " \t\r\n|;&("):
                if int(digits) == 0:
                    return True                 # explicit fd 0 = stdin
            else:
                return True                     # implicit fd 0 (or digits are part of a word) = stdin
            i += 1
            continue
        i += 1
    return False


def has_shell_command_word(text):
    """True if any pipeline stage's resolved COMMAND WORD is a shell that CONSUMES the pipe. A heredoc
    body is only a script when the command consuming it is a shell (`bash <<EOF`), not when a shell
    name merely appears as an argument (`echo bash <<EOF`, `cat <<EOF | grep bash` — Codex #26 r7 F3),
    and not when the shell reads stdin from an explicit `< file` redirect instead of the pipe
    (`cat <<A | bash < /dev/null` — the body never runs, Codex #26 r50 F3). Unparsable input returns
    True so the body is still scanned (fail-safe)."""
    try:
        _, redacted, _ = extract_subs(text)
    except Unparsable:
        return True
    # Split the UN-stripped text so a stage's stdin redirect is still visible; strip per-stage only
    # for the command-word lookup. (Over-splitting a `>&` stage on `&` at worst adds an inert stage.)
    for pipeline in split_pipelines(redacted):
        for stage in pipeline:
            try:
                tokens = shlex.split(strip_redirections(stage), posix=True)
            except ValueError:
                return True
            # source/`.` execute their stdin/herestring as a script too, so a heredoc they consume
            # (`source /dev/stdin <<EOF …`) is a script, not data (Codex #26 r12 F4). But a shell/
            # source running a SCRIPT FILE reads stdin as that file's DATA, so `bash deploy.sh <<EOF`
            # does NOT execute the body (Codex #26 r51 F1); and an explicit `< file` stdin redirect
            # overrides the pipe (Codex #26 r50 F3).
            resolved = command_head_and_args(tokens)
            if resolved is None:
                continue
            _head, _cargs = resolved
            if _head in SHELLS or _head in ("source", "."):
                if not has_stdin_redirect(stage) and shell_reads_stdin_script(_head, _cargs):
                    return True
    return False


def heredoc_shell_argv(intro):
    """For a heredoc consumed by a shell reading stdin (`bash -s -- <args> <<EOF`), return the argv
    bash assigns to the body's positional params — a `$0` placeholder plus <args> — or None. Lets
    the heredoc-body scan resolve `$@`/`$N` in the body (Codex #26 r13 F4)."""
    try:
        tokens = shlex.split(strip_redirections(intro), posix=True)
    except ValueError:
        return None
    while tokens:
        if ASSIGN_RE.match(tokens[0]) or tokens[0] in RESERVED:
            tokens = tokens[1:]
            continue
        bare = tokens[0].lstrip("({!")
        if bare != tokens[0]:
            tokens = ([bare] + tokens[1:]) if bare else tokens[1:]
            continue
        head = tokens[0].rsplit("/", 1)[-1]
        if head == "timeout":
            tokens = strip_wrapper_options(tokens[1:], "timeout")
            tokens = tokens[1:]
            continue
        if head in PREFIXES:
            tokens = strip_wrapper_options(tokens[1:], head)
            continue
        break
    if not tokens or tokens[0].rsplit("/", 1)[-1] not in SHELLS:
        return None
    rest = tokens[1:]
    for i, t in enumerate(rest):
        if t == "--":
            args = rest[i + 1:]
            return (["_"] + args) if args else None
    trailing = [t for t in rest if not t.startswith("-")]
    return (["_"] + trailing) if trailing else None


def needs_fallback(deob):
    """A fallback guard fires on this (deobfuscated) text: it feeds text to a shell (sink shape or a
    pipe into a shell behind wrapper options), hands a code string to an interpreter, uses a
    find/exec or command-runner wrapper, passes a command as option data to a tool that executes it,
    builds a file from a process substitution, or runs a shell/eval script built from an expansion we
    cannot resolve statically. Checked at EVERY scan level so a construct inside a `-c` script is
    caught, not only at the top (Codex #26 r12 F1). The legacy matcher (which over-blocks on the
    literal) then decides — the verdict stays the UNION of the two matchers.

    Only shapes that CANNOT be quoted and still work are matched here, against the quote-blanked
    probe: a shell sink, a reserved word / unmodeled construct, a process substitution, and a
    shell/eval script built from an expansion. A guard that reads text cannot tell a quoted
    COMMAND WORD (`"python3" -c …`, which bash runs) from a quoted MENTION (`git commit -m
    "…python3 -c…"`, which is data) — matching raw over-blocked the mention (r18 F3), matching
    blanked under-blocked the command (r20 F1). Those guards are now decided per-stage from the
    resolved command word in scan(), via runs_unmodelled_command()."""
    probe = blank_quoted(deob)
    if SINK_RE.search(probe) or CONSTRUCT_RE.search(probe):
        return True
    if EXPANSION_RE.search(probe) and (EVAL_RE.search(probe) or SHELL_DASH_C_RE.search(probe)):
        return True
    if pipes_into_shell(deob):
        return True
    return False


def sub_feeds_shell(redacted, n):
    """True if command-substitution placeholder __SUBn__ is the argument of a shell `-c`/`eval` in
    `redacted` — i.e. its OUTPUT is executed as a script (`bash -c "$(cat <<EOF …)"`). Scoped to the
    same simple command (Codex #26 r14 F2 — the previous global flag over-scanned unrelated
    heredocs). The `-c` may sit anywhere in a short-option CLUSTER (`bash -cx`, `sh -ec`,
    `bash -lcx` — bash reads `-cx` as `-c -x`); matching only clusters ENDING in `c` let
    `bash -cx "$(cat <<EOF … )"` execute a heredoc body the fallback then stripped (Codex #26 r19
    F1). Same cluster rule as DASH_C_RE, which resolve() already applies to a literal script.

    `-c` runs its FIRST operand as the script, so the substitution feeds the shell only when it IS
    that operand — only whitespace/quotes may sit between the `-c` cluster and the placeholder. A
    substitution that is a LATER positional is `$0`/`$1`, not the script (`bash -c 'echo hi'
    <(printf …)` runs `echo hi`; the procsub is `$0`), and scanning its output as a script was an
    over-block exposed once the r36 F2 trigger reached `<(` (Codex #26 r36 F2). `eval` concatenates
    ALL its arguments into the script, so a substitution anywhere in its list still feeds it."""
    ph = "__SUB%d__" % n
    c_script = re.search(
        r"(?:[\w./-]*/)?(?:sh|bash|zsh|dash|ksh)\b[^|;&\n]*\s[-+][A-Za-z]*c[A-Za-z]*(?=[\s\"'])"
        r"[\s\"']*" + re.escape(ph), redacted)
    eval_script = re.search(r"(?:^|[\s;&|(])eval\b[^|;&\n]*" + re.escape(ph), redacted)
    return bool(c_script or eval_script)


def procsub_consumer_dangerous(text, n, subs, depth):
    """Scan input-procsub `__SUBn__`'s OUTPUT as its consumer's executed program, when `text` shows a
    consumer that EXECUTES that file (`bash <(…)`, `make -f <(…)`, `python3 <(…)`). Returns True on a
    dangerous hit. Shared by the top-level sub loop and the resolved-command-word path — where the
    consumer word was an expansion (`m=make; $m -f <(…)`) that only resolves to a real consumer once
    the parent assignments are known, so procsub_script_argv keyed to the raw `$m` missed it (r59 F1)."""
    consumer = procsub_script_argv(text, n)
    if consumer is None:
        return False
    produced = sub_output_text(subs[n - 1])
    if not produced:
        return False
    if consumer[0] == "shell":
        return scan_executed(substitute_positional(produced, consumer[1]), depth)
    return interpreter_program_is_dangerous(produced)


def case_arm_bodies(text):
    """The executed BODIES of `case W in PAT) BODY ;; … esac` arms. At statement level the arm
    pattern glues to the body's first command (`x) printf` resolves with head `x)`), so an assembled
    sink in the body is never seen — extract each BODY, from an arm's unquoted `)` to its `;;`/`;&`/
    `;;&` or the closing `esac`, and the caller scan_executes it (Codex #26 r67 F1). Quote- and
    paren-nesting aware so a `)` inside `$(…)` or a quoted pattern does not end an arm early."""
    bodies = []
    for cm in re.finditer(r"(?:^|[\s;&|(){}!])case[\s]", text):
        i, n = cm.end(), len(text)
        in_sq = in_dq = False
        depth = 0
        state = 0            # 0 = before `in`, 1 = expecting a pattern, 2 = inside a body
        body_start = None
        while i < n:
            c = text[i]
            if in_sq:
                if c == "'":
                    in_sq = False
                i += 1
                continue
            if in_dq:
                if c == '"':
                    in_dq = False
                i += 1
                continue
            if c == "'":
                in_sq = True
                i += 1
                continue
            if c == '"':
                in_dq = True
                i += 1
                continue
            if c == "(":
                depth += 1
                i += 1
                continue
            if c == ")":
                if depth > 0:
                    depth -= 1
                elif state == 1:
                    state, body_start = 2, i + 1
                i += 1
                continue
            if state == 0:
                m = re.match(r"in(?=[\s;&|]|$)", text[i:])
                if m:
                    state = 1
                    i += m.end()
                    continue
                i += 1
                continue
            if re.match(r"esac(?=[\s;&|)]|$)", text[i:]):
                if state == 2 and body_start is not None:
                    bodies.append(text[body_start:i])
                break
            if state == 2 and text[i:i + 3] == ";;&":
                bodies.append(text[body_start:i])
                state, i = 1, i + 3
                continue
            if state == 2 and text[i:i + 2] in (";;", ";&"):
                bodies.append(text[body_start:i])
                state, i = 1, i + 2
                continue
            i += 1
    return bodies


def scan(text, depth=0, is_script=False, feeds_shell=False):
    if depth > MAX_DEPTH:
        raise TooDeep("recursion")
    deob = deobfuscate(text)
    stripped, heredocs = split_heredocs(deob)
    # A heredoc body is data to `cat`, but a SCRIPT to `bash <<EOF ... EOF`. Scan it when the command
    # CONSUMING it is a shell/source, OR this text feeds a shell (it is the content of a command
    # substitution that is a `-c`/eval argument — `bash -c "$(cat <<EOF …)"` — Codex #26 r7 F3/r12 F4).
    for intro, body in heredocs:
        argv = heredoc_shell_argv(intro)
        body_text = substitute_positional(unescape_dollar(body), argv) if argv else body
        if (has_shell_command_word(intro) or feeds_shell) and scan_executed(body_text, depth):
            return True
        # A body handed to an INTERPRETER reading stdin is its PROGRAM, not data. It is not shell,
        # so it cannot be parsed here — and deferring loses it, because the legacy matcher strips
        # heredoc bodies. Match the body directly (Codex #26 r23 F1). A body consumed by a script
        # FILE (`python3 script.py <<EOF`) is stdin data and is not matched.
        if interpreter_program_consumer(intro) and interpreter_program_is_dangerous(body_text):
            raise Dangerous()
    subs, redacted, input_procsubs = extract_subs(stripped)
    for i, sub in enumerate(subs):
        feeds = sub_feeds_shell(redacted, i + 1)
        if scan(sub, depth + 1, feeds_shell=feeds):
            return True
        # When the substitution's OUTPUT is the script (`bash -c "$(printf '…')"`, `eval "$(…)"`),
        # scanning the PRODUCER only proves `printf` is harmless — the text it prints is what runs,
        # and it may assemble the dangerous command from further substitutions
        # (`bash -c "$(printf '$(printf r)$(printf m) -rf /')"` — Codex #26 r29 F3).
        if feeds:
            produced = sub_output_text(sub)
            if produced and scan_executed(produced, depth):
                return True
        # A process substitution redirected into a shell's STDIN is that shell's script, with the
        # shell's argv bound to $@: `bash -s -- -rf / < <(printf 'rm "$@"')` runs `rm -rf /`. The
        # sub was scanned above as its own command (printf, benign); its OUTPUT is what the shell
        # executes (Codex #26 r35 F2). `redacted` still has the `< __SUBn__` redirect here — it is
        # stripped later — so detect it now.
        argv = procsub_stdin_shell_argv(redacted, i + 1)
        if argv is not None:
            produced = sub_output_text(sub)
            if produced:
                produced = substitute_positional(produced, ["_"] + argv)
                if scan_executed(produced, depth):
                    return True
        # An INPUT process substitution `<(…)` passed as the SCRIPT-FILE argument of a shell /
        # `source` / interpreter is executed as that consumer's program (`bash <(printf …)`, `source
        # <(printf …)`, `python3 <(printf …)`). The producer (printf) was scanned above as benign; its
        # OUTPUT is the script, and a split literal keeps it out of the legacy matcher — the same
        # printf reassembly `printf … | sh` and `bash -c "$(printf …)"` already model (Codex #26 r36
        # F2). Only `<(…)` is a script FILE; a `$(…)` here word-splits into argv (`bash $(printf 'rm
        # -rf /')` runs `bash rm -rf /`), so it is excluded via input_procsubs.
        if i in input_procsubs and procsub_consumer_dangerous(redacted, i + 1, subs, depth):
            return True
    if RAW_RE.search(blank_quoted(redacted)):
        return True
    redacted = space_herestrings(redacted)
    # A redirect TARGET writes to whatever path it names, and quoting a filename does not make it data:
    # `echo hi > "/dev/sda"` overwrites the disk exactly as the bare form does. The top-of-scan RAW_RE
    # runs on blank_quoted text (so a quoted `/dev/sda` in an ARGUMENT stays data) and therefore blanks
    # a quoted TARGET too, and a target can also be expansion-built (`d=/dev/sda; echo hi > $d`) — both
    # slip that check (Codex #26 r53 F4 / r56 F1). Re-check every redirect target here, DEQUOTED and
    # expansion-resolved, in STATEMENT ORDER against the shell state AT THE POINT the write runs: a
    # later reassignment (`…; d=/dev/null`) must not mask an earlier dangerous write, and a later
    # dangerous value must not retro-condemn an earlier benign one (r54 F1 — the point-in-time fix).
    # `split_pipelines` breaks `>|` at the `|`, so rejoin each statement's stages before stripping
    # (which recognises `>|`/`&>`/`>&`). The incremental assigns mirror the main loop's subshell rule
    # (a pipeline-stage assignment does not persist), and each target is checked BEFORE this statement's
    # own assignments are recorded, so a command-prefix `d=/dev/sda echo hi > $d` (d unset for the
    # redirect) cannot self-arm. Gated on a redirect being present; a benign target matches nothing.
    if ">" in redacted:
        f4_assigns = {}
        for _pl in split_pipelines(redacted):
            _stmt = "|".join(_pl)
            _tgts = []
            strip_redirections(_stmt, _tgts)
            for _tgt in _tgts:
                _dq = resolve_assignment_value(_tgt, subs, f4_assigns).replace('"', "").replace("'", "")
                if RAW_RE.search("> " + _dq):
                    return True
            if len(_pl) == 1:
                try:
                    record_assignments(shlex.split(strip_redirections(_stmt), posix=True), f4_assigns, subs)
                except ValueError:
                    pass
    redacted = strip_redirections(redacted)
    var_cmd = False
    # A printer→shell sink whose output we STATICALLY computed and scanned clean is fully modelled;
    # a pipe-into-shell whose stdin we could not compute is not. Tracked so the fallback guard can
    # allow the former (whose raw text still LOOKS like a sink) without opening the latter (r65 F2).
    sink_resolved_clean = False
    sink_unresolved = False
    assigns = {}
    pipeline_seps = []
    pipeline_list = split_pipelines(redacted, pipeline_seps)
    pipeline_cond = pipeline_conditionality(pipeline_list, pipeline_seps)
    for pipeline_idx, pipeline in enumerate(pipeline_list):
        # `printer | xargs sh -c 'rm "$@"' _`: xargs WORD-SPLITS the previous stage's stdin and
        # appends the words as the `-c` script's positional params ($1,$2,… → `$@`), so the resolved
        # `rm "$@"` runs `rm -rf /`. resolve() below CONSUMES the `sh -c` stage (scanning it with an
        # EMPTY $@), so the appended-args view is only reachable from the RAW stages — detect it here
        # before resolution, at command position via strip_leading_prefixes (Codex #26 r49 F1).
        raw = []
        for _st in pipeline:
            try:
                raw.append(shlex.split(_st, posix=True))
            except ValueError:
                raw.append(None)
        for i in range(1, len(raw)):
            if raw[i] is None or raw[i - 1] is None:
                continue
            # ONLY xargs turns the previous stage's stdin into the child's argv — sudo/env/nice do
            # not, so `echo x | sudo sh -c 'rm "$@"'` feeds stdin, not $@ (harmless data). xargs may
            # sit behind wrappers or an `env -S` split, so unwrap to it robustly (Codex #26 r67 F2).
            info = xargs_stage_info(raw[i])
            if info is None:
                continue
            sh_toks, delim, token, arg_file = info
            # An `-a`/`--arg-file` xargs reads its items from a FILE, not the pipe — handled by the
            # stage-level arg-file pass below, so skip the pipe-fed model here (Codex #26 r67 F3).
            if arg_file is not None:
                continue
            prev = strip_leading_prefixes(raw[i - 1])
            if not prev or prev[0].rsplit("/", 1)[-1] not in ("echo", "printf"):
                continue
            # The printer's operands can be expansion-built (`a=/; echo $a | xargs …`), so resolve
            # each (no-split, preserving printf operand boundaries) before rendering (Codex #26 r53 F3).
            prev_res = [resolve_assignment_value(a, subs, assigns) for a in prev[1:]]
            produced = printer_output(prev[0].rsplit("/", 1)[-1], prev_res)
            if xargs_child_dangerous(sh_toks, delim, token, produced, depth, subs, assigns):
                return True
        # xargs `-a FILE` / `--arg-file=FILE` reads its items from a FILE instead of stdin, so a
        # process substitution there feeds the child with NO upstream printer: `xargs -a <(printf /)
        # rm -rf` runs `rm -rf /` (Codex #26 r67 F3). Check every stage (the arg-file source needs no
        # pipe), resolving the procsub's output as the input items.
        for _st in raw:
            if _st is None:
                continue
            info = xargs_stage_info(_st)
            if info is None or info[3] is None:
                continue
            sh_toks, delim, token, arg_file = info
            produced = procsub_output(arg_file, subs)
            if xargs_child_dangerous(sh_toks, delim, token, produced, depth, subs, assigns):
                return True
        cmds = []
        stages = []
        for stage in pipeline:
            try:
                tokens = shlex.split(stage, posix=True)
            except ValueError:
                raise Unparsable("shlex")
            # Bash runs every stage of a MULTI-stage pipeline in a subshell, so an assignment there
            # does not survive it: `d=/ | cat; rm -rf $d` leaves `d` unset (verified). Recording it
            # denied the later harmless `rm` (Codex #26 r31 F4).
            if len(pipeline) == 1:
                record_assignments(tokens, assigns, subs, conditional=pipeline_cond[pipeline_idx])
            resolved = resolve(tokens, depth, subs, assigns)
            if resolved is None:
                cmds.append("")
                continue
            cmd, args = resolved
            # The pipeline checks below compare command WORDS and reconstruct what a downstream shell
            # receives, so an expansion-built word must be resolved to what it stands for first
            # (`c=curl; $c http://x | sh` — Codex #26 r24 F2). A word that resolves to MULTIPLE words
            # (`$(echo echo rm)` → `echo rm`) contributes its head as the command and its tail words
            # as leading ARGS, so the printer-to-shell check sees the full `echo rm -rf /` and not
            # just `echo -rf /` — Codex #26 r36 F3.
            pipe_head = cmd
            stage_args = args
            if UNRESOLVABLE_CMD_RE.search(cmd):
                words = resolve_expansion_words(cmd, subs, assigns)
                if words:
                    pipe_head = words[0]
                    stage_args = words[1:] + args
            cmds.append(pipe_head)
            stages.append((pipe_head, stage_args))
            # A `$var`/`${var}` in COMMAND position runs whatever the variable holds, and a
            # command-substitution placeholder (`__SUBn__`, incl. a `-c`/eval script that is
            # nothing but `"$(…)"` — its OUTPUT is the script) runs whatever that produced. Both
            # are statically unresolvable (`c='rm -rf /'; $c`, `bash -c "$(echo rm -rf /)"`), so
            # defer: the legacy matcher blocks iff a dangerous literal is present anywhere in the
            # text, and a benign `$EDITOR file` / `eval "$(git rev-parse HEAD)"` stays allowed
            # (Codex #26 r16 F2, r18 F3).
            # A command word containing an expansion — `$var`, `$(…)` (as `__SUBn__`), or a
            # CONCATENATION of them (`$(printf r)$(printf m)`, `r$(printf m)`, `$a$b`) — is what
            # bash assembles at runtime, and it may be assembled out of fragments so that the
            # dangerous literal never appears contiguously in the text (Codex #26 r23 F2).
            if UNRESOLVABLE_CMD_RE.search(cmd):
                var_cmd = True
                # Deferring alone is not enough: the legacy matcher needs a CONTIGUOUS literal, and
                # an unresolvable command word SPLITS it — `$(echo rm) -rf /` and `c=rm; $c -rf /`
                # both run `rm -rf /`, yet neither text contains it. Rebuild the statement from what
                # the word stands for and match it AT COMMAND POSITION, exactly as a literal command
                # is matched. Matching the rebuilt text with the unanchored legacy matcher instead
                # denied `$(echo echo rm) -rf /`, which merely PRINTS the text (Codex #26 r32 F2).
                word = resolved_command_text(cmd, subs, assigns)
                head_tokens = None
                if word:
                    try:
                        head_tokens = shlex.split(word, posix=True)
                    except ValueError:
                        head_tokens = word.split()
                if head_tokens:
                    # The word RESOLVED. Decide from the real command, at command position — and do
                    # NOT fall through to the unknown-head heuristic, which would re-block a
                    # resolved-but-benign command like `$(echo echo rm) -rf /` (the head is `echo`,
                    # not `rm` — Codex #26 r32 F2).
                    full = head_tokens + [w for a in args for w in resolve_arg_words(a, subs, assigns)]
                    # The resolved word may itself be a WRAPPED command — `c='sudo rm'; $c -rf /` and
                    # `$(echo sudo rm) -rf /` run `sudo rm -rf /` — so strip wrappers to reach the real
                    # command before matching; keying only off full[0] left `sudo`/`env` as the head
                    # and the rm check never saw `rm` (self-audit, r40 sweep). A benign resolved head
                    # (`$(echo echo rm) -rf /` → `echo`) still does not match.
                    stripped = command_head_and_args(full)
                    real, real_args = stripped if stripped is not None else (full[0].rsplit("/", 1)[-1], full[1:])
                    if CMD_RE.search(" ".join([real] + real_args)) or rm_is_destructive(real, real_args):
                        raise Dangerous()
                    # CMD_RE / rm_is_destructive are the GENERIC guards; the command-SPECIFIC ones
                    # stayed keyed to the unresolved `$var`, so a resolved `find`/`make`/shell slipped
                    # its own handler (`c=find; $c / -delete`, `m=make; $m -f <(printf …)` — r59 F1).
                    # Re-resolve the command word REPLACED by its real value but with the ORIGINAL args
                    # (not resolve_arg_words'd — that inlines a procsub's output and drops the
                    # `__SUBn__` placeholder), so resolve()'s find `-delete`/`-exec` and shell `-c`
                    # handlers see the real word; resolve() raises Dangerous on a hit.
                    reconstructed = head_tokens + args
                    try:
                        resolve(reconstructed, depth, subs, assigns)
                    except Unparsable:
                        pass
                    # A make/awk procsub-file-exec consumer built from `$var` still needs its OUTPUT
                    # scanned — the top-level sub loop saw the unresolved head. Re-check on the resolved
                    # command text (the substitution's own producer was already scanned as benign).
                    reconstructed_text = " ".join(reconstructed)
                    for _pm in PROCSUB_ARG_RE.finditer(reconstructed_text):
                        _n = int(_pm.group(0)[len("__SUB"):-2])
                        if (_n - 1) in input_procsubs and procsub_consumer_dangerous(reconstructed_text, _n, subs, depth):
                            raise Dangerous()
                # The word could NOT be resolved (`$(printf r)$(printf m)`, an unknown `$VAR`). Ask
                # instead whether the ARGV would be destructive for any command the patterns know:
                # `$(x) -rf /` is denied, `$EDITOR notes.txt` and `$(which ls) -la` are not.
                elif destructive_for_any_head(args):
                    raise Dangerous()
            # An interpreter code string, a command-runner wrapper, a tool handed a command as
            # option data, or find's -exec family: this stage EXECUTES something command-position
            # analysis cannot see. Decided from the resolved command word — quotes are already
            # gone, so `"python3" -c …` and `git -c 'alias.p=!…' p` are caught while a quoted
            # mention in an argument (`git commit -m "…python3 -c…"`) is not (Codex #26 r20 F1).
            if runs_unmodelled_command(cmd, args):
                var_cmd = True
                # The legacy fallback only sees a CONTIGUOUS literal, so a split-literal shell SINK
                # inside an executed payload (`git -c alias.x='!printf … | sh' x`) slipped it. Scan the
                # payload as an executed script — its printer-to-shell / rm logic catches the sink
                # (Codex #26 r43 F2). scan_executed raises Dangerous on a hit (→ BLOCK at the top).
                for _payload in unmodelled_shell_payloads(cmd, args, leading_env(tokens, subs, assigns)):
                    try:
                        if scan_executed(_payload, depth):
                            return True
                    except (NeedsFallback, Unparsable, TooDeep):
                        pass
                # The payload scan above sees only the placeholder-bearing arg, so a DYNAMIC command
                # word whose destructive flags/target are SEPARATE argv words slips it: `strace
                # $(echo rm) -rf /`, `git submodule foreach $(echo rm) -rf /` resolve to `rm -rf /`
                # but `__SUB0__` alone is `rm` with no target. A RUNNER wrapper / DATA-EXEC tool runs
                # its remaining argv as a COMMAND, but its option grammar is unmodelled, so the real
                # command word can sit at any position — resolve every arg's expansions and run the
                # UNANCHORED legacy matcher on the reconstruction, exactly as the raw-text defer does
                # but on RESOLVED text. python_legacy BLANKS quoted regions, so a message arg
                # (`… -m "rm -rf /"`) stays data. Scoped to runner/data-exec: an INTERPRETER's argv is
                # NOT a shell command (`python3 script.py <(printf …)` — the procsub is a data
                # filename to script.py, not executed), so it must not be reconstruction-scanned
                # (Codex #26 r47 F1, r36 F2 regression).
                _rbase = cmd.rsplit("/", 1)[-1]
                if (RUNNER_CMD_RE.match(_rbase) or _rbase in DATA_EXEC_CMDS) and python_legacy(
                        " ".join([cmd] + [w for a in args for w in resolve_arg_words(a, subs, assigns)])):
                    return True
            # A dangerous TARGET can be built from an expansion exactly as a command word can, and
            # then it appears nowhere in the text: `rm -rf $(echo /)`, `d=/; rm -rf $d`. Resolve the
            # arguments that CAN be resolved; the rest stay literal and match nothing.
            eff_args = [w for a in args for w in resolve_arg_words(a, subs, assigns)]
            if CMD_RE.search(" ".join([cmd] + eff_args)):
                return True
            if rm_is_destructive(cmd, eff_args):
                return True
        for k, cmd in enumerate(cmds):
            if cmd in SHELLS and any(p in FETCHERS for p in cmds[:k]):
                return True
        # `xargs` APPENDS its stdin words to the command it runs, so the destructive TARGET can come
        # from the previous stage and never sit next to the command: `echo / | xargs rm -rf` deletes
        # the root, yet `rm -rf /` appears nowhere in the text (self-audit, r24 sweep). When the
        # upstream stage is a literal printer, its words are exactly what xargs appends.
        for k in range(1, len(stages)):
            cmd, args = stages[k]
            prev_cmd, prev_args = stages[k - 1]
            # The printer's OWN operands can be expansion-built (`a=/; echo $a | xargs rm -rf`,
            # `a=rm; b=' -rf /'; printf %s $a "$b" | sh`), so resolve each before rendering — no-split
            # so a quoted operand stays ONE printf operand (Codex #26 r53 F3).
            prev_res = [resolve_assignment_value(a, subs, assigns) for a in prev_args] if prev_args else prev_args
            if cmd == "rm" and prev_cmd in ("echo", "printf") and prev_args:
                # xargs WORD-SPLITS its stdin, so a single upstream word can carry both the flags
                # and the target: `printf '%s\n' '-rf /' | xargs rm` runs `rm -rf /` (Codex #26 r28
                # F1). Splitting is what makes `-rf /` two argv words rather than one inert token.
                produced = printer_output(prev_cmd, prev_res)
                piped = (produced or " ".join(prev_res)).split()
                if rm_is_destructive("rm", args + piped):
                    return True
            # A printer piped into a SHELL supplies that shell's script, and the text it prints is
            # what runs: `printf '%s' r m ' -rf /' | sh` executes `rm -rf /`, which appears nowhere
            # in the command (Codex #26 r30 F4). If the shell has positional args (`bash -s -- -rf /`)
            # those bind to $@ in that stdin script (`printf 'rm "$@"' | bash -s -- -rf /` — r35 F2).
            # `source`/`.` reading its stdin (`… | source /dev/stdin`) is the same sink but with no
            # positional-arg binding — the SHELLS check missed it (Codex #26 r62 F1).
            source_stdin_sink = cmd in ("source", ".") and shell_reads_stdin_script(cmd, args)
            if cmd in SHELLS or source_stdin_sink:
                produced = printer_output(prev_cmd, prev_res) if (
                    prev_cmd in ("echo", "printf") and prev_args) else None
                if produced is None:
                    # A pipe-into-shell whose stdin we could NOT statically compute (`cat f | sh`,
                    # `$(gen) | sh`) is an UNMODELLED sink — it must stay deferred to the fallback.
                    sink_unresolved = True
                else:
                    if produced and cmd in SHELLS:
                        argv = ["_"] + shell_operand_argv([cmd] + args)
                        if len(argv) > 1:
                            produced = substitute_positional(produced, argv)
                    if produced and scan_executed(produced, depth):
                        return True
                    # Output computed AND scanned clean — this sink is FULLY modelled (a `%q`-escaped
                    # operand runs as one inert word), so the fallback need not re-condemn its raw text.
                    sink_resolved_clean = True
    # Nothing dangerous in command position at THIS level. If this text is an EXECUTED shell script
    # (a `-c`/eval/herestring/heredoc/source body), an unanchored dangerous literal in it runs — the
    # bash legacy matcher would strip such bodies, so match here in python (Codex #26 r13 F1).
    if is_script and python_legacy(text):
        raise Dangerous()
    # A fallback guard here defers the whole command to the legacy matcher — applied recursively, so
    # a sink/interpreter/runner inside a `-c` script is caught, not only at the top (Codex #26 r12 F1).
    # The legacy matcher only knows clustered `-rf`, so a split-flag rm hidden in the DATA a construct
    # executes would slip through it — check that here before deferring (Codex #26 r15c F1).
    if var_cmd or needs_fallback(deob):
        # A printer→shell sink whose OUTPUT we computed and scanned CLEAN is fully modelled, yet its
        # raw text still LOOKS like a shell sink (SINK_RE / pipes_into_shell), so needs_fallback fires
        # and the over-blocking legacy matcher re-condemns a `%q`-escaped operand that runs as ONE
        # inert word (`printf '%q' 'rm -rf /' | sh`, verified safe against bash — Codex #26 r65 F2).
        # Suppress the fallback ONLY when that shell-sink shape is the SOLE reason: every shell sink
        # was resolved clean, none was left unresolved, no command word was expansion-unresolvable
        # (var_cmd), and no unmodelled construct / expansion-eval is present. Any of those keeps the
        # fallback so a genuinely unmodelled danger is never suppressed.
        probe = blank_quoted(deob)
        other_reason = var_cmd or bool(CONSTRUCT_RE.search(probe)) or bool(
            EXPANSION_RE.search(probe) and (EVAL_RE.search(probe) or SHELL_DASH_C_RE.search(probe)))
        if sink_resolved_clean and not sink_unresolved and not other_reason:
            return False
        # A `case` arm body runs on match but its pattern glued to the body's first command at
        # statement level, hiding an assembled `printf … | sh` sink — scan each arm body as an executed
        # script before deferring (Codex #26 r67 F1). Function-def bodies are already exposed by
        # resolve()'s opener strip; the legacy matcher below catches contiguous literals in either.
        for _body in case_arm_bodies(stripped):
            if scan_executed(_body, depth):
                return True
        # Scan the heredoc-STRIPPED text: a body consumed by a shell was already scanned above (its
        # split-flag rm caught by the parser recursion), and a body that is data to `cat`/`echo` must
        # not be matched here — mirrors the bash legacy, which strips heredoc bodies (Codex #26 r15c).
        if legacy_rm_destructive(stripped):
            raise Dangerous()
        raise NeedsFallback()
    return False


# Cap on how many line-prefixes the recovery pass will re-scan — a backstop against an adversarial
# input whose only balanced newlines sit before a huge unparsable region (e.g. a many-line heredoc).
RECOVER_MAX_PREFIXES = 64


def balanced_line_cuts(text):
    """Offsets of every top-level NEWLINE — one that is not inside a quote, `$'…'` ANSI-C string,
    backtick, or `$(`/`<(`/`>(` paren group. bash reads and runs a COMPLETE newline-terminated
    command-list before a LATER line's syntax error aborts the read (an unterminated quote/paren on
    one line consumes continuation lines to EOF, so only a newline outside every open construct ends
    a runnable command). `;`/`&&`/`||`/`&`/`|` do NOT — a syntax error anywhere on the physical line
    makes the whole line fail with nothing run (verified against bash). The prefix up to such a
    newline is exactly what bash executed, so it is what the recovery pass scans."""
    cuts = []
    i, n = 0, len(text)
    in_sq = in_dq = in_ansi = in_bt = False
    depth = 0
    while i < n:
        c = text[i]
        if in_sq:  # plain single quotes: nothing escapes, closes on '
            if c == "'":
                in_sq = False
            i += 1
            continue
        if in_ansi:  # $'…': backslash escapes the next char
            if c == "\\":
                i += 2
                continue
            if c == "'":
                in_ansi = False
            i += 1
            continue
        if in_dq:  # double quotes: backslash escapes, closes on "
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_dq = False
            i += 1
            continue
        if in_bt:  # backtick command substitution
            if c == "\\":
                i += 2
                continue
            if c == "`":
                in_bt = False
            i += 1
            continue
        if c == "\\":  # unquoted backslash escapes the next char (incl. a line-continuation newline)
            i += 2
            continue
        if c == "$" and i + 1 < n and text[i + 1] == "'":
            in_ansi = True
            i += 2
            continue
        if c == "'":
            in_sq = True
        elif c == '"':
            in_dq = True
        elif c == "`":
            in_bt = True
        elif c == "(":
            depth += 1
        elif c == ")":
            if depth:
                depth -= 1
        elif c == "\n" and depth == 0:
            cuts.append(i)
        i += 1
    return cuts


def scan_runnable_prefix(text, base_depth=0, is_script=False):
    """True iff the commands bash actually EXECUTED before a later line's syntax error contain a
    dangerous command in command position. Reached when a parse aborted (unbalanced quote/paren/
    backtick) — at the top level AND inside `scan_executed` for a shell-fed body. Scans the longest
    top-level-newline prefix (the runnable lines) as scan() would, peeling back to an earlier newline
    if the balance model's guess still will not parse. Returns True ONLY for a definitive block; a
    clean or benign leading prefix returns False so the legacy matcher stays the arbiter exactly as
    before (Codex #26 r64 F1)."""
    try:
        cuts = sorted(set(balanced_line_cuts(text)), reverse=True)
    except Exception:
        return False
    for count, end in enumerate(cuts):
        if count >= RECOVER_MAX_PREFIXES:
            break
        prefix = text[:end]
        if not prefix.strip():
            continue
        try:
            return bool(scan(prefix, base_depth, is_script=is_script))
        except Dangerous:
            return True
        except NeedsFallback:
            return False
        except (Unparsable, ValueError, RecursionError, TooDeep):
            continue  # this prefix is itself mid-construct — peel back to an earlier newline
        except Exception:
            continue
    return False


raw = ""
try:
    raw = sys.stdin.read()
    print("BLOCK" if scan(raw) else "ALLOW")
except NeedsFallback:
    print("FALLBACK")
except (Dangerous, TooDeep, RecursionError):
    print("BLOCK")
except Exception:
    # The full parse aborted (unbalanced quote/paren/backtick). bash still EXECUTES every complete
    # newline-terminated command-list BEFORE the line whose syntax error aborts the read, so a
    # dangerous leading line — e.g. a split-literal `printf … | sh` sink — must still BLOCK even
    # though a LATER line is unparsable. Recover the runnable-line prefix and scan it; only a
    # definitive block flips the verdict, everything else defers to the legacy matcher as before
    # (Codex #26 r64 F1).
    print("BLOCK" if scan_runnable_prefix(raw) else "FALLBACK")

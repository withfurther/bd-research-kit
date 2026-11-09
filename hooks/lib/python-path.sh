# shellcheck shell=bash
# Sourced, never executed. Exports CC_PYTHON (absolute path to a stable CPython) and, when it is
# safe to do so, prepends that interpreter's dir to PATH so hooks invoke the real binary instead
# of the pyenv shim.
#
# WHY: macOS leaks a wired 1 KB MAXPATHLEN kernel buffer on every exec of a `#!` script whose
# parent process was itself started from a `#!` script. `python3`/`pytest` here are pyenv shims
# (bash scripts) that exec ~8 more pyenv helper scripts — ~15-21 KB of unreclaimable wired memory
# per call, ~95% of all kernel-zone leak on this machine, reclaimed ONLY by reboot (the zone
# panics near 21.28M elements). Bypassing the shim measured -99% leak and a 3.3x latency win.
#
# SECURITY — NO REPOSITORY-SUPPLIED INPUT MAY INFLUENCE WHICH INTERPRETER RUNS.
# These hooks are security gates (block-dangerous.sh, command-safety-prefilter.sh,
# block-production-push.sh, ...) and they execute in whatever directory the agent is working in.
# `.python-version` is a file ANY repository can ship, so it is deliberately NOT consulted here,
# even though pyenv itself honours it:
#   * Interpolating it into a path was a traversal -> arbitrary-code-execution vector (a payload
#     of `../../../evil` put an attacker-controlled `python3` on PATH INSIDE the gates).
#   * Even restricted to exact matches against installed versions it remained a real attack: a
#     repo could steer a gate onto a different interpreter where the parser errors, and
#     block-dangerous.sh then takes its documented FALLBACK to weaker legacy text matching.
#     Repo-controlled degradation of a safety control is the same defect as repo-controlled code
#     execution, just quieter.
# Only user-level configuration rooted at this file's trusted install location is consulted: the
# global `.pyenv/version` below the derived home. Inherited PYENV_VERSION, PYENV_ROOT, and HOME
# are deliberately ignored. Exact-match validation against installed versions remains defense
# in depth so no unvalidated string is ever interpolated into a path.
#
# VIRTUALENVS ARE REPOSITORY CONTENT — NO EXCEPTION IS MADE FOR THEM.
# A virtualenv normally lives INSIDE the repository (`.venv/`) and is auto-activated by direnv in
# many Python projects, so `VIRTUAL_ENV` and everything in its `bin/` are repo-controlled. An
# earlier revision of this file skipped the PATH prepend when VIRTUAL_ENV was set, to avoid
# shadowing project tooling. That reopened exactly the hole this file exists to close: the gates'
# `python3` resolved to the repo's `.venv/bin/python3`, letting a repository supply the interpreter
# that runs block-dangerous.sh's parser. The prepend is therefore UNCONDITIONAL — a gate must run
# on the trusted interpreter even when a venv is active.
#
# The one hook that legitimately needs project tooling (pre-push-test-gate.sh, which runs the
# project's pytest) deliberately does NOT source this file. That is the correct split: gates get a
# trusted interpreter, project test-running gets the project's. Do not "fix" a shadowed venv by
# adding an exception here — exclude the hook instead.
#
# Resolution uses shell builtins and glob expansion ONLY. Calling `pyenv` to locate the
# interpreter would re-create the very chain this exists to avoid.
#
# If pyenv is absent, the version is unreadable, or no installed version matches, PATH stays
# untouched. Consumers clear inherited CC_PYTHON first and handle an unavailable resolver.

__cc_pyenv_path_init() {
  local root ver chosen self_dir derived cand
  # Neutralise inherited field-splitting; every expansion below is quoted, but a hostile
  # IFS must not reach `read`.
  local IFS=$' \t\n'
  local cands

  # NO environment variable steers interpreter selection — not PYENV_ROOT, not PYENV_VERSION, and
  # not even $HOME. All are inherited and unvalidated: an attacker-set root containing
  # versions/<name>/bin/python3 would pass both the exact-match check and the ownership check
  # below (they would own it) and become the gates' interpreter.
  #
  # The root is instead derived from THIS FILE'S OWN INSTALL LOCATION, which is trusted for the
  # same reason the hooks are: anyone who can relocate it already controls the hook code. This is
  # also why $HOME is not used as a fallback — reintroducing it would reintroduce the vector. A
  # side benefit is robustness: a harness or sandbox that rewrites HOME (tests, sudo -H, launchd)
  # no longer silently strips the gates of their interpreter and pushes them onto a degraded path.
  # Normalise this file's own location before deriving anything from it. A hook can legitimately
  # be invoked relatively (`./block-dangerous.sh`, `hooks/block-dangerous.sh`, `bash hook.sh`,
  # a path containing `..`), and a suffix-match on the raw string silently failed for every one of
  # those — leaving CC_PYTHON unset and dropping the gate onto its degraded path (for
  # pre-push-codex-review.sh, an `exit 0` fail-open SKIP). Resolution must not depend on HOW the
  # hook was invoked. `cd`/`pwd` are builtins and the subshell forks without exec, so this costs
  # no kalloc leak.
  self_dir="${BASH_SOURCE[0]%/*}"
  [ "$self_dir" = "${BASH_SOURCE[0]}" ] && self_dir="."

  # Make the path ABSOLUTE before any cd. Given a relative argument that does not begin with `/`,
  # `./` or `../` — exactly what `hooks/lib/../../..` is when a hook is invoked as `hooks/hook` —
  # bash's cd searches $CDPATH, an inherited attacker-settable variable. Measured: with
  # CDPATH=/tmp/cdp the cd resolved to /tmp AND echoed its target, so the capture became
  # "/tmp\n/private/tmp", CC_PYTHON came out UNSET, and block-direct-main-push.sh returned
  # exit 0 — a direct push to main ALLOWED. An absolute argument is never CDPATH-searched.
  case "$self_dir" in
    /*) ;;
    *) self_dir="${PWD}/${self_dir}" ;;
  esac

  # `CDPATH=` is belt-and-braces once the path is absolute; `builtin` prevents an exported shell
  # function named cd or pwd (inherited via BASH_FUNC_*) from hijacking the resolution.
  derived=$(CDPATH='' builtin cd -P -- "$self_dir/../../.." 2>/dev/null && builtin pwd -P) || return 0
  # Reject anything that is not a single absolute path (a CDPATH-style echo yields two lines).
  case "$derived" in
    *$'\n'*) return 0 ;;
    /*) ;;
    *) return 0 ;;
  esac
  root="$derived/.pyenv"
  [ -d "$root/versions" ] || return 0

  # User-level candidates only, in precedence order. An invalid candidate is SKIPPED rather than
  # fatal, so a stale global version file cannot suppress resolution and silently push callers
  # onto whatever `python3` PATH happens to hold (for the audit-log shipper that would be
  # /usr/bin/python3, which lacks google-cloud-logging — breaking OPS-296 with no error).
  # PYENV_VERSION is likewise inherited and unvalidated, and is not honoured. Only the on-disk
  # global version file selects the version.
  cands=()
  if [ -r "$root/version" ]; then
    read -r ver < "$root/version" 2>/dev/null || ver=""
    [ -n "$ver" ] && cands+=("$ver")
  fi
  [ "${#cands[@]}" -gt 0 ] || return 0

  chosen=""
  for ver in "${cands[@]}"; do
    # A version file may carry several versions on one line, or a trailing CR; take the first token.
    ver="${ver%%[[:space:]]*}"
    [ -n "$ver" ] || continue
    # Defense in depth: the exact-match loop below already makes these unrepresentable.
    case "$ver" in
      */*|*\\*|.|..|.*) continue ;;
    esac
    # Construct the path DIRECTLY rather than enumerating with a glob. Bash imports SHELLOPTS
    # from the environment, so an inherited `SHELLOPTS=noglob` disabled pathname expansion, the
    # enumeration matched nothing, CC_PYTHON came out unset, and block-direct-main-push.sh took
    # its fail-open branch — exit 0 on a `git push origin main`. GLOBIGNORE is the same class.
    # Direct construction is safe here because $ver no longer has any repo-supplied source (the
    # `.python-version` walk was removed): it comes only from the on-disk global version file, is
    # shape-validated above, and the executable is ownership-checked below.
    cand="$root/versions/$ver/bin"
    if [ -f "$cand/python3" ] && [ -x "$cand/python3" ] && [ -O "$cand/python3" ]; then
      chosen="$cand"
    fi
    [ -n "$chosen" ] && break
  done
  [ -n "$chosen" ] || return 0

  CC_PYTHON="$chosen/python3"
  export CC_PYTHON

  case ":${PATH:-}:" in
    *":$chosen:"*) return 0 ;;
  esac

  PATH="$chosen:$PATH"
  export PATH
}

__cc_pyenv_path_init
unset -f __cc_pyenv_path_init

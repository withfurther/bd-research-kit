#!/usr/bin/env bash
# Claude Code PreToolUse hook — blocks destructive bash commands
# Exit 0 = allow, exit 2 = block
#
# Command-position aware (OPS-523). A dangerous token is blocked when it is the COMMAND being
# run, and allowed when it is DATA inside an argument (`echo "rm -rf /"`, `git commit -m "..."`,
# `grep -r "rm -rf" .`). The previous implementation deleted quote characters and regex-matched
# the whole string: that caught quoted-argument bypasses (`rm -rf "$HOME"`) but blocked any
# command that merely *mentioned* a dangerous string.
#
# Fail-safe by construction. Three outcomes from the parser:
#   BLOCK    — a dangerous command was found in command position (or nesting exceeded the budget)
#   ALLOW    — parsed cleanly, nothing dangerous in command position
#   FALLBACK — could not parse (unbalanced quotes, shlex error, python3 absent); the legacy
#              strip-and-match matcher decides, preserving the old over-blocking behavior
set -euo pipefail

input=$(cat)

deny() {
  cat <<HOOKEOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Blocked by safety hook: destructive command pattern detected"}}
HOOKEOF
  exit 2
}

command_str=""
if command -v jq &>/dev/null; then
  command_str=$(printf '%s' "$input" | jq -r '.tool_input.command // ""' 2>/dev/null) || true
elif command -v python3 &>/dev/null; then
  # jq absent but python3 (the parser's OWN dependency) is present — parse the JSON properly so an
  # ESCAPED quote in the value is not truncated. `grep -o '"command":"[^"]*"'` stopped at the first
  # \" and extracted `rm -rf \` for `rm -rf "$HOME"`, exiting 0 on a supported fallback (Codex #26 r38 F1).
  command_str=$(printf '%s' "$input" | python3 -c 'import json, sys
try:
    sys.stdout.write(json.load(sys.stdin).get("tool_input", {}).get("command", "") or "")
except Exception:
    pass' 2>/dev/null) || true
else
  # Doubly-degraded host (no jq AND no python3): only the legacy text matcher can run. A JSON string
  # body is (non-quote-non-backslash | backslash-escape)*; `sed -nE` (ERE — `|` works on stock BSD and
  # GNU sed, unlike BRE) captures that, so an escaped quote no longer truncates the command. Optional
  # whitespace around the `:` is tolerated. Then unescape the common \" and \\ so the matcher sees the
  # effective text (best-effort; the legacy matcher over-blocks anyway).
  #
  # A TRIPLY-degraded host (also no `sed` or `head`) cannot extract the command AT ALL, and cannot run
  # the parser — the `|| true` would leave command_str empty and the empty-check below would exit 0 on
  # an unseen `rm -rf /`. There is no way to verify safety, so fail CLOSED (Codex #26 r63 F1).
  if ! { command -v sed && command -v head; } &>/dev/null; then
    deny
  fi
  command_str=$(printf '%s' "$input" \
    | sed -nE 's/.*"command"[[:space:]]*:[[:space:]]*"(([^"\]|\\.)*)".*/\1/p' | head -1) || true
  command_str=${command_str//\\\"/\"}
  command_str=${command_str//\\\\/\\}
fi

if [[ -z "$command_str" ]]; then
  exit 0
fi

# python-absent counterpart to the python legacy_rm_destructive: a split/reordered-flag rm targeting
# root/home/cwd found anywhere in the flattened text (`rm -r -f /`, `rm --recursive --force ~`). The
# array patterns only know clustered `-rf`, so without this a construct that executes argument data
# (git alias, interpreter string, runner, tar/rsync/submodule) would slip a split-flag rm past the
# no-python legacy path (Codex #26 r15c F1). Word-split with globbing disabled so `/*` cannot expand.
legacy_rm_split() {
  local text="$1" i j n base w has_r has_f
  text=${text//\\/}; text=${text//\'/}; text=${text//\"/}
  text=$(printf '%s' "$text" | sed 's/[;&|]/ & /g')
  local -a words
  set -f
  # shellcheck disable=SC2206
  words=( $text )
  set +f
  # Home targets are home ITSELF or a glob wipe of it, not an ordinary path beneath it — a bare `~`
  # here matched `~/tmp/scratch` too, denying an everyday command on the no-python path (self-audit,
  # r27 sweep). Kept in lockstep with the parser's HOME_TARGET.
  # A run of `/.`/`/..` dot-segments before a glob normalizes back to the same home/cwd wipe
  # (`~/./*`, `~/../*`); a real subdir name stops the run (`~/build` stays allowed). Codex #26 r42 F1.
  local tre='^(/([^A-Za-z]|$)|(~([+-]|[A-Za-z_][A-Za-z0-9_.-]*)?|\$\{?(HOME|PWD|OLDPWD)\}?)(/(\.\.?|[*?].*)?)*$|\.(/(\.\.?|[*?].*)?)*$)'
  n=${#words[@]}
  for (( i = 0; i < n; i++ )); do
    base=${words[i]##*/}
    [[ $base == rm ]] || continue
    has_r=0; has_f=0
    for (( j = i + 1; j < n; j++ )); do
      w=${words[j]}
      case $w in
        ';'|'&'|'|') break ;;
        --recursive) has_r=1 ;;
        --force) has_f=1 ;;
        --*) ;;
        -*) [[ $w == *[rR]* ]] && has_r=1; [[ $w == *f* ]] && has_f=1 ;;
        *) if (( has_r && has_f )) && [[ $w =~ $tre ]]; then return 0; fi ;;
      esac
    done
  done
  return 1
}

# Legacy strip-and-match fallback path (the pre-OPS-523 matcher, kept over-blocking by design;
# hardened where its stripping LOST a dangerous literal — see the herestring guard below).
legacy_is_dangerous() {
  # $2=1 → also re-scan shell-fed heredoc bodies (the NO-PYTHON path, which has no parser to catch
  # them). On the FALLBACK path (python present) the parser already resolved every heredoc precisely
  # (`echo bash <<EOF` data vs `bash <<EOF` script, per-statement `cat <<A; bash <<B`), so re-scanning
  # here would only re-introduce over-blocks the parser already avoided — leave it off (Codex #26 r52 F2).
  local text="$1" _scan_hd="${2:-0}" stripped joined quoteless unescaped
  # A herestring is NOT a heredoc: `done <<< 'rm -rf /'` matched the heredoc-strip range below at
  # its `<<`, which deleted the whole line and lost the dangerous literal the fallback exists to
  # catch (Codex #26 r16). Neutralize the operator so its payload stays visible to the greps.
  text=${text//<<</ __HERESTRING__ }
  # A `<<` behind a `#` is inside a COMMENT, not a heredoc operator — and the range address deleted
  # everything after it, so `# <<EOF` ⏎ `rm -rf /` lost the live command on this path too (found
  # while fixing Codex #26 r31 F1 in the parser). Requiring no `#` before the `<<` keeps a real
  # heredoc stripped while leaving a commented one alone. `echo "# x" <<EOF` then over-blocks, which
  # is this matcher's documented direction.
  stripped=$(printf '%s' "$text" | sed '/^[^#]*<<['"'"']\{0,1\}[A-Za-z_]*['"'"']\{0,1\}/,/^[A-Za-z_]\{1,\}$/d')
  # Bash's own quote removal (`r\m`, `$'rm'`, `"rm"` all resolve to `rm`) is one CANDIDATE spelling,
  # not the only one: deleting backslashes also destroys a boundary the patterns depend on, so
  # `printf 'rm -rf /\n' | bash` collapsed to `rm -rf /n` and `/([^a-zA-Z]|$)` stopped matching
  # (Codex #26 r15 F2, root cause). Test BOTH spellings and block if EITHER matches — the union
  # keeps this matcher no weaker than the unanchored one it inherits from.
  quoteless=$(printf '%s' "$stripped" | sed "s/['\"]//g")
  unescaped=$(printf '%s' "$stripped" | sed -e 's/\\//g' -e "s/\$'/'/g" -e "s/['\"]//g")
  local legacy_patterns=(
    'rm\s+-rf\s+/([^a-zA-Z]|$)'
    # A run of `/.`/`/..` dot-segments before a glob normalizes back to the same home/cwd wipe
    # (`~/./*`, `~/../*`, `$HOME/./*`); a real subdir stops the run so `~/build/*` stays allowed
    # (Codex #26 r42 F1). Glob content excludes separators so a match cannot cross a statement.
    'rm\s+-rf\s+~([+-]|[A-Za-z_][A-Za-z0-9_.-]*)?(/(\.\.?|[*?][^[:space:];&|]*)?)*([[:space:]]|;|&|\||$)'
    'rm\s+-rf\s+\$\{?(HOME|PWD|OLDPWD)\}?(/(\.\.?|[*?][^[:space:];&|]*)?)*([[:space:]]|;|&|\||$)'
    'rm\s+-rf\s+\.(/(\.\.?|[*?][^[:space:];&|]*)?)*([[:space:]]|;|&|\||$)'
    # NOTE: these are ERE strings for `grep -E`, where a `\` inside a bracket expression is a
    # LITERAL backslash — `[^\s;&|]` therefore means "not one of \ s ; & |", excluding the LETTER
    # `s`. On the stock `/usr/bin/grep` that made the token walks below stop at any `s`, so
    # `git push -f upstream main` slipped the legacy path entirely (found while fixing r19; ugrep,
    # which this box uses, hides it by treating bracket-`\s` as whitespace). POSIX classes
    # (`[[:space:]]`) mean the same thing in every grep. Outside brackets `\s` is a GNU/ugrep
    # extension that the stock grep does honor, so the existing `\s+` terms stay as they are.
    # Kept in lockstep with the parser's DEVICE_FAMILY: bare `mkfs` needs a `/dev/` operand (so
    # `mkfs --help` is not denied) and `dd` only destroys when its `of=` names a raw disk, not
    # `/dev/null` or `/dev/stdout` (Codex #26 r24 F4).
    'mkfs\.'
    'mkfs\s+[^;&|]*/dev/'
    'dd\s+[^;&|]*of=/dev/(sd|nvme|vd|hd|xvd|mmcblk|loop|dm-|md[0-9]|md/|mapper/|disk/|r?disk[0-9])'
    '>\|?[[:space:]]*/dev/(sd|nvme|vd|hd|xvd|mmcblk|loop|dm-|md[0-9]|md/|mapper/|disk/|r?disk[0-9])'
    'chmod\s+([^[:space:];&|]+\s+)*(-[A-Za-z]*R[A-Za-z]*|--recursive)\s+([^[:space:];&|]+\s+)*0?777\s+([^[:space:];&|]+\s+)*/'
    'chmod\s+([^[:space:];&|]+\s+)*0?777\s+([^[:space:];&|]+\s+)*(-[A-Za-z]*R[A-Za-z]*|--recursive)\s+([^[:space:];&|]+\s+)*/'
    ':\(\)\{\s*:\|:&\s*\};:'
    'git\s+(-[^[:space:];&|]*([[:space:]]+[^[:space:];&|]+)?[[:space:]]+)*push(\s[^[:space:];&|]*)*\s--force(-with-lease(=\S*)?)?(\s[^[:space:];&|]*)*\s([^[:space:];&|]*[:/])?(main|master)([[:space:];&|]|$)'
    'git\s+(-[^[:space:];&|]*([[:space:]]+[^[:space:];&|]+)?[[:space:]]+)*push(\s[^[:space:];&|]*)*\s-[A-Za-z0-9]*f[A-Za-z0-9]*(\s[^[:space:];&|]*)*\s([^[:space:];&|]*[:/])?(main|master)([[:space:];&|]|$)'
    'git\s+(-[^[:space:];&|]*([[:space:]]+[^[:space:];&|]+)?[[:space:]]+)*push(\s[^[:space:];&|]*)*\s([^[:space:];&|]*[:/])?(main|master)(\s[^[:space:];&|]*)*\s(--force(-with-lease(=\S*)?)?|-[A-Za-z0-9]*f[A-Za-z0-9]*)([[:space:];&|]|$)'
    'git\s+(-[^[:space:];&|]*([[:space:]]+[^[:space:];&|]+)?[[:space:]]+)*push(\s[^[:space:];&|]*)*\s\+([^[:space:];&|]*:)?(refs/heads/)?(main|master)([[:space:];&|]|$)'
    'git\s+(-[^[:space:];&|]*([[:space:]]+[^[:space:];&|]+)?[[:space:]]+)*reset\s+--hard\s+origin/(main|master)'
    'curl\s+.*\|\s*(sh|bash|zsh)'
    'wget\s+.*\|\s*(sh|bash|zsh)'
  )
  joined=$(IFS='|'; echo "${legacy_patterns[*]}")
  printf '%s' "$quoteless" | grep -qEi "$joined" 2>/dev/null && return 0
  printf '%s' "$unescaped" | grep -qEi "$joined" 2>/dev/null && return 0
  # A heredoc body fed to a SHELL is a SCRIPT, so `bash <<EOF … rm -rf / … EOF` is dangerous even
  # though the strip above removed it as if it were data — the parser catches this, so the no-python
  # fallback must too (Codex #26 r52 F2). Re-scan the body of any heredoc whose INTRODUCER line
  # carries a shell command word; over-matching `echo bash <<EOF` is this matcher's documented
  # over-block direction. bash 3.2 + stock grep/sed only.
  # A shell READS the heredoc (stdin) only when it is followed by OPTIONS then the heredoc `<<`, a
  # pipe, or end-of-line — NOT when it has a script-FILE operand (`bash deploy.sh`, r51 F1) or an
  # overriding single-`<` stdin redirect (`bash < /dev/null`, r50 F3), which make the heredoc that
  # file's/redirect's data. Matching a bare `bash` anywhere over-blocked those (Codex kit#26 r52 F2).
  if [[ "$_scan_hd" == 1 ]]; then
    local _intro_re='(^|[;&|]|[[:space:]])([^[:space:];&|]*/)?(sh|bash|zsh|dash|ksh)([[:space:]]+[-+][^[:space:];&|<>]*)*[[:space:]]*(<<|\||$)'
    local _hd_re='<<(-?)['"'"'"]?([A-Za-z_][A-Za-z0-9_]*)'
    local _in=0 _delim="" _dash="" _body="" _line _cand _q
    while IFS= read -r _line; do
      if (( _in )); then
        _cand="$_line"
        if [[ -n "$_dash" ]]; then while [[ "$_cand" == $'\t'* ]]; do _cand="${_cand#$'\t'}"; done; fi
        if [[ "$_cand" == "$_delim" ]]; then
          _q=$(printf '%s' "$_body" | sed "s/['\"]//g")
          printf '%s' "$_q" | grep -qEi "$joined" 2>/dev/null && return 0
          legacy_rm_split "$_q" && return 0
          _in=0; _body=""
          continue
        fi
        _body+="$_line"$'\n'
        continue
      fi
      if [[ "$_line" =~ $_hd_re ]]; then
        _dash="${BASH_REMATCH[1]}"; _delim="${BASH_REMATCH[2]}"     # capture BEFORE the next =~ clobbers it
        if [[ "$_line" =~ $_intro_re ]]; then _in=1; _body=""; fi
      fi
    done <<< "$text"
  fi
  # Scan the heredoc-STRIPPED text so a heredoc body that is data (to `cat`/`echo`) is not matched,
  # matching the grep above which runs on `stripped` (Codex #26 r15c).
  legacy_rm_split "$stripped"
}

# Fast path. python3 costs ~150ms to start (pyenv shim); this hook runs on every Bash call, so
# only pay it when a block is even possible. The regex below is a NECESSARY CONDITION for the
# parser to return BLOCK: every blocking rule requires one of these literals to survive quote
# removal — the rm/mkfs/chmod/git rules by construction, `dd if=..of=/dev/` and `> /dev/<disk>` via
# /dev/, the fork bomb via :(), and pipe-to-shell via curl/wget. A dangerous script hidden in a
# wrapper (`sh -c`, eval, $(...)) is a substring of this same text, so it triggers too.
# Bash's own quote removal is applied first — backslashes deleted and `$'…'` reduced to `'…'` —
# because bash resolves `r\m`, `$'rm'`, and `"rm"` all to `rm`. Newlines are folded so a pattern
# split across lines still matches. Over-triggering only costs a python run; under-triggering
# would skip the matcher entirely, so this must stay at least as permissive as both matchers.
#
# Done with parameter expansion rather than `sed | tr`: a missing coreutil would abort the script
# under `set -e` with a non-2 status, which the harness reads as ALLOW — a fail-open. This also
# removes three forks from the hot path.
trigger_text=${command_str//\\/}
trigger_text=${trigger_text//\$\'/\'}
trigger_text=${trigger_text//\'/}
trigger_text=${trigger_text//\"/}
# A newline-PRESERVING copy: bash starts a command after a newline, so command-position detection
# (the r71 dynamic-command-word clause) must see them — the flattened `trigger_text` cannot (r71 F1).
_trigger_nl=$trigger_text
trigger_text=${trigger_text//$'\n'/ }

# Matched with bash's own regex rather than grep: the fast path must never depend on an external
# binary, because a missing one aborts the script under `set -e` with a non-2 status and the
# harness reads that as ALLOW.
# `rm[[:space:]]+[0-9&]*[<>]` triggers when a redirection sits between `rm` and its flags
# (`rm >&2 -rf /`); `\$[0-9@*]` triggers on a positional-parameter reference so a `-c` script that
# smuggles flags through `$@`/`$1` (`bash -c 'rm "$@"' _ -rf /`) reaches the parser, which
# substitutes them. Only `$0-9`/`$@`/`$*` match — `$HOME`/`$?`/`${…}` do not, so benign commands
# stay off the python path.
# `git[[:space:]]+(push|reset)` missed a GLOBAL option before the subcommand (`git -C /tmp push
# --force main`), which the patterns now block — the trigger must stay a necessary condition for
# every block rule, so it accepts any option words between `git` and its subcommand.
# `find[[:space:]][^;&|]*-delete` triggers on find's own recursive-delete action (`find / -delete` =
# `rm -rf /`), which carries no `rm`; the parser confirms the search path is an absolute root/home
# wipe (a cwd/relative path is a documented boundary — OPS-541 — and stays allowed). self-audit r50.
TRIGGER_RE='rm[[:space:]]+-rf|rm[[:space:]]+[0-9&]*[<>]|\$\{?[0-9@*]|mkfs|chmod[[:space:]][^;&|]*(-r|777)|/dev/|:\(\)|git[[:space:]][^;&|]*(push|reset)|find[[:space:]][^;&|]*-delete|curl|wget'
shopt -s nocasematch
_triggered=0
[[ $trigger_text =~ $TRIGGER_RE ]] && _triggered=1
# `rm` with recursive AND force in ANY flag arrangement (`-r -f`, `-fr`, `--recursive --force`) is a
# necessary condition the clustered-`-rf` trigger misses; the parser confirms the target. Requiring
# BOTH keeps the common `rm -f <file>` / `rm -r <dir>` off the python path (Codex #26 r15b F1).
# `rm` need not be followed by a space: `xargs` supplies its argv, so the command can END the text
# (`printf '%s\n' '-rf /' | xargs rm` runs `rm -rf /` — Codex #26 r28 F1). Requiring a trailing
# space let the trigger exit before the parser, which does block it.
if (( ! _triggered )) && [[ $trigger_text =~ (^|[^[:alnum:]])rm([^[:alnum:]]|$) ]] \
    && [[ $trigger_text =~ (-[[:alpha:]]*r|--recursive) ]] \
    && [[ $trigger_text =~ (-[[:alpha:]]*f|--force) ]]; then
  _triggered=1
fi
# An UNRESOLVABLE command word splits a dangerous literal so that no contiguous spelling of it
# survives in the text: `$(echo rm) -rf /` and `c=rm; $c -rf /` both run `rm -rf /`, and every
# alternative above is anchored on a contiguous form. The parser reassembles them (inline_command_word),
# but only if it RUNS — so the trigger, which must stay a NECESSARY condition for any block, has to
# admit them. Requiring an expansion AND a destructive word keeps ordinary substitutions
# (`echo $(date)`, `cd "$(dirname "$0")"`) off the python path (self-audit, r21 differential).
if (( ! _triggered )) \
    && [[ $trigger_text =~ (\$\(|\`|\$\{?[A-Za-z_]) ]] \
    && [[ $trigger_text =~ ((^|[^[:alnum:]])(rm|chmod|mkfs|dd|git|curl|wget)([^[:alnum:]]|$)|777|/dev/|--force|-[[:alpha:]]*r[[:alpha:]]*f) ]]; then
  _triggered=1
fi
# The clause above requires a CLUSTERED `-rf` or a literal command name, but the parser also blocks
# an unresolvable command word whose argv is destructive on its own: `$X -r -f /` (split flags) and
# `$X push -f main` / `$X reset --hard origin/main` (the command name lives in the variable, so
# neither `rm` nor `git` appears). Without these the trigger exits before the parser ever runs
# (Codex #26 r27 F1). Both still require an expansion, so ordinary commands stay off the python path.
if (( ! _triggered )) \
    && [[ $trigger_text =~ (\$\(|\`|\$\{?[A-Za-z_]) ]] \
    && [[ $trigger_text =~ (-[[:alpha:]]*r|--recursive) ]] \
    && [[ $trigger_text =~ (-[[:alpha:]]*f|--force) ]]; then
  _triggered=1
fi
if (( ! _triggered )) \
    && [[ $trigger_text =~ (\$\(|\`|\$\{?[A-Za-z_]) ]] \
    && [[ $trigger_text =~ (^|[[:space:]])(push|reset)([[:space:]]|$) ]]; then
  _triggered=1
fi
# A command word built from an expansion may resolve to `find`, whose own `-delete` action wipes the
# search path with no `rm` present (`c=find; $c / -delete` — the parser resolves `$c` and blocks). The
# literal `find … -delete` clause in TRIGGER_RE cannot see the variable-held `find`, so admit an
# expansion alongside a `-delete` word (Codex #26 r59 F1). Over-triggering only costs a python run.
if (( ! _triggered )) \
    && [[ $trigger_text =~ (\$\(|\`|\$\{?[A-Za-z_]) ]] \
    && [[ $trigger_text =~ (^|[[:space:]])-delete([[:space:]]|$) ]]; then
  _triggered=1
fi
# A FULLY expansion-assembled command builds its command word AND flags AND target from expansions,
# so NO dangerous literal survives quote removal — every clause above needs one, yet the parser
# resolves the assignments/subs and BLOCKs (`r=$(printf r)m; a=-; b=r; c=f; t=/; $r $a$b $a$c $t`
# runs `rm -r -f /`, a trigger-invariant break — Codex #26 r70 F1). The one NECESSARY signal is a
# dynamic command word (`$var`/`${var`/`$(`/backtick) at COMMAND POSITION. bash starts a command at
# the start and after `;`/`&`/`|`/newline/`(`/`{`/`!` and the reserved words `then`/`do`/`else`/`elif`
# (Codex #26 r71 F1) — checked on the newline-preserving copy. Over-triggering only costs a python run
# (`$EDITOR file` / `$(which ls) -la` parse then ALLOW); a `$var` in ARGUMENT position (`echo $x`) is
# not command position. Regexes are single-quoted so backtick/`(` are literal, not shell metachars;
# the newline is spliced into the first bracket via `$'\n'`.
_nl=$'\n'
_cmdpos_a='(^|[;&|(){}!'"$_nl"'])[[:space:]]*(\$[A-Za-z_{(]|`)'
_cmdpos_b='(^|[[:space:]])(then|do|else|elif)[[:space:]]+(\$[A-Za-z_{(]|`)'
if (( ! _triggered )) && { [[ $_trigger_nl =~ $_cmdpos_a ]] || [[ $_trigger_nl =~ $_cmdpos_b ]]; }; then
  _triggered=1
fi
# A pipe into a SHELL is a script sink whose text may be assembled from fragments that contain no
# dangerous literal at all: a fetcher name built from pieces (`c=c; u=url; $c$u … | sh` — Codex #26
# r29 F1) or a printer whose output IS the script (`printf '%s' r m ' -rf /' | sh` — r30 F4, which
# has no expansion, so this clause cannot require one). The parser resolves both and returns BLOCK,
# so the trigger must let it run. `… | sh` is rare enough that always parsing it costs nothing.
if (( ! _triggered )) \
    && [[ $trigger_text =~ \|[[:space:]]*([A-Za-z_/.-]*/)?(sh|bash|zsh|dash|ksh)([^[:alnum:]]|$) ]]; then
  _triggered=1
fi
# The shell of a pipe-into-a-shell sink may sit behind WRAPPERS that resolve() strips — `printf … |
# sudo bash`, `| env X=1 bash`, `| timeout 1 bash`, `| nice bash`, `| sudo -n /bin/bash` — so the
# parser BLOCKs them, but the immediate-`| shell` clause above missed them: a trigger-invariant break
# (Codex #26 r39 F1). Admit a shell that appears anywhere in the SAME pipeline stage after the pipe
# (one-or-more non-pipe chars then whitespace then the shell). Over-triggering only costs a python run
# (`| grep bash` parses then ALLOWs); `| grep foo` has no shell word and does not trigger.
if (( ! _triggered )) \
    && [[ $trigger_text =~ \|[^|]+[[:space:]]([A-Za-z_/.-]*/)?(sh|bash|zsh|dash|ksh)([^[:alnum:]]|$) ]]; then
  _triggered=1
fi
# An INPUT process substitution `<(…)` fed to a shell / `source` / interpreter as its SCRIPT FILE
# executes that file's OUTPUT, and a printer can assemble the script from operands split so no literal
# survives quote removal (`bash <(printf '%s' r m ' -rf /')` — the inter-operand SPACE stays, so `rm`
# never re-forms in trigger_text). The parser reassembles the printer output (procsub_script_argv), so
# the trigger — a necessary condition for every block — must admit `<(` alongside a consumer word.
# `make -f <(…)` (a Makefile recipe) and `awk -f <(…)` (an awk program whose `system(…)` is shell) also
# EXECUTE the substitution's output, so they belong here too (Codex #26 r55 F1). Over-triggering here
# only costs a python run; `<(` with no such consumer (`diff <(…) <(…)`) does not.
if (( ! _triggered )) && [[ $trigger_text == *'<('* ]] \
    && [[ $trigger_text =~ (^|[^[:alnum:]_.])(sh|bash|zsh|dash|ksh|source|python[0-9.]*|perl|ruby|node|nodejs|php|lua|tclsh|osascript|deno|bun|Rscript|make|gmake|bmake|gnumake|awk|gawk|mawk)([^[:alnum:]_]|$) ]]; then
  _triggered=1
fi
# Dot-source of an input procsub (`. <(printf …)`) — `.` is a command word, not in the name list above.
if (( ! _triggered )) && [[ $trigger_text == *'<('* ]] \
    && [[ $trigger_text =~ (^[[:space:]]*|[;\&\|\(][[:space:]]*)\.[[:space:]] ]]; then
  _triggered=1
fi
shopt -u nocasematch

# ANSI-C quoting ($'\x72\x6d' → rm) can spell a dangerous command word in escapes the pure-bash
# trigger cannot cheaply decode, so it would exit ALLOW before the parser runs (Codex #26 r5 F2).
# Force the python path whenever $'...' is present; the parser's deobfuscate decodes it.
_ansic="\$'"
if [[ $command_str == *"$_ansic"* ]]; then
  _triggered=1
fi

if (( ! _triggered )); then
  exit 0
fi

# Past the trigger, the command contains at least one dangerous token. If neither analyser can run,
# denying is the only safe answer — silently allowing was the pre-existing behavior and it let a
# `rm -rf /` through on a host missing sed or grep. Benign commands never reach here.
matcher_available() {
  command -v sed &>/dev/null && command -v grep &>/dev/null
}

if ! command -v python3 &>/dev/null; then
  matcher_available || deny
  # find's `-delete`/`-exec` actions are PARSER-ONLY — the legacy matcher has no find model and cannot
  # substitute a search path into the action, so `find / -delete` would exit 0 on a python-absent host
  # (Codex #26 r63 F2). Conservatively deny a find carrying such an action alongside an absolute/home/
  # `$PWD` search path; a purely cwd-relative find (`find . -delete`) is left to the legacy matcher.
  # Over-blocking an ordinary absolute path is the fail-safe on the degraded path.
  if [[ $command_str =~ (^|[^[:alnum:]./])(find|gfind)[[:space:]] ]] \
     && [[ $command_str =~ [[:space:]](-delete|-exec|-execdir|-ok|-okdir)([[:space:]]|$) ]] \
     && [[ $command_str =~ (^|[[:space:]])(/|~|\$\{?HOME|\$\{?PWD|\$\{?OLDPWD) ]]; then
    deny
  fi
  legacy_is_dangerous "$command_str" 1 && deny   # 1 → re-scan shell-fed heredocs (no parser here)
  exit 0
fi

# The parser is a sibling MODULE, not a heredoc: its source is ~67KB, which exceeds the pipe buffer,
# so bash would spool a heredoc that large through a temp file. On a host with a read-only /tmp that
# silently yielded an EMPTY parser and the hook degraded to the legacy matcher — re-blocking the data
# cases OPS-523 allows AND failing open on the parser-only protections (`bash <<EOF … rm -rf / … EOF`
# was allowed). Codex #26 r22 F1. Resolving a sibling file needs no temp storage.
#
# Past the trigger a dangerous token is present and python3 exists (checked above), so a parser that
# is missing or unreadable means a truncated/partial install — not a supported degradation. Deny,
# rather than silently becoming the weaker hook this one replaces.
#
# `${BASH_SOURCE[0]%/*}` returns the NAME unchanged when the hook is invoked without a directory
# component (a PATH lookup), which would resolve the parser against the caller's cwd. Fall back to
# `.` only in that case.
_hook_path="${BASH_SOURCE[0]}"
_hook_dir="${_hook_path%/*}"
[[ "$_hook_dir" == "$_hook_path" ]] && _hook_dir="."
_parser="$_hook_dir/block-dangerous.py"
if [[ ! -r $_parser ]]; then
  deny
fi

verdict=$(printf '%s' "$command_str" | python3 "$_parser" 2>/dev/null) || verdict="FALLBACK"

case "$verdict" in
  BLOCK) deny ;;
  ALLOW) exit 0 ;;
  *)
    matcher_available || deny
    legacy_is_dangerous "$command_str" && deny
    exit 0
    ;;
esac

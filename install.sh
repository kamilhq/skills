#!/bin/sh
# Install skills from this repository for Claude Code and/or Codex.
#
#   curl -fsSL https://raw.githubusercontent.com/kamilhq/skills/main/install.sh | sh -s -- --agent claude --skill games
#
# or from a checkout:  sh install.sh [options]
#
# Options
#   --agent A       claude, codex or both (repeatable, or comma-separated)
#   --skill S       a skill name, a group (a folder under skills/, e.g. games, apple) or all
#                   (repeatable, or comma-separated)
#   --project DIR   install into a project (DIR/.claude/skills, DIR/.agents/skills) instead of for your user
#                   (~/.claude/skills, ~/.agents/skills)
#   --ref REF       branch, tag or commit to install from (default: main)
#   --repo O/N      GitHub repository to install from (default: kamilhq/skills)
#   --local         use the checkout this script is in instead of downloading
#   --force         replace skill folders that were not installed by this script
#   --dry-run       show what would be installed, change nothing
#   --list          list the available skills and exit
#   -h, --help      this help
#
# Without --agent or --skill, and with a terminal, it asks. A skill that needs another skill brings it along.
# Reinstalling replaces the folders this script installed earlier (it marks them with .skills-install);
# nothing else in the skills folders is touched. Needs: sh, tar, and curl or wget (only when downloading).
set -eu

REPO=kamilhq/skills
REF=main
AGENTS=
SKILLS=
PROJECT=
LOCAL=0
FORCE=0
DRY=0
LIST=0
MARK=.skills-install

# skills that need another skill to be useful: "skill:needed ..."
REQUIRES='game-rewrite:byte-identical-game-decomp'

say() { printf '%s\n' "$*"; }
err() { printf 'install.sh: %s\n' "$*" >&2; }
die() { err "$*"; exit 1; }
usage() { sed -n '2,/^set -eu/p' "$0" 2>/dev/null | sed '$d' | sed 's/^# \{0,1\}//'; }

need_arg() { [ $# -ge 2 ] && [ -n "$2" ] || die "$1 needs a value"; }
while [ $# -gt 0 ]; do
  case $1 in
    --agent) need_arg "$@"; AGENTS="$AGENTS,$2"; shift 2 ;;
    --agent=*) AGENTS="$AGENTS,${1#*=}"; shift ;;
    --skill|--skills) need_arg "$@"; SKILLS="$SKILLS,$2"; shift 2 ;;
    --skill=*|--skills=*) SKILLS="$SKILLS,${1#*=}"; shift ;;
    --project) need_arg "$@"; PROJECT=$2; shift 2 ;;
    --project=*) PROJECT=${1#*=}; shift ;;
    --ref) need_arg "$@"; REF=$2; shift 2 ;;
    --ref=*) REF=${1#*=}; shift ;;
    --repo) need_arg "$@"; REPO=$2; shift 2 ;;
    --repo=*) REPO=${1#*=}; shift ;;
    --local) LOCAL=1; shift ;;
    --force) FORCE=1; shift ;;
    --dry-run) DRY=1; shift ;;
    --list) LIST=1; shift ;;
    -h|--help)
      if [ -f "$0" ] && grep -q 'Install skills from this repository' "$0" 2>/dev/null; then usage
      else say 'Options: --agent claude|codex|both  --skill NAME|GROUP|all  --project DIR  --ref REF  --repo O/N  --local  --force  --dry-run  --list'; fi
      exit 0 ;;
    *) die "unknown option: $1 (see --help)" ;;
  esac
done

# --- the source: this checkout, or a downloaded archive -------------------------------------------
TMP=
cleanup() { [ -n "$TMP" ] && rm -rf "$TMP"; return 0; }
trap cleanup EXIT INT TERM

HERE=  # the checkout this script is in, when it was run as a file (not piped)
if [ -f "$0" ] && grep -q 'Install skills from this repository' "$0" 2>/dev/null; then
  HERE=$(cd "$(dirname "$0")" 2>/dev/null && pwd) || HERE=
fi
if [ "$LOCAL" = 1 ]; then
  [ -n "$HERE" ] && [ -d "$HERE/skills" ] || die "--local: run the script from a checkout (sh path/to/install.sh)"
  SRC=$HERE
  ORIGIN="local checkout $(cd "$SRC" && git rev-parse --short HEAD 2>/dev/null || echo '')"
else
  case $REPO in */*) ;; *) die "--repo must be OWNER/NAME" ;; esac
  TMP=$(mktemp -d 2>/dev/null || mktemp -d -t skills-install)
  URL="https://codeload.github.com/$REPO/tar.gz/$REF"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$URL" -o "$TMP/src.tar.gz" || die "could not download $URL (check --repo and --ref)"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$TMP/src.tar.gz" "$URL" || die "could not download $URL (check --repo and --ref)"
  else
    die "needs curl or wget to download (or run it from a checkout with --local)"
  fi
  mkdir "$TMP/src"
  tar -xzf "$TMP/src.tar.gz" -C "$TMP/src" || die "could not unpack the archive from $URL"
  SRC=$(find "$TMP/src" -mindepth 1 -maxdepth 1 -type d | head -n 1)
  [ -d "$SRC/skills" ] || die "no skills/ folder in $REPO at $REF"
  ORIGIN="$REPO@$REF"
fi

# every skill: "group/name" for each skills/<group>/<name>/SKILL.md
CATALOG=$(cd "$SRC/skills" && for f in */*/SKILL.md; do [ -f "$f" ] && dirname "$f"; done | sort)
[ -n "$CATALOG" ] || die "no skills found in $ORIGIN"
SKILL_GROUPS=$(say "$CATALOG" | cut -d/ -f1 | sort -u)

describe() {  # the first line of the description in a SKILL.md, shortened
  awk '/^---/{n++; next} n==1 && /^description:/{sub(/^description:[ ]*([>|][-+]?)?[ ]*/,""); d=$0; if (d=="") getline d; print d; exit}' "$1" |
    sed 's/^[ ]*//; s/^["'"'"']//' | cut -c1-90
}

if [ "$LIST" = 1 ]; then
  for g in $SKILL_GROUPS; do
    say "$g:"
    for s in $(say "$CATALOG" | grep "^$g/"); do
      printf '  %-44s %s\n' "${s#*/}" "$(describe "$SRC/skills/$s/SKILL.md")"
    done
  done
  exit 0
fi

# --- ask for what is missing ------------------------------------------------------------------------
ask() {  # ask "question" -> answer on stdout; reads the terminal, since stdin may be the piped script
  printf '%s ' "$1" > /dev/tty
  IFS= read -r ans < /dev/tty || ans=
  say "$ans"
}
can_ask() { [ -r /dev/tty ] && [ -w /dev/tty ] && (: < /dev/tty) 2>/dev/null; }

if [ -z "$AGENTS" ]; then
  can_ask || die "--agent is required (claude, codex or both)"
  AGENTS=$(ask "Install for which agent? [claude/codex/both] (claude):")
  [ -n "$AGENTS" ] || AGENTS=claude
fi
if [ -z "$SKILLS" ]; then
  can_ask || die "--skill is required (a skill, a group: $(say $SKILL_GROUPS | tr '\n' ' ')or all); --list shows them"
  {
    say "Skills in $ORIGIN:"
    for g in $SKILL_GROUPS; do
      say "  $g: $(say "$CATALOG" | grep "^$g/" | cut -d/ -f2 | tr '\n' ' ')"
    done
  } > /dev/tty
  SKILLS=$(ask "Which skills? Names or groups, separated by spaces or commas, or all:")
  [ -n "$SKILLS" ] || die "no skills chosen"
fi

# --- resolve agents and skills ----------------------------------------------------------------------
want_claude=0; want_codex=0
for a in $(say "$AGENTS" | tr ', ' '\n\n'); do
  case $a in
    claude|claude-code) want_claude=1 ;;
    codex) want_codex=1 ;;
    both|all) want_claude=1; want_codex=1 ;;
    *) die "unknown agent: $a (claude, codex or both)" ;;
  esac
done
[ $want_claude = 1 ] || [ $want_codex = 1 ] || die "no agent chosen"

SELECTED=
add() { case " $SELECTED " in *" $1 "*) ;; *) SELECTED="$SELECTED $1" ;; esac; }
for s in $(say "$SKILLS" | tr ', ' '\n\n'); do
  if [ "$s" = all ]; then
    for x in $CATALOG; do add "$x"; done
  elif say "$SKILL_GROUPS" | grep -qx "$s"; then
    for x in $(say "$CATALOG" | grep "^$s/"); do add "$x"; done
  else
    m=$(say "$CATALOG" | grep -E "(^|/)$s\$" || true)
    [ -n "$m" ] || die "unknown skill: $s (--list shows the skills)"
    [ "$(say "$m" | wc -l | tr -d ' ')" = 1 ] || die "ambiguous skill name: $s ($(say "$m" | tr '\n' ' '))"
    add "$m"
  fi
done
for r in $REQUIRES; do  # bring along what a selected skill needs
  for x in $SELECTED; do
    if [ "${x#*/}" = "${r%%:*}" ]; then
      m=$(say "$CATALOG" | grep -E "/${r#*:}\$" || true)
      if [ -n "$m" ]; then
        case " $SELECTED " in *" $m "*) ;; *) say "${r%%:*} needs ${r#*:}: installing it too"; add "$m" ;; esac
      fi
    fi
  done
done

# --- install ----------------------------------------------------------------------------------------
if [ -n "$PROJECT" ]; then
  [ -d "$PROJECT" ] || die "project folder not found: $PROJECT"
  BASE=$(cd "$PROJECT" && pwd)
  CLAUDE_DIR="$BASE/.claude/skills"; CODEX_DIR="$BASE/.agents/skills"
else
  [ -n "${HOME:-}" ] || die "HOME is not set"
  CLAUDE_DIR="$HOME/.claude/skills"; CODEX_DIR="$HOME/.agents/skills"
fi

installed=0; skipped=0
install_into() {  # install_into DEST_DIR AGENT_LABEL
  dest=$1
  for x in $SELECTED; do
    name=${x#*/}
    target="$dest/$name"
    if [ -e "$target" ] && [ ! -f "$target/$MARK" ] && [ "$FORCE" != 1 ]; then
      err "skipped $target: it exists and was not installed by this script (--force replaces it)"
      skipped=$((skipped + 1)); continue
    fi
    if [ "$DRY" = 1 ]; then
      if [ -e "$target" ]; then say "would replace $target"; else say "would install $target"; fi
      continue
    fi
    mkdir -p "$dest"
    staging="$dest/.$name.installing.$$"
    rm -rf "$staging"
    cp -R "$SRC/skills/$x" "$staging"
    printf 'source: %s\nskill: skills/%s\nagent: %s\n' "$ORIGIN" "$x" "$2" > "$staging/$MARK"
    rm -rf "$target"
    mv "$staging" "$target"
    say "installed $target"
    installed=$((installed + 1))
  done
}
[ $want_claude = 1 ] && install_into "$CLAUDE_DIR" claude
[ $want_codex = 1 ] && install_into "$CODEX_DIR" codex

if [ "$DRY" = 1 ]; then say "dry run: nothing changed"; exit 0; fi
if [ "$skipped" = 0 ]; then say "$installed installed from $ORIGIN"; else say "$installed installed from $ORIGIN, $skipped skipped"; fi
[ $want_claude = 1 ] && say "Claude Code: start a new session to load them."
[ $want_codex = 1 ] && say "Codex: picked up automatically; restart Codex if they do not appear."
[ "$skipped" = 0 ]

# Skills

- [`skills/apple/`](#apple-skills): Apple-authored coding and localization skills extracted from Xcode.
- [`skills/games/`](#game-skills): reverse engineering and rewriting PC games you own.

## Install

`install.sh` installs skills for Claude Code, Codex or both, straight from GitHub (no clone needed).
Run it from your project's folder; the skills go into that project:

```sh
cd your-project
curl -fsSL https://raw.githubusercontent.com/kamilhq/skills/main/install.sh | sh -s -- --agent claude --skill games
```

Add `--global` to install them for your user instead, for every project.

Without `--agent` or `--skill` it asks. Options:

| Option | Meaning |
|---|---|
| `--agent claude\|codex\|both` | which agent to install for (repeatable, or comma-separated) |
| `--skill NAME` | a skill name, a group (`games`, `apple`) or `all` (repeatable, or comma-separated) |
| `--project DIR` | install into the project in `DIR` instead of the current directory |
| `--global` | install for your user instead of into a project |
| `--ref REF` | branch, tag or commit to install from (default `main`) |
| `--list` | list the skills and exit |
| `--dry-run` | show what would be installed, change nothing |
| `--force` | replace skill folders that this script did not install |
| `--local` | install from the checkout the script is in (`sh install.sh --local ...`) |

Where the skills go:

| Agent | Default (current directory) | With `--global` |
|---|---|---|
| Claude Code | `./.claude/skills/<skill>` | `~/.claude/skills/<skill>` |
| Codex | `./.agents/skills/<skill>` | `~/.agents/skills/<skill>` |

Commit those folders to share the skills with everyone working on the project.

Running it again updates the skills it installed (it marks each folder with a `.skills-install` file).
Folders it did not install are left alone unless you pass `--force`, and nothing else in those
directories is touched. A skill that needs another one brings it along. Start a new Claude Code session to load new skills; Codex picks them
up by itself (restart it if they do not appear). The script needs `sh`, `tar`, and `curl` or `wget`;
on Windows, run it from Git Bash or WSL.

# Game skills

One skill, for 32-bit Windows games built with Microsoft Visual C++ that you own (for example from a GOG
installer):

| Skill | What it does |
|---|---|
| [`clean-room-game-rewrite`](skills/games/clean-room-game-rewrite/SKILL.md) | From the installer to a playable source rewrite in C++ or Rust (you choose once the game is analysed) that builds a native Windows exe, reads the game's own data from your installation, and is checked frame by frame against the original. Written clean-room, so the rewrite is the one part you may publish. |

How it works: analyst agents unpack the installer, check for copy protection, recover and name all code
with Ghidra, prove every data format with round-trip readers, and write behaviour specs in their own
words. A probe DLL records the unchanged original game's per-frame state under scripted input. Fresh
implementer sessions that never see the decompilation write the game from the specs and those traces,
until the traces match. Every step ends at a gate a script checks: GOG's hash list for the extracted
game, no copy protection, zero orphan instructions, byte-identical round trips of the data, deterministic
traces of the original, identical traces of the rewrite, and a release check of the clean tree.

This replaces the earlier `byte-identical-game-decomp` and `game-rewrite` skills. If you installed those,
delete their folders (`.claude/skills/byte-identical-game-decomp`, `.claude/skills/game-rewrite`, or the
`.agents/skills` ones) after installing this one.

## Legal frame

The skill works only on a game you own, never removes or bypasses copy protection (it stops when it finds
one), and keeps everything derived from the game on your machine. Copyright protects the original's code
and assets, not its behaviour or file formats, so the rewrite is never translated from decompiled code:

- Analyst agents read the decompilation and write behaviour specs in their own words.
- Fresh implementer sessions that never see the decompilation write the code from those specs and the
  original's frame traces.
- `cleanroom.py` lints the specs and keeps a hash-chained log of every hand-over.
- `release_check.py` must pass before publishing: no copied code, address markers, original names,
  embedded game data or assets; a licence and notices present.
- The game's data is always read from your own installation at run time.

Details and the law behind them: [`legal.md`](skills/games/clean-room-game-rewrite/references/legal.md),
[`cleanroom.md`](skills/games/clean-room-game-rewrite/references/cleanroom.md). This is not legal advice;
laws differ by country.

## Use

Install it with `--skill games` ([Install](#install)), then ask the agent in your game project, for example
"rewrite this game, the installer is at ...". `SKILL.md` describes the steps; the `references/` files hold
the details the agent reads when it reaches each step. The agent asks for the target language after the
analysis and the oracle are done.

## Requirements

- Python 3.9+ (standard library only) or Node.js 20+ (built-ins only), see below.
- [Ghidra](https://ghidra-sre.org) 12.x and the JDK it needs, for the analysis.
- On macOS and Linux, Wine, to run the original game, the rewrite and the Windows compiler.
- An x86 Microsoft C/C++ compiler for the probe and a C++ rewrite (VS2010 SP1 is free from Microsoft as the
  Windows SDK 7.1 plus a compiler update; the skill explains how to unpack it under Wine).
- For a Rust rewrite: Rust with the `i686-pc-windows-gnu` target (no MinGW needed) and clang.
- The upstream source of any library the game uses, fetched with pinned SHA-256 hashes.

Nothing else is installed: no pip or npm packages, no innoextract, ffmpeg or assemblers. The installer
reader, decompressors, PNG writer, PE reader, probe helpers and trace tools are part of the skill.
`sh skills/games/clean-room-game-rewrite/scripts/check_deps.sh` reports what is present.

## Python and JavaScript

Every script exists twice, in Python (`scripts/*.py`) and as a Node.js port (`scripts/js/*.mjs`) with the
same command line, output and files. Use whichever runtime you have. The Python versions came first; the
ports were added so the tools also run where only Node is installed, and both are kept until the ports
have been used on more projects. The parity suite runs both versions and compares the results:

```sh
# synthetic inputs (fake game, fake Wine and compiler) for the rewrite-side scripts; runs anywhere
node skills/games/clean-room-game-rewrite/scripts/js/parity/rewrite.mjs

# everything; the analysis-side tests need a project's game files and outputs: run it from (or point it at) your project
node skills/games/clean-room-game-rewrite/scripts/js/parity/run_all.mjs --root PROJECT
```

A change to a script goes into both versions, with its parity test, in the same commit. The Ghidra scripts
(Java), the C headers and the shell wrappers exist once.

## Layout

```text
skills/games/
  clean-room-game-rewrite/
    SKILL.md
    references/        Legal frame, intake, code recovery, naming, code inventory, formats, clean room,
                       harness and probe, toolchains, C++, Rust, orchestration
    scripts/           Pipeline and analysis tools (Python), ghidra/ (Java), formats/ (reader helpers),
                       harness/ (probe and trace contract in C), library builds, scenario runner, trace
                       comparison, clean-room record and release gate, Rust templates
      js/              Node.js ports, lib/ (ported algorithms), parity/ (tests)
      examples/        A made-up example libraries.json
```

## What is not here

Nothing derived from a game: no game files, decoded data, decompiled code, names, traces or rewritten
source. The skill keeps all of that in your local project, out of git, and keeps any repository with game
content private. You need your own copy of the game. Nothing to remove or get around copy protection
either.

# Apple skills

Apple-authored coding and localization skills extracted from Xcode, with their original contents.

## Extract

Requires macOS, Xcode, and Node.js 18 or newer. No npm dependencies. From this repo:

```sh
# List available skills without writing files
node scripts/xcode-skills.mjs --list

# Extract selected skills
node scripts/xcode-skills.mjs --skill swiftui-specialist --skill app-intents-specialist

# Extract all Apple skills
node scripts/xcode-skills.mjs

# Choose the installation and destination
node scripts/xcode-skills.mjs --xcode /Applications/Xcode-beta.app --output /tmp/apple-skills

# Preview a selection without writing files
node scripts/xcode-skills.mjs --skill xctrace --dry-run
```

The default destination is `skills/apple/` in this repo, regardless of the current
working directory. Xcode is detected via `xcode-select`, falling back to
`/Applications/Xcode.app` when Command Line Tools are selected. Localization skills
are included automatically. Unknown skill names fail
before any files are copied.

## Layout

```text
scripts/
  xcode-skills.mjs       CLI options, discovery, planning, and extraction
skills/apple/
  <skill-name>/
    SKILL.md
    references/        Supporting documentation, when bundled
    scripts/           Supporting scripts, when bundled
```

The extractor identifies skill frontmatter in Apple's `.idechatprompttemplate`
files and saves them as `SKILL.md`. It restores flattened `<skill>-ref-*` and
`<skill>-script-*` files to their proper folders and strips `.packaged` suffixes.
It preserves file contents and skips framework symlink aliases. Localization is copied from the bundled skill directories.

Reruns overwrite matching files; they do not remove other skills or manually added
files. `--skill` limits what is copied, not what remains in the destination.
Some skills require Xcode-specific tools, which this script does not install.

## Weekly updates

[Update Apple skills](.github/workflows/update-apple-skills.yml) runs Mondays at
06:23 UTC and can also be started manually from GitHub Actions. GitHub publishes
runner updates weekly but does not guarantee a deployment day, so this checks the
latest available image each week.

The workflow selects the newest installed Xcode on the `xcode-27` runner (at least
27.2), extracts into a temporary directory, and synchronizes `skills/apple/`,
including removals. Changed skills open or update one PR on
`codex/update-apple-skills`; unchanged skills produce no PR. Updates require review
and are not merged automatically.

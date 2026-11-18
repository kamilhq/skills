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
directories is touched. A skill that needs another one brings it along (`game-rewrite` installs
`byte-identical-game-decomp` too). Start a new Claude Code session to load new skills; Codex picks them
up by itself (restart it if they do not appear). The script needs `sh`, `tar`, and `curl` or `wget`;
on Windows, run it from Git Bash or WSL.

# Game skills

Two skills that work together, for 32-bit Windows games built with Microsoft Visual C++ that you own
(for example from a GOG installer):

| Skill | What it does |
|---|---|
| [`byte-identical-game-decomp`](skills/games/byte-identical-game-decomp/SKILL.md) | From the installer to decoded data files, complete recovered and named code, a byte-identical rebuild of every binary, and C++ matched function by function with the original compiler. |
| [`game-rewrite`](skills/games/game-rewrite/SKILL.md) | A full source rewrite in C++ or Rust that builds a native Windows exe, uses the game's own data, and is checked frame by frame against the original with a differential test harness. Starts from the decomp skill's results. Private (translated, kept local) or publishable (clean room, with a release gate). |

Every phase ends at a gate a script checks: SHA-256 identity for data and binaries, zero orphan
instructions for code recovery, no copy protection on the game, identical per-frame traces and save files
for a rewrite, and for a rewrite meant for release, a clean-room record and a check for copied code.

## Legal frame

The skills work only on a game you own, never remove or bypass copy protection (they stop when they find
one), and keep everything derived from the game on your machine. Copyright protects the original's code
and assets, not its behaviour or file formats, so there are two ways to rewrite:

- **Private** (default): the rewrite is translated from the decompilation. That makes it a derivative work of
  the original code, so it stays local, like the decompilation itself.
- **Publishable**: a clean-room rewrite. Analyst agents read the decompilation and write behaviour specs in
  their own words; fresh implementer sessions that never see the decompilation write the code from those
  specs and the original's frame traces. `cleanroom.py` lints the specs and keeps a hash-chained log of every
  hand-over; `release_check.py` must pass before publishing (no copied code, address markers, original names,
  embedded game data or assets; licence and notices present). The game's data is always read from your own
  installation at run time.

Details and the law behind them: [`legal-and-repo.md`](skills/games/byte-identical-game-decomp/references/legal-and-repo.md),
[`cleanroom.md`](skills/games/game-rewrite/references/cleanroom.md). This is not legal advice; laws differ by
country.

## Use

Install both with `--skill games` ([Install](#install)), then ask the agent in your game project, for
example "decompile this game, the installer is at ..." or "rewrite it in Rust". Each skill's `SKILL.md`
describes the phases; the `references/` files hold the details the agent reads when it reaches each phase.

## Requirements

- Python 3.9+ (standard library only) or Node.js 20+ (built-ins only), see below.
- [Ghidra](https://ghidra-sre.org) 12.x and the JDK it needs, for code recovery.
- For matching and for the C++ rewrite: the game's original compiler, supplied by you. On macOS and Linux,
  Wine runs it and the game.
- For the Rust rewrite: Rust with the `i686-pc-windows-gnu` target (no MinGW needed).
- The upstream source of any library the game uses, fetched with pinned SHA-256 hashes.

Nothing else is installed: no pip or npm packages, no innoextract, ffmpeg or assemblers. The installer
reader, decompressors, PNG writer, PE reader and writer, and trace tools are part of the skills.
`sh skills/games/byte-identical-game-decomp/scripts/check_deps.sh` reports what is present.

## Python and JavaScript

Every script exists twice, in Python (`scripts/*.py`) and as a Node.js port (`scripts/js/*.mjs`) with the
same command line, output and files. Use whichever runtime you have. The Python versions came first; the
ports were added so the tools also run where only Node is installed, and both are kept until the ports
have been used on more projects. Parity suites run both versions and compare the results:

```sh
# synthetic inputs (fake game, fake Wine and compiler); runs anywhere
node skills/games/game-rewrite/scripts/js/parity/run_all.mjs

# some tests need a decomp project's binaries and outputs; run it from (or point it at) your project
node skills/games/byte-identical-game-decomp/scripts/js/parity/run_all.mjs --root PROJECT
```

A change to a script goes into both versions, with its parity test, in the same commit. The Ghidra scripts
(Java) and shell wrappers exist once.

## Layout

```text
skills/games/
  byte-identical-game-decomp/
    SKILL.md
    references/        Intake, decoding, code recovery, naming, reassembly, matching, orchestration
    scripts/           Pipeline and tools (Python), ghidra/ (Java), formats/ (decoder helpers)
      js/              Node.js ports, lib/ (ported algorithms), parity/ (tests)
  game-rewrite/
    SKILL.md
    references/        Inventory, toolchains, harness, C++, Rust, clean room, orchestration
    scripts/           Library builds, oracle, scenario runner, trace comparison, C++ and Rust tools,
                       clean-room record and release gate
      js/              Node.js ports and parity tests
      examples/        Made-up example configs
```

## What is not here

Nothing derived from a game: no game files, decoded data, decompiled code, names, traces or rewritten
source. The skills keep all of that in your local project, out of git, and keep any repository with game
content private. You need your own copy of the game, and of its original compiler for matching. Nothing to
remove or get around copy protection either.

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

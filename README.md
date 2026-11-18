# Skills

- `skills/apple/`: Apple-authored coding and localization skills extracted from Xcode (below).
- `skills/games/`: skills for games the user owns:
  - `byte-identical-game-decomp`: from a GOG installer to decoded data, recovered and named code, a byte-identical
    rebuild of every binary, and matched C++ (MSVC under Wine).
  - `game-rewrite`: a full source rewrite in C++ or Rust that builds a native Windows exe and is checked frame by
    frame against the original with a differential test harness (scripted input, per-frame state traces).

  Both run their tools with Python's standard library or Node.js built-ins (each Python script has a parity-tested
  JavaScript port), plus Ghidra and the target toolchains. Nothing derived from a game is in this repository.

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

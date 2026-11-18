# Ownership, legal boundaries and repository rules

- Work only on games the user owns, from their own installer or install. Ask once at the start.
- Tools, format specs, analysis write-ups (in your own words, with addresses), verification reports
  (file names, sizes, hashes) are the project's own work and can be committed.
- Anything derived from the game stays local and git-ignored: extracted archives, decoded assets, previews,
  decompiled pseudocode, assembly from phase 5b, matched C++ from phase 6, names maps that embed game
  strings, Ghidra projects. Keep a GitHub repo private; publishing even the tooling publicly is the user's
  decision, and derived game content should never be published.
- Do not download game files, compilers, SDKs or patches from unofficial sources. Visual C++ 6.0, the DirectX
  SDK of the era and the installer are user-supplied.
- Privacy: no absolute local paths, usernames or emails in committed reports/docs; replace with
  `<GAME_DIR>`, `.` etc. Scratch paths in docs must be replaced by repo-relative tool paths.

## .gitignore template
```gitignore
# Game-derived content (copyrighted; regenerate locally from your own installer)
/extracted/
/decoded/
/previews/
/decompiled*/
/reassembled/
/src_matched/
/analysis/
/work/
# verification scratch
/verify_out/
/verify_reports/
__pycache__/
*.pyc
.DS_Store
```

## Commit hygiene
- Commit after each phase gate with the numbers in the message (files identical, functions recovered).
- If a commit message turns out wrong after pushing, say so rather than force-pushing a rewrite.

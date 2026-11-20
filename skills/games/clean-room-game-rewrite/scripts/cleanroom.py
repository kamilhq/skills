#!/usr/bin/env python3
"""Clean-room bookkeeping of the rewrite (references/cleanroom.md).

  python3 -I cleanroom.py init   [--project DIR]
  python3 -I cleanroom.py lint   FILE... [--project DIR] [--json OUT]
  python3 -I cleanroom.py pack   --wave NAME --out DIR INPUT... [--note TEXT] [--project DIR]
  python3 -I cleanroom.py record --wave NAME --event KIND [--note TEXT] [FILE...] [--project DIR]
  python3 -I cleanroom.py verify [--project DIR]

Two kinds of agent work on a clean-room rewrite: analysts, who read the decompilation and write behaviour
specs in their own words, and implementers, who write the rewrite from those specs, the format docs and the
oracle's traces without ever seeing code derived from the original. This script keeps the two apart and
keeps the record. Settings: decomp.json "rewrite.cleanroom" (dir, specs, log, tree, forbidden, reference, ...;
defaults in references/cleanroom.md).
  init    creates <dir>/specs, <dir>/questions, <dir>/README.md and the log <dir>/log.jsonl with an "init"
          entry (the forbidden areas and the reference folders at that time). Exit 1 if the log exists.
  lint    checks spec files for copied code: Ghidra names (FUN_..., iVar1, param_1), fenced code blocks
          tagged as C, C++, Rust or assembly, untagged blocks or loose text with >= spec_code_lines code-like
          lines, and runs of tokens shared with the reference code (raw token 12-grams, winnowed; a file with
          >= spec_overlap shared fingerprints fails). Exit 0 clean, 1 findings.
  pack    builds an implementer's workspace: copies every INPUT (files, or folders recursively) to
          DIR/<project-relative path>, with INPUTS.json (paths, SHA-256, sizes) and RULES.md. Refused, with
          nothing copied, when an input lies outside the project or in a forbidden area (by its path or its
          real path), or a .md/.txt input fails lint. Every pack, and every refusal, is a log entry.
  record  appends another event to the log (question, answer, handoff, review ...), with the SHA-256 of
          each FILE; the same checks as pack apply to the files.
  verify  checks the log: every line JSON, "seq" consecutive, "prev" the SHA-256 of the previous line.
          Prints entries, head (the SHA-256 of the last line: the chain cannot protect the last line, git
          does), events and waves. Exit 0 intact, 1 broken, 2 no log.
Log lines are compact JSON: seq, recorded (UTC; SOURCE_DATE_EPOCH when set), event, ..., prev. Keep the log
in git: it is the evidence of the process. Prints a JSON summary. Exit 2 on bad input.
Python standard library only.
"""
import os
import re
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rwlib  # noqa: E402
import cleanlib as C  # noqa: E402

PROG = 'cleanroom'
FENCE_RE = re.compile(r'^(```+|~~~+)[ \t]*([^ \t`~]*)')
CODE_LINE_RE = re.compile(r';$|^[{}][ \t]*;?$|\{$|^(?:if|for|while|switch|return|else)\b[^\n]*[;{(]', re.ASCII)
CODE_LANGS = frozenset(['c', 'h', 'cpp', 'c++', 'cc', 'cxx', 'hpp', 'rust', 'rs', 'asm', 'nasm', 'masm', 'x86', 's',
                        'pseudocode', 'pseudo', 'ghidra', 'decompiled'])
EVENT_RE = re.compile(r'^[a-z][a-z0-9_-]*$')
LINT_EXTS = ('.md', '.markdown', '.txt')

README = """# Clean-room record

This folder holds the clean-room process of the rewrite (see the clean-room-game-rewrite skill,
references/cleanroom.md).

- `specs/`: behaviour specs written by analysts, in their own words. No code from the decompilation or the
  analysts' tools (format readers, the probe). Run `cleanroom.py lint` on every spec before it is handed over.
- `questions/`: implementers' written questions and the analysts' written answers.
- `log.jsonl`: every hand-over (`cleanroom.py pack` / `record`), hash-chained. Do not edit it.

Implementers never open the decompiled code, the Ghidra projects, the analysts' tools (format readers, the
probe), the names maps or the original executable's bytes. They work from their workspace (made by `pack`), the
traces of the oracle and the game's own data files, and write their own design.
"""

RULES = """# Rules for this workspace

You write the rewrite from the files in this folder: behaviour specs, format documents, traces of the
original game and answers to your questions. Nothing else from the project.

- Do not open, search, list or ask for: decompiled or disassembled code, Ghidra projects, the analysts'
  tools (format readers, the probe), names maps, or the original executable's bytes. If you come across any of
  them, stop and tell the coordinator.
- Ask questions in writing through the coordinator; answers come back as new spec files.
- Choose your own design, names and structure. The behaviour must match the traces; the code should not
  resemble anything you were not given.
- Do not put game data (levels, text, graphics, sound, tables) into the source: read it from the user's
  own game files at run time.
- Do not commit, download or publish anything.
"""


class InputError(Exception):
    pass


def relp(project, p):
    """(project-relative path or None, display path)."""
    r = C.rel(project, p)
    return r, (r if r is not None else p)


def lint_text(text, corpus, th):
    """-> [(line, rule, detail)]"""
    out = []
    lines = text.split('\n')
    for n, line in enumerate(lines, 1):
        m = C.GHIDRA_RE.search(line)
        if m:
            out.append((n, 'ghidra', 'Ghidra name %s' % m.group(0)))
    fence = None   # (mark, lang, start, code lines)
    loose = []

    def close(f):
        mark, lang, start, code = f
        if lang in CODE_LANGS:
            out.append((start, 'code-block', 'fenced %s block' % lang))
        elif lang not in ('json', 'text', 'txt') and code >= th['spec_code_lines']:
            out.append((start, 'code-block', 'block with %d code-like lines' % code))

    for n, line in enumerate(lines, 1):
        s = line.strip(C.WS)
        if fence is None:
            m = FENCE_RE.match(s)
            if m:
                fence = [m.group(1), m.group(2).lower(), n, 0]
                continue
            if CODE_LINE_RE.search(s):
                loose.append(n)
        else:
            if s.startswith(fence[0]) and s.strip('`~') == '':
                close(fence)
                fence = None
                continue
            if CODE_LINE_RE.search(s):
                fence[3] += 1
    if fence is not None:
        close(fence)
    if len(loose) >= th['spec_code_lines']:
        out.append((loose[0], 'code-lines', '%d code-like lines outside code blocks (lines %s)' %
                    (len(loose), ', '.join(str(x) for x in loose[:10]))))
    if corpus is not None:
        fp = C.file_fingerprints(text, raw=True)
        hits = sorted({ln for ln, h in fp['raw'] if h in corpus.raw})
        n_hits = sum(1 for _, h in fp['raw'] if h in corpus.raw)
        if n_hits >= th['spec_overlap']:
            out.append((hits[0], 'overlap', '%d fingerprints shared with the reference code (lines %s)' %
                        (n_hits, ', '.join(str(x) for x in hits[:10]))))
    out.sort(key=lambda x: (x[0], x[1], x[2]))
    return out


class Linter:
    def __init__(self, project, s):
        self.project, self.s = project, s
        self.corpus = None

    def lint(self, path):
        if self.corpus is None:
            self.corpus = C.Corpus(self.project, self.s['reference'], self.s['reference_exclude'], raw=True)
        return lint_text(C.read_text(path), self.corpus, self.s['thresholds'])


def check_inputs(project, s, paths, linter):
    """-> (files [(rel, abs)], refused [{path, reason}]); folders are expanded."""
    files, refused = [], []
    for p in paths:
        r, shown = relp(project, p)
        if not os.path.exists(p):
            raise InputError('%s: no such file or folder' % shown)
        if r is None:
            refused.append({'path': '<outside>/' + os.path.basename(os.path.abspath(p)), 'reason': 'outside the project'})
            continue
        if os.path.isdir(p) and not os.path.islink(p):
            members = C.walk(project, r)
        else:
            members = [r]
        for m in members:
            a = os.path.join(project, m)
            hit = C.glob_match(m, s['forbidden'])
            real = C.rel(project, os.path.realpath(a))
            if not hit and real is not None:
                hit = C.glob_match(real, s['forbidden'])
            if hit:
                refused.append({'path': m, 'reason': 'forbidden area %s' % hit})
                continue
            if real is None:
                refused.append({'path': m, 'reason': 'its real path is outside the project'})
                continue
            if m.lower().endswith(LINT_EXTS):
                found = linter.lint(a)
                if found:
                    refused.append({'path': m, 'reason': 'lint: ' + '; '.join(
                        'line %d %s: %s' % f for f in found[:5])})
                    continue
            files.append((m, a))
    seen, uniq = set(), []
    for m, a in files:
        if m not in seen:
            seen.add(m)
            uniq.append((m, a))
    return uniq, refused


def entry_inputs(files):
    return [{'path': m, 'sha256': rwlib.sha256_file(a), 'bytes': os.path.getsize(a)} for m, a in files]


def cmd_init(project, s, a):
    log = os.path.join(project, s['log'])
    if os.path.exists(log):
        sys.stderr.write('%s: error: %s exists: the clean room is already initialised\n' % (PROG, s['log']))
        return 1
    created = []
    for d in (s['dir'], s['specs'], s['dir'] + '/questions'):
        if not os.path.isdir(os.path.join(project, d)):
            os.makedirs(os.path.join(project, d))
            created.append(d + '/')
    readme = os.path.join(project, s['dir'], 'README.md')
    if not os.path.exists(readme):
        with open(readme, 'w', encoding='utf-8') as f:
            f.write(README)
        created.append(s['dir'] + '/README.md')
    os.makedirs(os.path.dirname(log) or '.', exist_ok=True)
    C.append_log(log, {'event': 'init', 'tree': s['tree'], 'forbidden': s['forbidden'], 'reference': s['reference']})
    created.append(s['log'])
    sys.stdout.write(rwlib.dumps({'log': s['log'], 'created': created}) + '\n')
    return 0


def cmd_lint(project, s, a):
    if not a['files']:
        raise InputError('lint needs at least one FILE')
    for p in a['files']:
        if not os.path.isfile(p):
            raise InputError('%s: not a file' % p)
    linter = Linter(project, s)
    findings = []
    for p in a['files']:
        shown = relp(project, p)[1]
        for line, rule, detail in linter.lint(p):
            findings.append({'file': shown, 'line': line, 'rule': rule, 'detail': detail})
            sys.stderr.write('%s:%d: %s: %s\n' % (shown, line, rule, detail))
    summary = {'files': len(a['files']), 'clean': not findings, 'findings': findings,
               'reference_files': len(linter.corpus.files)}
    text = rwlib.dumps(summary)
    if a['json']:
        with open(a['json'], 'w', encoding='utf-8') as f:
            f.write(text + '\n')
    sys.stdout.write(text + '\n')
    return 0 if not findings else 1


def need_log(project, s):
    if not os.path.exists(os.path.join(project, s['log'])):
        raise InputError('no clean-room log %s: run cleanroom.py init first' % s['log'])


def refuse(project, s, a, event, refused):
    C.append_log(os.path.join(project, s['log']), {'event': 'refused', 'for': event, 'wave': a['wave'],
                                                   'note': a['note'], 'refused': refused})
    for r in refused:
        sys.stderr.write('%s: refused %s: %s\n' % (PROG, r['path'], r['reason']))
    sys.stdout.write(rwlib.dumps({'event': event, 'wave': a['wave'], 'refused': refused}) + '\n')
    return 1


def cmd_pack(project, s, a):
    need_log(project, s)
    if not a['inputs']:
        raise InputError('pack needs at least one INPUT')
    out = a['out']
    if os.path.exists(out) and (not os.path.isdir(out) or os.listdir(out)):
        raise InputError('%s exists and is not an empty folder' % out)
    out_rel, out_shown = relp(project, out)
    if out_rel is not None and C.glob_match(out_rel, s['forbidden']):
        raise InputError('%s is inside a forbidden area' % out_shown)
    files, refused = check_inputs(project, s, a['inputs'], Linter(project, s))
    if refused:
        return refuse(project, s, a, 'pack', refused)
    for m, src in files:
        dst = os.path.join(out, m)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src, dst)
    inputs = entry_inputs(files)
    with open(os.path.join(out, 'INPUTS.json'), 'w', encoding='utf-8') as f:
        f.write(rwlib.dumps({'wave': a['wave'], 'note': a['note'], 'inputs': inputs}) + '\n')
    with open(os.path.join(out, 'RULES.md'), 'w', encoding='utf-8') as f:
        f.write(RULES)
    e = C.append_log(os.path.join(project, s['log']), {
        'event': 'pack', 'wave': a['wave'], 'note': a['note'],
        'out': out_rel if out_rel is not None else '<outside>/' + os.path.basename(os.path.abspath(out)),
        'inputs': inputs})
    sys.stdout.write(rwlib.dumps({'event': 'pack', 'seq': e['seq'], 'wave': a['wave'], 'out': e['out'],
                                  'files': len(inputs), 'bytes': sum(x['bytes'] for x in inputs)}) + '\n')
    return 0


def cmd_record(project, s, a):
    need_log(project, s)
    if not EVENT_RE.match(a['event']) or a['event'] in ('init', 'pack', 'refused'):
        raise InputError('--event: a lower-case word other than init, pack and refused, e.g. question, answer')
    files, refused = check_inputs(project, s, a['files'], Linter(project, s)) if a['files'] else ([], [])
    if refused:
        return refuse(project, s, a, a['event'], refused)
    inputs = entry_inputs(files)
    e = C.append_log(os.path.join(project, s['log']), {'event': a['event'], 'wave': a['wave'], 'note': a['note'],
                                                       'inputs': inputs})
    sys.stdout.write(rwlib.dumps({'event': a['event'], 'seq': e['seq'], 'wave': a['wave'], 'files': len(inputs)}) +
                     '\n')
    return 0


def cmd_verify(project, s, a):
    path = os.path.join(project, s['log'])
    v = C.verify_log(path)
    v['log'] = s['log']
    for p in v['problems']:
        sys.stderr.write('%s: %s\n' % (s['log'], p))
    sys.stdout.write(rwlib.dumps(v) + '\n')
    if not os.path.exists(path):
        return 2
    return 0 if v['ok'] else 1


COMMANDS = {
    'init': (cmd_init, [], []),
    'lint': (cmd_lint, [('--json', 'str', None)], [('files', '*')]),
    'pack': (cmd_pack, [('--wave', 'str', rwlib.REQUIRED), ('--out', 'str', rwlib.REQUIRED), ('--note', 'str', '')],
             [('inputs', '*')]),
    'record': (cmd_record, [('--wave', 'str', rwlib.REQUIRED), ('--event', 'str', rwlib.REQUIRED),
                            ('--note', 'str', '')], [('files', '*')]),
    'verify': (cmd_verify, [], []),
}


def main(argv):
    if not argv or argv[0] in ('-h', '--help'):
        if argv:
            sys.stdout.write(__doc__.strip() + '\n')
            return 0
        sys.stderr.write('%s: error: missing command (%s)\n' % (PROG, ', '.join(COMMANDS)))
        return 2
    cmd = argv[0]
    if cmd not in COMMANDS:
        sys.stderr.write('%s: error: unknown command %s (%s)\n' % (PROG, cmd, ', '.join(COMMANDS)))
        return 2
    fn, opts, pos = COMMANDS[cmd]
    a = rwlib.parse_args(PROG, __doc__, argv[1:], [('--project', 'str', '.')] + opts, pos)
    project = os.path.abspath(a['project'])
    try:
        s = C.settings(project)
        return fn(project, s, a)
    except (InputError, ValueError) as e:
        sys.stderr.write('%s: error: %s\n' % (PROG, e))
        return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

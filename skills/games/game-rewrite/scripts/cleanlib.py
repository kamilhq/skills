"""Shared helpers of cleanroom.py and release_check.py (Python standard library only).

The JavaScript port is js/lib/cleanlib.mjs; both must behave the same (js/parity/run_all.mjs checks it).

  settings(project)            -> the clean-room settings: decomp.json "rewrite.cleanroom" over defaults
  glob_match(path, patterns)   -> the first pattern that matches a project-relative POSIX path (or an ancestor)
  walk(root, exclude)          -> sorted project-relative POSIX paths of the regular files under root
  tokens(text)                 -> [(kind, text, line)]: C, C++ and Rust tokens, comments included
  norm_number(tok)             -> 'i<int>' or 'f<IEEE-754 hex>': the value of a numeric literal in any of the three
  Corpus(project, dirs, exclude) -> fingerprints of the reference code (decompiled, matched, private rewrites)
  file_fingerprints(text, ...) -> one source file's fingerprints, strings and tables
  read_log(path), append_log(path, entry), verify_log(path) -> the clean-room log (hash-chained JSON lines)
"""
import hashlib
import json
import os
import re
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rwlib  # noqa: E402

CODE_EXTS = ('.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh', '.hxx', '.inl', '.rs')
THRESHOLDS = {
    'code_pct': 10,        # max % of the tree's code fingerprints found in the reference
    'const_pct': 20,       # max % of the tree's constant-sequence fingerprints found in the reference
    'file_pct': 50,        # max % for one file (with at least file_min fingerprints)
    'file_min': 20,
    'names_pct': 30,       # max % of the tree's function names that are phase-5 names
    'names_min': 20,       # the names check applies from this many function definitions
    'table_items': 1024,   # an embedded numeric table this long is game data
    'string_items': 64,    # an embedded string table this long is game data
    'string_bytes': 2048,  # max bytes of string literals (>= min_string chars) shared with the reference
    'min_string': 8,
    'spec_overlap': 3,     # a spec sharing this many raw-code fingerprints with the reference fails lint
    'spec_code_lines': 3,  # code-like lines that make an untagged code block (or a spec) fail lint
}
CODE_K, CONST_K, RAW_K, WINDOW = 12, 5, 12, 4
KEYWORDS = frozenset(['if', 'else', 'for', 'while', 'do', 'switch', 'case', 'default', 'break', 'continue',
                      'return', 'goto', 'match', 'loop', 'true', 'false'])
NOT_FN = frozenset(['if', 'for', 'while', 'switch', 'catch', 'return', 'sizeof', 'do', 'else', 'match', 'loop'])
FN_SKIP = frozenset(['const', 'noexcept', 'override', 'final', 'volatile'])
SMALL = 32                 # numbers below this (and small multiples of 1/4) are too common to fingerprint
GHIDRA_RE = re.compile(r'\b(?:(?:thunk_)?FUN_[0-9a-fA-F]{6,16}|DAT_[0-9a-fA-F]{6,16}|LAB_[0-9a-fA-F]{6,16}|'
                       r'PTR_[A-Za-z0-9_]*_?[0-9a-fA-F]{6,16}|switchD_[0-9a-fA-F]{6,16}|undefined[1248]|'
                       r'(?:in|extraout|unaff)_[A-Z]{2,3}|(?:[iubcsfdl]|p[a-z]{0,3}|a[a-z]{1,2})Var[0-9]+|local_[0-9a-f]+|param_[0-9]+|'
                       r'CONCAT[0-9]{2}|SUB[0-9]{2}|ZEXT[0-9]{2}|SEXT[0-9]{2})\b', re.ASCII)
_ADDR = r'0x(?:00)?[4-7][0-9a-fA-F]{5}\b|0x1[0-9a-fA-F]{7}\b'
ADDR_COMMENT_RE = re.compile(r'(?:\b(?:FUNCTION|STUB|LIBRARY|GLOBAL|VTABLE|SYNTHETIC|TEMPLATE|address|addr)\b'
                             r'[^\n]*\b(?:' + _ADDR + r')|^(?://+!?|/\*+)[ \t]*(?:' + _ADDR + r'))', re.ASCII)
STUB_RE = re.compile(r'\bstub![ \t]*\([ \t]*0x[0-9a-fA-F]+', re.ASCII)
WS = ' \t\r\n\f\v'          # what strip() removes, the same in both ports

_WS = '[ \\t\\r\\n\\f\\v]'
TOKEN_RE = re.compile(
    '(' + _WS + '+)'
    r'|(//[^\n]*|/\*[\s\S]*?\*/)'
    r'|("(?:[^"\\\n]|\\[^\n])*")'
    r"|('(?:[^'\\\n]|\\[^\n])')"
    r'|(0[xX][0-9A-Fa-f_]+[A-Za-z0-9_]*|[0-9][0-9_]*(?:\.(?![.A-Za-z_])[0-9_]*)?(?:[eE][-+]?[0-9_]+)?[A-Za-z0-9_]*'
    r'|\.[0-9][0-9_]*(?:[eE][-+]?[0-9_]+)?[A-Za-z0-9_]*)'
    r'|([A-Za-z_][A-Za-z0-9_]*)'
    r'|(::|->|=>|<<=|>>=|&&|\|\||<<|>>|\+\+|--|[-+*/%&|^!=<>]=|[^ \t\r\n\f\v])')
KINDS = (None, 'ws', 'comment', 'string', 'char', 'number', 'ident', 'punct')
HEX_RE = re.compile(r'^0[xX]([0-9A-Fa-f]*)')
FLOAT_RE = re.compile(r'^([0-9]*\.[0-9]*(?:[eE][-+]?[0-9]+)?|[0-9]+[eE][-+]?[0-9]+)')
INT_RE = re.compile(r'^([0-9]+)')


# ------------------------------------------------------------------------------------------------ settings
def settings(project):
    cfg, rw = rwlib.load_config(project)
    cr = rw.get('cleanroom') or {}
    paths = cfg.get('paths') or {}
    bins = [b for b in (cfg.get('binaries') or []) if isinstance(b, dict)]
    analysis = paths.get('analysis') or 'analysis'
    src = paths.get('src') or 'src_matched'
    private = cr.get('private', ['rewrite/cpp', 'rewrite/rust', 'rewrite/rust_wave'])
    derived = []
    for b in bins:
        for k in ('decompiled', 'named', 'reassembled'):
            if b.get(k):
                derived.append(b[k])
    derived += [src, analysis]
    if rwlib.get(rw, 'oracle.dir'):
        derived.append(rwlib.get(rw, 'oracle.dir'))
    reference = [b[k] for b in bins for k in ('decompiled', 'named') if b.get(k)] + [src] + list(private)
    names = [analysis + '/' + b['name'] + '/names_apply.json' for b in bins if b.get('name')]
    d = cr.get('dir', 'cleanroom')
    th = dict(THRESHOLDS)
    th.update(cr.get('thresholds') or {})
    return {
        'dir': d,
        'tree': cr.get('tree', 'rewrite/clean'),
        'specs': cr.get('specs', d + '/specs'),
        'log': cr.get('log', d + '/log.jsonl'),
        'allow': cr.get('allow', d + '/allow.json'),
        'forbidden': cr.get('forbidden', derived + list(private) + ['**/*.gpr', '**/*.rep']),
        'reference': cr.get('reference', reference),
        'reference_exclude': cr.get('reference_exclude', ['**/build/**', '**/target/**', '**/third_party/**',
                                                          '**/.git/**']),
        'tree_exclude': cr.get('tree_exclude', ['third_party/**', 'vendor/**', 'target/**', 'build/**', '.git/**']),
        'assets': cr.get('assets', [paths.get('game') or 'work/game', paths.get('extracted') or 'extracted',
                                    paths.get('decoded') or 'decoded']),
        'names': cr.get('names', names),
        'libraries': rw.get('libraries'),
        'require_log': cr.get('require_log', True),
        'thresholds': th,
    }


# ------------------------------------------------------------------------------------------------ paths
def _glob_re(pat):
    parts = pat.split('/')
    out = ''
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        if part == '**':
            out += '.*' if last else '(?:[^/]+/)*'
            continue
        seg = ''
        for ch in part:
            if ch == '*':
                seg += '[^/]*'
            elif ch == '?':
                seg += '[^/]'
            elif ch in '.^$+{}()|[]\\-':
                seg += '\\' + ch
            else:
                seg += ch
        out += seg + ('' if last else '/')
    return re.compile('^' + out + '$', re.DOTALL)


_GLOBS = {}


def glob_match(path, patterns):
    """The first pattern matching path or one of its parent folders (project-relative POSIX paths), or None."""
    parts = path.split('/')
    prefixes = ['/'.join(parts[:i]) for i in range(1, len(parts) + 1)]
    for pat in patterns:
        pat = pat.strip('/')
        if pat not in _GLOBS:
            _GLOBS[pat] = _glob_re(pat)
        r = _GLOBS[pat]
        for p in prefixes:
            if r.match(p):
                return pat
    return None


def rel(project, p):
    """Project-relative POSIX path of p (absolute or relative to the current folder), or None if outside."""
    a = os.path.abspath(p)
    r = os.path.relpath(a, os.path.abspath(project))
    if r == '.' or r.startswith('..'):
        return None
    return r.replace(os.sep, '/')


def walk(project, root, exclude=()):
    """Sorted project-relative POSIX paths of the regular files under project/root (no symlinks)."""
    out = []
    top = os.path.join(project, root)
    if os.path.isfile(top) and not os.path.islink(top):
        return [root.strip('/')]
    for d, dirs, files in os.walk(top):
        dirs.sort()
        rd = os.path.relpath(d, project).replace(os.sep, '/')
        dirs[:] = [x for x in dirs if not os.path.islink(os.path.join(d, x)) and
                   not glob_match(rd + '/' + x, exclude)]
        for f in sorted(files):
            p = os.path.join(d, f)
            r = rd + '/' + f
            if os.path.isfile(p) and not os.path.islink(p) and not glob_match(r, exclude):
                out.append(r)
    return sorted(out)


def read_text(path):
    with open(path, 'rb') as f:
        return f.read().decode('utf-8', 'replace')


def is_text(path, limit=8192):
    with open(path, 'rb') as f:
        head = f.read(limit)
    return b'\0' not in head


# ------------------------------------------------------------------------------------------------ tokens
def tokens(text):
    """[(kind, text, line)] with kind in comment, string, char, number, ident, punct (whitespace dropped)."""
    out = []
    line = 1
    for m in TOKEN_RE.finditer(text):
        g = m.lastindex
        t = m.group(g)
        if g != 1:
            out.append((KINDS[g], t, line))
        line += t.count('\n')
    return out


def norm_number(tok):
    t = tok.replace('_', '')
    m = HEX_RE.match(t)
    if m:
        return 'i%d' % int(m.group(1) or '0', 16)
    m = FLOAT_RE.match(t)
    if m:
        return 'f' + struct.pack('>d', float(m.group(1))).hex()
    m = INT_RE.match(t)
    return 'i%d' % int(m.group(1)) if m else 'i0'


def significant(n):
    """A normalized number worth fingerprinting: an integer >= SMALL, or a float that is not a small multiple of
    1/4 (0.5, 2.0, -3.25 are everywhere)."""
    if n[0] == 'i':
        return int(n[1:]) >= SMALL
    v = struct.unpack('>d', bytes.fromhex(n[1:]))[0]
    if v != v or v in (float('inf'), float('-inf')):
        return True
    return not (abs(v) < SMALL and (v * 4).is_integer())


def h48(parts):
    return int.from_bytes(hashlib.sha1('\x1f'.join(parts).encode('utf-8')).digest()[:6], 'big')


def winnow(hashes, w=WINDOW):
    """Winnowing (Schleimer et al.): the rightmost minimum of every window of w hashes -> [(index, hash)]."""
    if len(hashes) <= w:
        if not hashes:
            return []
        m = min(hashes)
        i = len(hashes) - 1 - hashes[::-1].index(m)
        return [(i, m)]
    out = []
    last = -1
    for s in range(len(hashes) - w + 1):
        win = hashes[s:s + w]
        m = min(win)
        i = s + w - 1 - win[::-1].index(m)
        if i != last:
            out.append((i, m))
            last = i
    return out


def file_fingerprints(text, raw=False):
    """-> dict with code [(line, hash)], consts [(line, hash)], strings {str: line}, raw [(line, hash)] (raw=True),
    toks (the token list)."""
    toks = tokens(text)
    code_toks = [t for t in toks if t[0] != 'comment']
    norm, anchor, lines, consts, strings = [], [], [], [], {}
    for kind, t, ln in code_toks:
        if kind == 'ident':
            n = t if t in KEYWORDS else 'I'
            a = 0
        elif kind == 'number':
            n = norm_number(t)
            a = 1 if significant(n) else 0
            if a:
                consts.append((ln, n))
        elif kind == 'string':
            n = 'S' + t
            a = 1
            if t not in strings:
                strings[t] = ln
        elif kind == 'char':
            n = 'C'
            a = 0
        else:
            n = t
            a = 0
        norm.append(n)
        anchor.append(a)
        lines.append(ln)
    code_h, code_ln = [], []
    run = sum(anchor[:CODE_K])
    for i in range(len(norm) - CODE_K + 1):
        if i:
            run += anchor[i + CODE_K - 1] - anchor[i - 1]
        if run >= 2:
            code_h.append(h48(norm[i:i + CODE_K]))
            code_ln.append(lines[i])
    code = [(code_ln[i], h) for i, h in winnow(code_h)]
    cv = [c[1] for c in consts]
    const = [(consts[i][0], h48(cv[i:i + CONST_K])) for i in range(len(cv) - CONST_K + 1)]
    out = {'code': code, 'consts': const, 'strings': strings, 'toks': code_toks}
    if raw:
        rt = [norm_number(t) if k == 'number' else t for k, t, _ in code_toks]
        rh = [h48(rt[i:i + RAW_K]) for i in range(len(rt) - RAW_K + 1)]
        out['raw'] = [(code_toks[i][2], h) for i, h in winnow(rh)]
    return out


def string_value(lit):
    """Content of a string literal token (escapes kept as written)."""
    return lit[1:-1]


class Corpus:
    """Fingerprint sets of the reference code: every source file under the reference folders."""

    def __init__(self, project, dirs, exclude, raw=False):
        self.files = []
        self.missing = []
        self.code, self.consts, self.strings, self.raw = set(), set(), set(), set()
        for d in dirs:
            if not os.path.exists(os.path.join(project, d)):
                self.missing.append(d)
                continue
            for r in walk(project, d, exclude):
                if r.lower().endswith(CODE_EXTS):
                    self.files.append(r)
        self.files = sorted(set(self.files))
        for r in self.files:
            fp = file_fingerprints(read_text(os.path.join(project, r)), raw=raw)
            self.code.update(h for _, h in fp['code'])
            self.consts.update(h for _, h in fp['consts'])
            self.strings.update(string_value(s) for s in fp['strings'])
            if raw:
                self.raw.update(h for _, h in fp['raw'])


# ------------------------------------------------------------------------------------------------ the log
def now_iso():
    t = os.environ.get('SOURCE_DATE_EPOCH')
    t = int(t) if t and rwlib.INT_RE.match(t) else int(time.time())
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(t))


def compact(obj):
    return json.dumps(obj, separators=(',', ':'))


def read_log(path):
    """-> (entries, problems, head): entries parsed in order; problems lists every broken line or link; head is
    the SHA-256 of the last line (the chain covers every line but the last: commit the log to protect it)."""
    entries, problems = [], []
    if not os.path.exists(path):
        return None, ['no clean-room log (run cleanroom.py init)'], None
    with open(path, 'rb') as f:
        data = f.read()
    prev = '0' * 64
    for n, raw in enumerate(data.split(b'\n'), 1):
        if not raw:
            continue
        try:
            e = json.loads(raw.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            problems.append('line %d: not JSON' % n)
            prev = hashlib.sha256(raw).hexdigest()
            continue
        if not isinstance(e, dict):
            problems.append('line %d: not an object' % n)
        else:
            if e.get('prev') != prev:
                problems.append('line %d: prev does not match the line before (edited or removed lines)' % n)
            if e.get('seq') != len(entries):
                problems.append('line %d: seq %s, expected %d' % (n, e.get('seq'), len(entries)))
            entries.append(e)
        prev = hashlib.sha256(raw).hexdigest()
    return entries, problems, (prev if entries or problems else None)


def append_log(path, entry):
    """Append entry with seq, recorded and prev (the SHA-256 of the previous line); returns the entry."""
    prev, seq = '0' * 64, 0
    if os.path.exists(path):
        with open(path, 'rb') as f:
            lines = [x for x in f.read().split(b'\n') if x]
        if lines:
            prev = hashlib.sha256(lines[-1]).hexdigest()
            seq = len(lines)
    e = {'seq': seq, 'recorded': now_iso()}
    e.update(entry)
    e['prev'] = prev
    with open(path, 'ab') as f:
        f.write(compact(e).encode('utf-8') + b'\n')
    return e


def verify_log(path):
    """-> summary dict {entries, head, events {kind: n}, waves {wave: {inputs, events}}, problems, ok}."""
    entries, problems, head = read_log(path)
    events, waves = {}, {}
    for e in entries or []:
        ev = str(e.get('event'))
        events[ev] = events.get(ev, 0) + 1
        w = e.get('wave')
        if w:
            s = waves.setdefault(str(w), {'events': 0, 'inputs': 0})
            s['events'] += 1
            s['inputs'] += len(e.get('inputs') or [])
    if entries is not None and not events.get('init'):
        problems.append('no init entry')
    return {'entries': len(entries or []), 'head': head, 'events': dict(sorted(events.items())),
            'waves': dict(sorted(waves.items())), 'problems': problems, 'ok': entries is not None and not problems}

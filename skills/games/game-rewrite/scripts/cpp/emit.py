#!/usr/bin/env python3
"""Generate a first C++ source tree from matched decomp units (one-shot: then fix the tree by hand).

  python3 -I emit.py --config CFG.json --out DIR [--units DIR] [--report REPORT.json] [--project DIR]

Every unit (*.cpp/*.c of the units folder, sorted) is split into top-level items (cppsplit.py). Library
units ("library_units": CRT, STL instances, library copies) contribute nothing. In the other units:
  * every annotated function (// FUNCTION) goes to one destination file: "addr_dest" {address: file} >
    "name_dest" {free function: file} > "class_dest" {class: file} > "unit_dest" {file: [unit ids]} >
    "default_dest"; it is written with a `// 0x<address>` comment (`(NONMATCHING in the decomp)` added
    when the unit tagged it), in address order;
  * dropped: forward and extern declarations, forward type declarations, explicit instantiations, #include
    and #pragma lines, // STUB items, lines matching "drop.lines" (e.g. // CLFLAGS), unannotated
    definitions with the signature of an annotated function (stand-ins), helpers matching "drop.functions"
    (regexes on the name) or "drop.keys" (signature keys), types defined in the shared "headers" or matching
    "drop.types", macros matching "drop.macros"; "drop.declspecs" (e.g. noinline) and "drop.keywords"
    {keyword: replacement} (e.g. __fastcall: "", __forceinline: "inline") are removed from the code;
  * kept once per destination: unannotated helpers, file statics, macros, unit-local types ("type_home"
    {type: header} moves a type into a header); globals once in the whole tree;
  * renames: "renames.members" {old: new} on the whole text first (two names of one exe function),
    "renames.global" and "renames.units" {unit: {old: new}} on identifiers (not after '.', '->', '::');
  * constants: each unit's own object-like macros and enum constants are evaluated; where a unit's value
    differs from the canonical value of the same name ("constants.canonical" {name: C expression}, plus
    the enums and macros of "constants.headers" and the shared headers), the unit's uses are renamed to the
    canonical name with that value in the same family (the prefix before the first '_', "constants.families"
    maps prefixes), else to the number; "constants.ignore" (regexes) skips names. `#define A B` aliases
    are resolved the same way.
Output: one .cpp per destination and a .h next to it (declarations of public free functions with their
default arguments, extern declarations of public globals, moved types); the shared "headers" {unit header:
out header} are copied with their stand-ins and #include "..." lines removed and get the declarations of the
.cpp of the same name. Each file includes its own header, "includes" (lines for every .cpp), the system
headers of "system_includes" {header: regex} whose regex matches, and every generated header whose names it
uses. A file static used by another file is made public. --report writes a JSON report (stats, stand-ins,
scaffolding, renames, unplaced items, per-file manifest); a JSON summary is printed. Paths in the config are
relative to --project (default: the current folder). Exit 0, 1 when an annotated function has no destination,
2 on bad input. Python standard library only. Port: ../js/cpp/emit.mjs.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import rwlib  # noqa: E402
import cppsplit as C  # noqa: E402

PROG = 'emit'


# ------------------------------------------------------------------------------------ C constants
class EvalError(Exception):
    pass


TOK_RE = re.compile(r"\s*(?:(0[xX][0-9a-fA-F]+|[0-9]+)[uUlL]*|('(?:\\x[0-9a-fA-F]+|\\.|[^'\\])')|"
                    r"([A-Za-z_][A-Za-z0-9_]*)|(<<|>>|<=|>=|==|!=|&&|\|\||[-+*/%~!&|^<>?:(),]))")
ESC = {'n': 10, 'r': 13, 't': 9, '0': 0, '\\': 92, "'": 39, '"': 34, 'b': 8, 'a': 7, 'f': 12, 'v': 11}
BINARY = [('||',), ('&&',), ('|',), ('^',), ('&',), ('==', '!='), ('<', '<=', '>', '>='), ('<<', '>>'),
          ('+', '-'), ('*', '/', '%')]


def _tokens(expr):
    toks = []
    i, n = 0, len(expr)
    while i < n:
        if expr[i:].strip() == '':
            break
        m = TOK_RE.match(expr, i)
        if not m:
            raise EvalError(expr)
        if m.group(1):
            s = m.group(1)
            if s[:2] in ('0x', '0X'):
                v = int(s[2:], 16)
            elif len(s) > 1 and s[0] == '0':
                if not all(c in '01234567' for c in s):
                    raise EvalError(s)
                v = int(s, 8)
            else:
                v = int(s)
            toks.append(('n', v))
        elif m.group(2):
            s = m.group(2)[1:-1]
            if s.startswith('\\x'):
                v = int(s[2:], 16)
            elif s.startswith('\\'):
                v = ESC.get(s[1], ord(s[1]))
            else:
                v = ord(s)
            toks.append(('n', v))
        elif m.group(3):
            toks.append(('i', m.group(3)))
        else:
            toks.append(('o', m.group(4)))
        i = m.end()
    return toks


def _strip_casts(toks, env):
    """Drop C casts: '(' identifiers that are not constants ')' followed by an operand."""
    out = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == ('o', '('):
            j = i + 1
            while j < len(toks) and toks[j][0] == 'i' and toks[j][1] not in env:
                j += 1
            if j > i + 1 and j < len(toks) and toks[j] == ('o', ')') and j + 1 < len(toks):
                nx = toks[j + 1]
                if nx[0] in ('n', 'i') or nx[1] in ('(', '-', '+', '~', '!'):
                    i = j + 1
                    continue
        out.append(t)
        i += 1
    return out


def _cdiv(a, b):
    if b == 0:
        raise EvalError('division by zero')
    q = abs(a) // abs(b)
    return q if (a < 0) == (b < 0) else -q


def _apply(op, a, b):
    if op == '||':
        return 1 if (a or b) else 0
    if op == '&&':
        return 1 if (a and b) else 0
    if op == '|':
        return a | b
    if op == '^':
        return a ^ b
    if op == '&':
        return a & b
    if op == '==':
        return 1 if a == b else 0
    if op == '!=':
        return 1 if a != b else 0
    if op == '<':
        return 1 if a < b else 0
    if op == '<=':
        return 1 if a <= b else 0
    if op == '>':
        return 1 if a > b else 0
    if op == '>=':
        return 1 if a >= b else 0
    if op in ('<<', '>>'):
        if b < 0 or b > 256:
            raise EvalError('shift')
        return a << b if op == '<<' else a >> b
    if op == '+':
        return a + b
    if op == '-':
        return a - b
    if op == '*':
        return a * b
    if op == '/':
        return _cdiv(a, b)
    return a - b * _cdiv(a, b)


class _Parser:
    def __init__(self, toks, env):
        self.t = toks
        self.i = 0
        self.env = env

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else ('e', None)

    def take(self, op):
        if self.peek() != ('o', op):
            raise EvalError(op)
        self.i += 1

    def cond(self):
        c = self.binary(0)
        if self.peek() == ('o', '?'):
            self.i += 1
            a = self.cond()
            self.take(':')
            b = self.cond()
            return a if c else b
        return c

    def binary(self, level):
        if level == len(BINARY):
            return self.unary()
        v = self.binary(level + 1)
        while self.peek()[0] == 'o' and self.peek()[1] in BINARY[level]:
            op = self.peek()[1]
            self.i += 1
            v = _apply(op, v, self.binary(level + 1))
        return v

    def unary(self):
        k, v = self.peek()
        if k == 'o' and v in ('-', '+', '~', '!'):
            self.i += 1
            x = self.unary()
            return -x if v == '-' else x if v == '+' else ~x if v == '~' else (0 if x else 1)
        if k == 'o' and v == '(':
            self.i += 1
            x = self.cond()
            self.take(')')
            return x
        if k == 'n':
            self.i += 1
            return v
        if k == 'i' and self.env.get(v) is not None:
            self.i += 1
            return self.env[v]
        raise EvalError(str(v))


def c_eval(expr, env):
    """Value of a C integer constant expression (names from env), or None."""
    try:
        toks = _strip_casts(_tokens(C.strip_comments(expr)), env)
        if not toks:
            return None
        p = _Parser(toks, env)
        v = p.cond()
        if p.i != len(toks):
            return None
        return v
    except EvalError:
        return None


ENUM_RE = re.compile(r'\benum\s*(?:class\s+|struct\s+)?(\w*)\s*(?::\s*[\w\s]+?)?\s*\{([\s\S]*)\}')


def parse_enum(text):
    """(name or None, [(constant, expression or None)]) of an enum definition."""
    m = ENUM_RE.search(C.strip_comments(text))
    if not m:
        return None, []
    out = []
    for part in C.split_top(m.group(2)):
        part = part.strip()
        mm = re.match(r'^([A-Za-z_]\w*)\s*(?:=\s*([\s\S]*))?$', part)
        if mm:
            out.append((mm.group(1), mm.group(2)))
    return (m.group(1) or None), out


def eval_enum(consts, env):
    res = []
    nxt = 0
    for n, ex in consts:
        v = c_eval(ex, env) if ex is not None else nxt
        env[n] = v
        res.append((n, v))
        nxt = v + 1 if v is not None else None
    return res


DEFINE_RE = re.compile(r'^#\s*define\s+([A-Za-z_]\w*)(\()?')


def define_parts(text):
    """(name, function-like, body) of a #define line, or None."""
    m = DEFINE_RE.match(text)
    if not m:
        return None
    return m.group(1), m.group(2) is not None, text[m.end():].replace('\\\n', ' ').strip()


# --------------------------------------------------------------------------------- header symbols
def header_symbols(text, cfg):
    """{'types', 'consts', 'macros', 'flags', 'funcs', 'vars'} a header defines or declares (top level);
    flags are macros without a body (include guards, feature switches)."""
    s = {'types': set(), 'consts': set(), 'macros': set(), 'flags': set(), 'funcs': set(), 'vars': set()}
    for ns, it in C.walk(C.split(text)):
        if it.kind == 'pp':
            d = define_parts(it.text)
            if d:
                s['macros' if d[1] or d[2] else 'flags'].add(d[0])
            continue
        if it.kind != 'code':
            continue
        cls = C.classify(it.text)
        if cls in ('typedef', 'typedecl'):
            nm = C.type_name(it.text, cls)
            if nm:
                s['types'].add(nm)
            if re.match(r'^\s*(typedef\s+)?enum\b', C.strip_comments(it.text)):
                for n, _ in parse_enum(it.text)[1]:
                    s['consts'].add(n)
        elif cls in ('funcdecl', 'funcdef') or (cls == 'externdecl' and C.find_params(C.strip_comments(it.text))):
            fn = C.parse_function(it.text, list(ns), cfg)
            if fn:
                s['funcs'].add(fn.name.split('::')[-1])
        elif cls in ('externdecl', 'vardef'):
            nm = C.var_name(it.text)[0]
            if nm:
                s['vars'].add(nm)
    return s


# ------------------------------------------------------------------------------------- code edits
def clean_code(text, cfg):
    d = cfg.get('drop', {})
    specs = d.get('declspecs', [])
    if specs:
        text = re.sub(r'__declspec\(\s*(?:' + '|'.join(re.escape(x) for x in specs) + r')\s*\)\s*', '', text)
    for kw, rep in d.get('keywords', {}).items():
        text = re.sub(r'\b' + re.escape(kw) + (r'\b\s*' if rep == '' else r'\b'), lambda m, r=rep: r, text)
    return text


def raw_body_start(text):
    """Index of the '{' that opens a definition's body (outside comments and literals), or None."""
    i, n = 0, len(text)
    depth = 0
    seen = False
    while i < n:
        c = text[i]
        if (c == '/' and i + 1 < n and text[i + 1] in '/*') or c == '"' or c == "'":
            i = C.skip_lit(text, i, n)
            continue
        if c == '(':
            depth += 1
            seen = True
        elif c == ')':
            depth -= 1
        elif c == '{' and depth == 0 and seen:
            return i
        i += 1
    return None


def def_parts(text):
    """(header without comments, body from its '{', [default expression or None per parameter])."""
    j = raw_body_start(text)
    if j is None:
        return C.strip_comments(text).strip(), '', []
    head = C.strip_comments(text[:j]).strip()
    pr = C.find_params(head)
    if not pr:
        return head, text[j:], []
    ps = C.split_top(head[pr[0] + 1:pr[1]])
    return head, text[j:], [p.split('=', 1)[1].strip() if '=' in p else None for p in ps]


def with_params(head, fn_defaults=None, strip=False):
    """Header with defaults stripped (strip) or filled in from fn_defaults."""
    pr = C.find_params(head)
    if not pr:
        return head
    a, b = pr
    ps = C.split_top(head[a + 1:b])
    out = []
    for i, p in enumerate(ps):
        base = re.sub(r'\s*=[\s\S]*$', '', p) if '=' in p else p
        if not strip and fn_defaults and i < len(fn_defaults) and fn_defaults[i] is not None:
            base = base.rstrip() + ' = ' + fn_defaults[i]
        out.append(base)
    return head[:a + 1] + ','.join(out) + head[b:]


def unqualify(sig, fn):
    for n in fn.ns:
        if n:
            sig = re.sub(r'\b' + re.escape(n) + r'::(?=~?\w+\s*\()', '', sig, count=1)
    return sig


def decl_of(e, defaults, header=True):
    """Declaration of a free function: without static/inline for a header, with them for a forward declaration."""
    head, _, dv = def_parts(e.text)
    if not any(x is not None for x in dv):
        dv = defaults.get(e.fn.key)
    sig = unqualify(with_params(head, dv), e.fn)
    if header:
        sig = re.sub(r'^\s*(?:(?:inline|__inline|static)\s+)+', '', sig)
    return sig.strip() + ';'


def strip_static(text):
    code_end = text.find('{')
    head = text[:code_end] if code_end >= 0 else text
    m = re.search(r'\bstatic\s+', head)
    if not m:
        return text
    return text[:m.start()] + text[m.end():]


def strip_def_defaults(text):
    head, body, dv = def_parts(text)
    if not any(x is not None for x in dv):
        return text
    return with_params(head, strip=True) + '\n' + body


def group_ns(items):
    """Lines for [(namespace list, text)], consecutive items of one namespace in one block."""
    out = []
    cur = ()
    for ns, text in items:
        ns = tuple(x for x in ns if x is not None)
        if ns != cur:
            if cur:
                out.append(' '.join('}' for _ in cur))
                out.append('')
            if ns:
                out.append(' '.join('namespace %s {' % n for n in ns))
                out.append('')
            cur = ns
        out.extend(text.rstrip().split('\n'))
        out.append('')
    if cur:
        out.append(' '.join('}' for _ in cur))
        out.append('')
    return out


def relinc(frm, to):
    return os.path.relpath(to, os.path.dirname(frm) or '.').replace(os.sep, '/')


# ------------------------------------------------------------------------------------------- main
class Entry:
    def __init__(self, **kw):
        self.__dict__.update(kw)


def run(cfg, units_dir, out_root):
    stats = {}
    rep = {}

    def count(k, n=1):
        stats[k] = stats.get(k, 0) + n

    def note(k, s):
        rep.setdefault(k, []).append(s)

    module = cfg.get('module')
    drop = cfg.get('drop', {})
    line_rx = re.compile('|'.join('(?:%s)' % r for r in drop['lines'])) if drop.get('lines') else None
    fn_rx = C.full_re(drop.get('functions', []))
    type_rx = C.full_re(drop.get('types', []))
    macro_rx = C.full_re(drop.get('macros', []))
    inc_rx = C.full_re(drop.get('includes', []))
    drop_keys = set(drop.get('keys', []))
    ren_cfg = cfg.get('renames', {})
    consts = cfg.get('constants', {})
    ign_rx = C.full_re(consts.get('ignore', []))
    families = consts.get('families', {})
    libs = set(cfg.get('library_units', []))
    placer = C.Placer(cfg)

    def drop_lines(text):
        if not line_rx:
            return text
        return '\n'.join(l for l in text.split('\n') if not line_rx.search(l))

    # ---- units
    units = []
    for path in C.unit_files(units_dir, cfg):
        text = drop_lines(C.read_text(path))
        text = C.sub_idents(text, ren_cfg.get('members', {}), members=True)
        rows = []
        for ns, it in C.walk(C.split(text)):
            anns, nonm = C.annotations(it.comments, module)
            cls = C.classify(it.text) if it.kind == 'code' else None
            fn = C.parse_function(it.text, list(ns), cfg) if cls in ('funcdef', 'funcdecl') else None
            rows.append(Entry(ns=list(ns), it=it, anns=anns, nonm=nonm, cls=cls, fn=fn))
        units.append((C.unit_id(cfg, path), rows))

    # ---- shared headers: copied (cleaned) later; their names are known
    shared = {}
    for src, dst in cfg.get('headers', {}).items():
        p = os.path.join(units_dir, src)
        shared[dst] = drop_lines(C.read_text(p))
    known = {'types': set(), 'consts': set(), 'macros': set()}
    for dst, text in shared.items():
        hs = header_symbols(text, cfg)
        for k in known:
            known[k] |= hs[k]
        known['macros'] |= hs['flags']

    # ---- canonical constants
    canon = {}
    for n, ex in consts.get('canonical', {}).items():
        canon[n] = c_eval(str(ex), canon)
    ctexts = [C.read_text(h) for h in consts.get('headers', [])] + [shared[d] for d in sorted(shared)]
    for t in ctexts:
        env = dict(canon)
        for ns, it in C.walk(C.split(t)):
            if it.kind == 'pp':
                d = define_parts(it.text)
                if d and not d[1]:
                    v = c_eval(d[2], env)
                    if v is not None and d[0] not in canon:
                        canon[d[0]] = v
                        env[d[0]] = v
            elif it.kind == 'code' and C.classify(it.text) == 'typedef' and \
                    re.match(r'^\s*(typedef\s+)?enum\b', C.strip_comments(it.text)):
                for n, v in eval_enum(parse_enum(it.text)[1], env):
                    if v is not None and n not in canon:
                        canon[n] = v

    def family(n):
        p = n.split('_')[0]
        return families.get(p, p)

    unit_ren, unit_local = {}, {}
    for u, rows in units:
        if u in libs:
            continue
        env = dict(canon)
        local, alias, undefs = {}, {}, set()
        for r in rows:
            if r.it.kind == 'pp':
                m = re.match(r'^#\s*undef\s+(\w+)', r.it.text)
                if m:
                    undefs.add(m.group(1))
                d = define_parts(r.it.text)
                if d and not d[1] and d[2]:
                    body = C.strip_comments(d[2]).strip()
                    if re.match(r'^[A-Za-z_]\w*$', body):
                        alias[d[0]] = body
                        continue
                    v = c_eval(body, env)
                    if v is not None:
                        local[d[0]] = v
                        env[d[0]] = v
            elif r.cls == 'typedef' and re.match(r'^\s*(typedef\s+)?enum\b', C.strip_comments(r.it.text)):
                for n, v in eval_enum(parse_enum(r.it.text)[1], env):
                    if v is not None:
                        local[n] = v
        ren, keep = {}, set()
        for n, v in local.items():
            if ign_rx and ign_rx.match(n):
                continue
            if n in canon and canon[n] == v:
                continue
            fam = family(n)
            cands = [c for c in canon if canon[c] == v and family(c) == fam]
            if n not in canon and not cands:
                keep.add(n)
                continue
            if cands:
                if cands[0] != n:
                    ren[n] = cands[0]
            else:
                ren[n] = str(v)
                note('const_literal', '%s %s=%s (canonical %s)' % (u, n, v, canon[n]))
        for k, b in alias.items():
            if k not in undefs:
                ren[k] = b
        ren.update(ren_cfg.get('units', {}).get(u, {}))
        unit_ren[u] = ren
        unit_local[u] = keep
        if ren:
            note('renames', '%s %s' % (u, ' '.join('%s->%s' % kv for kv in sorted(ren.items()))))

    # ---- default arguments from forward declarations
    defaults = {}
    for u, rows in units:
        for r in rows:
            if r.cls == 'funcdecl' and r.fn is not None:
                code = C.strip_comments(r.it.text)
                pr = C.find_params(code)
                dv = [p.split('=', 1)[1].strip() if '=' in p else None for p in C.split_top(code[pr[0] + 1:pr[1]])]
                if any(x is not None for x in dv) and r.fn.key not in defaults:
                    defaults[r.fn.key] = dv

    # ---- annotated functions of game units
    annotated = set()
    for u, rows in units:
        if u in libs:
            continue
        for r in rows:
            if r.fn is not None and r.cls == 'funcdef' and any(a[0] == 'FUNCTION' for a in r.anns):
                annotated.add(r.fn.key)

    dests = {}

    def dest(d):
        if d not in dests:
            dests[d] = {'funcs': [], 'helpers': [], 'vars': [], 'types': [], 'macros': [], 'units': []}
        return dests[d]

    seen_helper, seen_var, seen_type, seen_macro, globals_def = {}, {}, {}, {}, {}
    home_types = {}

    for u, rows in units:
        if u in libs:
            count('library_unit_items', len(rows))
            continue
        ren = dict(ren_cfg.get('global', {}))
        ren.update(unit_ren.get(u, {}))
        udest = placer.unit.get(u, placer.default)
        for r in rows:
            it, cls, anns = r.it, r.cls, r.anns
            if it.kind == 'tail':
                continue
            if it.kind == 'pp':
                t = it.text
                if re.match(r'^#\s*include\b', t):
                    count('include_dropped')
                    continue
                if re.match(r'^#\s*pragma\b', t):
                    count('pragma_dropped')
                    continue
                d = define_parts(t)
                if udest is None:
                    count('unplaced_pp')
                    continue
                if d:
                    nm = d[0]
                    if (macro_rx and macro_rx.match(nm)) or nm in ren or nm in known['macros']:
                        count('macro_dropped')
                        continue
                    if nm in canon and nm not in unit_local.get(u, set()):
                        count('macro_canonical')
                        continue
                    body = C.sub_idents(t, ren)
                    prev = seen_macro.setdefault(udest, {}).get(nm)
                    if prev is not None:
                        if re.sub(r'\s+', '', C.strip_comments(prev.text)) != re.sub(r'\s+', '', C.strip_comments(body)):
                            note('macro_conflict', '%s %s (%s, %s)' % (udest, nm, prev.unit, u))
                        count('macro_dup')
                        continue
                    e = Entry(name=nm, text=body, unit=u)
                    seen_macro[udest][nm] = e
                    dest(udest)['macros'].append(e)
                    count('macros')
                else:
                    dest(udest)['macros'].append(Entry(name=None, text=t, unit=u))
                    count('pp_kept')
                continue
            if cls in ('funcdecl', 'externdecl', 'fwdtype', 'instantiation'):
                count('dropped_' + cls)
                continue
            if anns and anns[0][0] == 'STUB':
                count('stub_dropped')
                continue
            if cls == 'funcdef':
                fn = r.fn
                body = clean_code(C.sub_idents(it.text, ren), cfg)
                fanns = [a for a in anns if a[0] == 'FUNCTION']
                if fanns:
                    addr = fanns[0][1]
                    d = placer.dest(u, fn, addr)
                    if d is None:
                        note('unplaced', '%s %s %s' % (u, addr, fn.qual))
                        count('unplaced_functions')
                        continue
                    b = dest(d)
                    b['funcs'].append(Entry(addr=addr, fn=fn, text=body, unit=u, ns=r.ns, nonm=r.nonm))
                    if u not in b['units']:
                        b['units'].append(u)
                    count('functions')
                    if r.nonm:
                        count('nonmatching_kept')
                    continue
                if fn.key in annotated:
                    count('standin_dropped')
                    note('standins', '%s %s' % (u, fn.key))
                    continue
                if (fn_rx and fn_rx.match(fn.name.split('::')[-1])) or fn.key in drop_keys:
                    count('scaffold_dropped')
                    note('scaffold', '%s %s' % (u, fn.key))
                    continue
                d = placer.dest(u, fn)
                if d is None:
                    note('unplaced', '%s helper %s' % (u, fn.key))
                    count('unplaced_helpers')
                    continue
                if fn.key in seen_helper.setdefault(d, {}):
                    count('helper_dup')
                    continue
                e = Entry(fn=fn, text=body, unit=u, ns=r.ns)
                seen_helper[d][fn.key] = e
                dest(d)['helpers'].append(e)
                count('helpers')
                continue
            if cls == 'vardef':
                body = clean_code(C.sub_idents(it.text, ren), cfg)
                nm, static = C.var_name(body)
                if nm is None:
                    note('var_unparsed', '%s %s' % (u, C.strip_comments(body).strip()[:80]))
                    continue
                d = placer.dest(u, None, anns[0][1]) if anns else udest
                if d is None:
                    note('unplaced', '%s variable %s' % (u, nm))
                    count('unplaced_vars')
                    continue
                qual = '::'.join([x for x in r.ns + [nm] if x])
                if not static:
                    if qual in globals_def:
                        count('global_dup')
                        continue
                    globals_def[qual] = d
                elif qual in seen_var.setdefault(d, {}):
                    count('static_dup')
                    continue
                seen_var.setdefault(d, {})[qual] = True
                dest(d)['vars'].append(Entry(name=nm, text=body, static=static, ns=r.ns, unit=u,
                                             addr=anns[0][1] if anns else None))
                count('vars')
                continue
            if cls in ('typedef', 'typedecl'):
                nm = C.type_name(it.text, cls)
                if nm and ((type_rx and type_rx.match(nm)) or nm in known['types']):
                    count('type_dropped')
                    continue
                s = C.strip_comments(it.text)
                if cls == 'typedef' and re.match(r'^\s*(typedef\s+)?enum\b', s):
                    names = [ren.get(n, n) for n, _ in parse_enum(s)[1]]
                    if names and all(re.match(r'^-?[0-9]+$', n) or ((n in canon or n in known['consts'])
                                                                    and n not in unit_local.get(u, set()))
                                     for n in names):
                        count('enum_canonical')
                        continue
                body = clean_code(C.sub_idents(it.text, ren), cfg)
                key = '::'.join([x for x in r.ns if x] + [nm or ('<anonymous>' + re.sub(r'\s+', ' ', s.strip())[:60])])
                home = cfg.get('type_home', {}).get(nm or '')
                if home:
                    prev = home_types.setdefault(home, {}).get(key)
                    if prev is None:
                        home_types[home][key] = Entry(name=nm, text=body, ns=r.ns, unit=u)
                        count('types_moved')
                    elif len(C.strip_comments(body)) > len(C.strip_comments(prev.text)):
                        prev.text = body
                    continue
                if udest is None:
                    note('unplaced', '%s type %s' % (u, nm))
                    continue
                prev = seen_type.setdefault(udest, {}).get(key)
                if prev is not None:
                    if re.sub(r'\s+', '', C.strip_comments(prev.text)) != re.sub(r'\s+', '', C.strip_comments(body)):
                        note('type_variant', '%s %s (%s, %s)' % (udest, key, prev.unit, u))
                        if len(C.strip_comments(body)) > len(C.strip_comments(prev.text)):
                            prev.text = body
                    count('type_dup')
                    continue
                e = Entry(name=nm, text=body, ns=r.ns, unit=u)
                seen_type[udest][key] = e
                dest(udest)['types'].append(e)
                count('types')
                continue
            note('unhandled', '%s %s %s' % (u, cls, C.strip_comments(it.text).strip()[:60]))

    # ---- statics used by other files become public
    def_files = {}
    for d, b in dests.items():
        for e in b['funcs'] + b['helpers']:
            if not e.fn.is_member:
                def_files.setdefault(e.fn.qual, set()).add(d)
    idents = {d: C.identifiers('\n'.join(e.text for e in b['funcs'] + b['helpers'] + b['vars']))
              for d, b in dests.items()}
    for d in sorted(dests):
        b = dests[d]
        for e in b['funcs'] + b['helpers']:
            e.public = False
            if e.fn.is_member:
                continue
            nm = e.fn.name
            if not e.fn.is_static:
                e.public = True
                continue
            users = [o for o in sorted(dests) if o != d and nm in idents[o]]
            others = [o for o in sorted(def_files.get(e.fn.qual, ())) if o != d]
            if users and not others and e in b['funcs']:
                e.text = strip_static(e.text)
                e.public = True
                note('made_public', '%s %s (used in %s)' % (d, nm, ', '.join(users)))
        for e in b['vars']:
            e.public = not e.static

    return emit_files(cfg, dests, shared, home_types, defaults, out_root, stats, rep, inc_rx, units)


def emit_files(cfg, dests, shared, home_types, defaults, out_root, stats, rep, inc_rx, units):
    guard_prefix = cfg.get('guard_prefix', '')
    banner = cfg.get('banner', 'From the matched units {units}.')

    # header texts (generated part)
    hdr_paths = set(shared) | set(home_types) | {os.path.splitext(d)[0] + '.h' for d in dests}
    gen = {h: [] for h in hdr_paths}
    decls = {h: [] for h in hdr_paths}
    for h, types in home_types.items():
        for key in types:
            e = types[key]
            gen[h].extend(group_ns([(e.ns, e.text.strip())]))
    have = {}
    for h, text in shared.items():
        keys = set()
        for ns, it in C.walk(C.split(text)):
            if it.kind != 'code':
                continue
            cls = C.classify(it.text)
            if cls in ('funcdecl', 'externdecl', 'vardef'):
                fn = C.parse_function(it.text, list(ns), cfg) if C.find_params(C.strip_comments(it.text)) else None
                if fn is not None:
                    keys.add(fn.key)
                elif cls != 'funcdecl':
                    nm = C.var_name(it.text)[0]
                    if nm:
                        keys.add('::'.join([x for x in list(ns) + [nm] if x]))
        have[h] = keys
    for d in sorted(dests):
        b = dests[d]
        h = os.path.splitext(d)[0] + '.h'
        known_decls = have.get(h, set())
        for e in b['funcs'] + b['helpers']:
            if e.public and not e.fn.is_member and e.fn.key not in known_decls:
                decls[h].append((e.fn.ns, decl_of(e, defaults)))
        for e in b['vars']:
            if e.public and '::'.join([x for x in e.ns + [e.name] if x]) not in known_decls:
                s = C.strip_comments(e.text).strip()
                s = re.sub(r'\s*=[\s\S]*;$', ';', s)
                decls[h].append((e.ns, 'extern ' + s))
    htext = {}
    for h in sorted(hdr_paths):
        parts = list(gen[h])
        if decls[h]:
            parts.append('/* defined in %s */' % (os.path.basename(os.path.splitext(h)[0]) + '.cpp'))
            parts.extend(group_ns(decls[h]))
        htext[h] = '\n'.join(parts).strip()

    # cleaned shared headers
    shared_clean = {}
    type_rx = C.full_re(cfg.get('drop', {}).get('types', []))
    for h, text in shared.items():
        cut = []
        for ns, it in C.walk(C.split(text)):
            gone = False
            if it.kind == 'pp':
                m = re.match(r'^#\s*include\s*([<"])([^>"]*)', it.text)
                if re.match(r'^#\s*pragma\b', it.text):
                    gone = True
                elif m and (m.group(1) == '"' or (inc_rx and inc_rx.match(m.group(2)))):
                    gone = True
            elif it.kind == 'code':
                cls = C.classify(it.text)
                if cls in ('typedef', 'typedecl'):
                    nm = C.type_name(it.text, cls)
                    gone = bool(nm and type_rx and type_rx.match(nm))
            if gone:
                cut.append((it.start, it.start + len(it.text)))
        out, pos = [], 0
        for a, b in sorted(cut):
            out.append(text[pos:a])
            pos = b
            if pos < len(text) and text[pos] == '\n':
                pos += 1
        out.append(text[pos:])
        shared_clean[h] = re.sub(r'\n{3,}', '\n\n', ''.join(out))

    # exports for include computation
    full = {h: shared_clean.get(h, '') + '\n' + htext[h] for h in hdr_paths}
    exports, texports = {}, {}
    for h in hdr_paths:
        s = header_symbols(full[h], cfg)
        texports[h] = s['types'] | s['macros']
        exports[h] = texports[h] | s['consts'] | s['funcs'] | s['vars']

    sysinc = [(k, re.compile(v)) for k, v in cfg.get('system_includes', {}).items()]

    def includes(path, text, types_only):
        ids = C.identifiers(text)
        own = os.path.splitext(path)[0] + '.h'
        res = []
        for h in sorted(hdr_paths):
            if h == path or h == own:
                continue
            if ids & (texports[h] if types_only else exports[h]):
                res.append('#include "%s"' % relinc(path, h))
        return res

    def system(text):
        code = C.strip_comments(text)
        return ['#include %s' % k for k, rx in sysinc if rx.search(code)]

    written = []

    def write(rel, text):
        C.write_text(os.path.join(out_root, rel), re.sub(r'\n{3,}', '\n\n', text).rstrip() + '\n')
        written.append(rel)

    for h in sorted(hdr_paths):
        body = htext[h]
        inc = system(full[h]) + includes(h, full[h], True)
        if h in shared_clean:
            t = shared_clean[h].rstrip()
            present = set(re.findall(r'^#\s*include\s*([<"][^>"]*[>"])', t, re.M))
            inc = [x for x in inc if x[len('#include '):] not in present]
            ends = [m.start() for m in re.finditer(r'^#\s*endif\b.*$', t, re.M)]
            guard = re.search(r'^#\s*ifndef\s+\w+\s*\n#\s*define\s+\w+[^\n]*\n', t, re.M)
            at = guard.end() if guard else 0
            tail_at = ends[-1] if ends and guard else len(t)
            mid = t[at:tail_at].rstrip()
            out = t[:at] + ('\n' + '\n'.join(inc) + '\n' if inc else '') + mid + \
                ('\n\n' + body + '\n' if body else '\n') + ('\n' + t[tail_at:] if tail_at < len(t) else '')
            write(h, out)
        else:
            g = guard_prefix + re.sub(r'[^A-Za-z0-9]', '_', h).upper()
            write(h, '#ifndef %s\n#define %s\n\n%s\n\n%s\n\n#endif /* %s */\n' % (g, g, '\n'.join(inc), body, g))

    manifest = {}
    for d in sorted(dests):
        b = dests[d]
        lines = []
        for e in b['macros']:
            lines.append(e.text.strip())
        if b['macros']:
            lines.append('')
        for e in b['types']:
            lines.extend(group_ns([(e.ns, e.text.strip())]))
        vitems = []
        for e in b['vars']:
            vitems.append((e.ns, ('// %s\n' % e.addr if e.addr else '') + e.text.strip()))
        lines.extend(group_ns(vitems))
        fwd = []
        for e in b['helpers'] + b['funcs']:
            if not e.public and not e.fn.is_member:
                fwd.append((e.fn.ns, decl_of(e, defaults, header=False)))
        lines.extend(group_ns(fwd))
        items = []
        for e in b['helpers']:
            items.append((e.ns, strip_def_defaults(e.text.strip())))
        for e in sorted(b['funcs'], key=lambda x: int(x.addr, 16)):
            tag = ' (NONMATCHING in the decomp)' if e.nonm else ''
            items.append((e.ns, '// %s%s\n%s' % (e.addr, tag, strip_def_defaults(e.text.strip()))))
        lines.extend(group_ns(items))
        body = '\n'.join(lines)
        h = os.path.splitext(d)[0] + '.h'
        head = ['// %s' % os.path.basename(d), '//', '// ' + banner.replace('{units}', ', '.join(b['units']) or '-'),
                '', '#include "%s"' % os.path.basename(h), '']
        head += cfg.get('includes', []) + system(body)
        head += [''] + includes(d, body, False) + ['']
        write(d, '\n'.join(head) + '\n' + body)
        manifest[d] = {'units': b['units'], 'functions': len(b['funcs']), 'helpers': len(b['helpers']),
                       'vars': len(b['vars']), 'types': len(b['types']), 'macros': len(b['macros']),
                       'addrs': sorted((e.addr for e in b['funcs']), key=lambda x: int(x, 16))}
    nsrc = sum(1 for w in written if not w.endswith('.h'))
    summary = {'units': len(units), 'library_units': sum(1 for u, _ in units if u in set(cfg.get('library_units', []))),
               'sources': nsrc, 'headers': len(written) - nsrc, 'stats': dict(sorted(stats.items())),
               'report_counts': {k: len(v) for k, v in sorted(rep.items())}}
    return summary, {'stats': dict(sorted(stats.items())), 'report': {k: v for k, v in sorted(rep.items())},
                     'manifest': manifest}


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [
        ('--config', 'str', rwlib.REQUIRED), ('--out', 'str', rwlib.REQUIRED), ('--units', 'str', None),
        ('--report', 'str', None), ('--project', 'str', '.')])
    try:
        cfg = C.load_config(a['config'])
    except (OSError, ValueError):
        sys.stdout.write(rwlib.dumps({'error': 'config cannot be read: %s' % a['config']}) + '\n')
        return 2
    units = a['units'] or (os.path.join(a['project'], cfg['units']) if cfg.get('units') else None)
    if not units or not os.path.isdir(units):
        sys.stdout.write(rwlib.dumps({'error': 'no units folder (--units or "units" in the config)'}) + '\n')
        return 2
    hdrs = cfg.get('constants', {}).get('headers', [])
    missing = [h for h in hdrs if not os.path.isfile(os.path.join(a['project'], h))]
    if missing:
        sys.stdout.write(rwlib.dumps({'error': 'constants header not found: %s' % missing[0]}) + '\n')
        return 2
    cfg = dict(cfg)
    cfg['constants'] = dict(cfg.get('constants', {}))
    cfg['constants']['headers'] = [os.path.join(a['project'], h) for h in hdrs]
    for h in cfg.get('headers', {}):
        if not os.path.isfile(os.path.join(units, h)):
            sys.stdout.write(rwlib.dumps({'error': 'shared header not found: %s' % h}) + '\n')
            return 2
    summary, report = run(cfg, units, a['out'])
    if a['report']:
        C.write_text(a['report'], rwlib.dumps(report) + '\n')
    sys.stdout.write(rwlib.dumps(summary) + '\n')
    return 1 if summary['stats'].get('unplaced_functions') else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""Split C++ translation units (matched decomp units) into top-level items, with their annotations.

  python3 -I cppsplit.py UNIT.cpp... [--module NAME] [--items] [--json OUT]

An item is one top-level thing of the file: a preprocessor line ("pp", continuations included), a
declaration or definition up to its ';' or closing '}' ("code"), a namespace or extern "C" block ("ns",
"externc": their contents are split again, names get the namespace), or trailing comments ("tail"). The
comment lines directly above an item belong to it, so the reccmp-style annotation block of the decomp skill
(`// FUNCTION: MODULE 0x401000 [symbol]`, `// STUB:`, `// GLOBAL:`, `// NONMATCHING ...`) travels with
the definition it annotates. Code items are classified: funcdef, funcdecl, vardef, externdecl, typedef
(class/struct/union/enum definition), typedecl (typedef/using), fwdtype, instantiation.

Prints a JSON summary per file: item counts by kind/class, annotations by kind, nonmatching count, and with
--items one row per item (line, kind, class, name, signature key, annotations). --module keeps only the
annotations of that module (others are ignored). Also the shared library of account.py and emit.py
(splitting, classification, signature keys, identifier renames, the cpp config, placement).
Exit 0, or 2 on a usage error or an unreadable file. Python standard library only. Port: ../js/cpp/cppsplit.mjs.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import rwlib  # noqa: E402

PROG = 'cppsplit'

ANN_RE = re.compile(r'^//\s*(FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY|GLOBAL|VTABLE|STRING)\s*:\s*'
                    r'(?:([A-Za-z_][A-Za-z0-9_]*)\s+)?(0x[0-9a-fA-F]+)(?:\s+(\S+))?')
NONMATCHING_RE = re.compile(r'^//\s*NONMATCHING\b')
IDCHAR = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
IDSTART = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'


def read_text(path):
    """A source file as text: UTF-8 (invalid bytes replaced), CRLF -> LF."""
    with open(path, 'rb') as f:
        return f.read().decode('utf-8', 'replace').replace('\r\n', '\n')


def write_text(path, text):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(text)


# --------------------------------------------------------------------------------------------- lexing
def skip_lit(text, i, n):
    """End index of the comment or string/char literal starting at text[i], or None."""
    c = text[i]
    if c == '/' and i + 1 < n and text[i + 1] == '/':
        j = text.find('\n', i)
        return n if j < 0 else j
    if c == '/' and i + 1 < n and text[i + 1] == '*':
        j = text.find('*/', i + 2)
        return n if j < 0 else j + 2
    if c == '"' or c == "'":
        j = i + 1
        while j < n:
            if text[j] == '\\':
                j += 2
                continue
            if text[j] == c:
                return j + 1
            if text[j] == '\n':
                return j
            j += 1
        return n
    return None


def strip_comments(t):
    """Comments removed (block comments become one space), literals kept."""
    out = []
    i, n = 0, len(t)
    start = 0
    while i < n:
        c = t[i]
        if c == '/' and i + 1 < n and t[i + 1] in '/*':
            out.append(t[start:i])
            j = skip_lit(t, i, n)
            if t[i + 1] == '*':
                out.append(' ')
            i = start = j
            continue
        if c == '"' or c == "'":
            i = skip_lit(t, i, n)
            continue
        i += 1
    out.append(t[start:n])
    return ''.join(out)


def sub_idents(text, mapping, members=False):
    """Replace whole identifiers outside comments and literals (one pass). Unless members is true, an
    identifier right after '.', '>' or ':' (a member access or a qualified name) is left alone."""
    if not mapping:
        return text
    out = []
    i, n = 0, len(text)
    start = 0
    while i < n:
        c = text[i]
        if (c == '/' and i + 1 < n and text[i + 1] in '/*') or c == '"' or c == "'":
            i = skip_lit(text, i, n)
            continue
        if c in IDSTART and (i == 0 or text[i - 1] not in IDCHAR):
            j = i + 1
            while j < n and text[j] in IDCHAR:
                j += 1
            w = text[i:j]
            if w in mapping and (members or i == 0 or text[i - 1] not in '.>:'):
                out.append(text[start:i])
                out.append(mapping[w])
                start = j
            i = j
            continue
        i += 1
    out.append(text[start:n])
    return ''.join(out)


def identifiers(text):
    """Set of identifiers outside comments and literals."""
    s = set()
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if (c == '/' and i + 1 < n and text[i + 1] in '/*') or c == '"' or c == "'":
            i = skip_lit(text, i, n)
            continue
        if c in IDSTART and (i == 0 or text[i - 1] not in IDCHAR):
            j = i + 1
            while j < n and text[j] in IDCHAR:
                j += 1
            s.add(text[i:j])
            i = j
            continue
        i += 1
    return s


# --------------------------------------------------------------------------------------------- split
class Item:
    def __init__(self, kind, comments, text, start, line, children=None, head=None):
        self.kind = kind            # pp, code, ns, externc, tail
        self.comments = comments    # comment lines/blocks directly above
        self.text = text            # raw text (ns/externc: the whole block)
        self.start = start          # offset of text in the file
        self.line = line            # 1-based line of text
        self.children = children or []
        self.head = head            # 'namespace font', 'extern "C"'


NS_RE = re.compile(r'^namespace(\s+[A-Za-z_]\w*)?\s*$')
EXTERNC_RE = re.compile(r'^extern\s+"C(\+\+)?"\s*$')
TYPEHEAD_RE = re.compile(r'^\s*(template\s*<[^>]*>\s*)?(typedef\s+)?(class|struct|union|enum)\b')
EQ_END_RE = re.compile(r'=\s*$')


def _line_of(nl, pos):
    lo, hi = 0, len(nl)
    while lo < hi:
        mid = (lo + hi) // 2
        if nl[mid] < pos:
            lo = mid + 1
        else:
            hi = mid
    return lo + 1


def split(text):
    nl = [i for i, c in enumerate(text) if c == '\n']
    return _split(text, 0, len(text), nl)


def _ws(text, i, n):
    while i < n and text[i] in ' \t\r':
        i += 1
    return i


def _split(text, i, n, nl):
    items = []
    pending = []
    while i < n:
        i = _ws(text, i, n)
        if i >= n:
            break
        c = text[i]
        if c == '\n':
            i += 1
            continue
        if c == '/' and i + 1 < n and text[i + 1] in '/*':
            j = min(skip_lit(text, i, n), n)
            pending.append(text[i:j])
            i = j
            continue
        if c == '#':
            j = i
            while True:
                k = text.find('\n', j, n)
                if k < 0:
                    k = n
                    break
                if text[k - 1] == '\\' or (text[k - 1] == '\r' and text[k - 2] == '\\'):
                    j = k + 1
                    continue
                break
            items.append(Item('pp', pending, text[i:k], i, _line_of(nl, i)))
            pending = []
            i = k
            continue
        start = i
        depth = 0
        done = False
        while i < n:
            s = skip_lit(text, i, n)
            if s is not None:
                i = min(s, n)
                continue
            c = text[i]
            if c == '#' and depth > 0:
                ls = text.rfind('\n', 0, i)
                if ls >= 0 and text[ls + 1:i].strip() == '':
                    k = text.find('\n', i, n)
                    i = n if k < 0 else k
                    continue
            if c in '{([':
                if c == '{' and depth == 0:
                    hs = text[start:i].strip()
                    if NS_RE.match(hs) or EXTERNC_RE.match(hs):
                        d2 = 1
                        j = i + 1
                        while j < n and d2:
                            s2 = skip_lit(text, j, n)
                            if s2 is not None:
                                j = min(s2, n)
                                continue
                            if text[j] == '{':
                                d2 += 1
                            elif text[j] == '}':
                                d2 -= 1
                            j += 1
                        kind = 'ns' if hs.startswith('namespace') else 'externc'
                        kids = _split(text, i + 1, j - 1 if d2 == 0 else j, nl)
                        items.append(Item(kind, pending, text[start:j], start, _line_of(nl, start), kids,
                                          re.sub(r'\s+', ' ', hs)))
                        pending = []
                        i = j
                        k = _ws(text, i, n)
                        if k < n and text[k] == ';':
                            i = k + 1
                        done = True
                        break
                depth += 1
            elif c in '})]':
                depth -= 1
                if c == '}' and depth == 0:
                    j = i + 1
                    k = j
                    while k < n and text[k] in ' \t\r\n':
                        k += 1
                    b = text.find('{', start, n)
                    hb = text[start:b]
                    is_type = TYPEHEAD_RE.match(hb) is not None and '(' not in strip_comments(hb)
                    has_eq = EQ_END_RE.search(hb) is not None
                    if is_type or has_eq or (k < n and text[k] == ';'):
                        while k < n and text[k] != ';':
                            s3 = skip_lit(text, k, n)
                            if s3 is not None:
                                k = min(s3, n)
                                continue
                            k += 1
                        i = min(k + 1, n)
                    else:
                        i = j
                    items.append(Item('code', pending, text[start:i], start, _line_of(nl, start)))
                    pending = []
                    done = True
                    break
            elif c == ';' and depth == 0:
                i += 1
                items.append(Item('code', pending, text[start:i], start, _line_of(nl, start)))
                pending = []
                done = True
                break
            i += 1
        if not done:
            items.append(Item('code', pending, text[start:n], start, _line_of(nl, start)))
            pending = []
            i = n
    if pending:
        items.append(Item('tail', pending, '', n, _line_of(nl, n)))
    return items


def walk(items, ns=()):
    """(namespace tuple, item) for every non-block item, namespaces and extern "C" blocks entered."""
    for it in items:
        if it.kind == 'ns':
            parts = it.head.split(' ')
            yield from walk(it.children, ns + ((parts[1],) if len(parts) > 1 else ('',)))
        elif it.kind == 'externc':
            yield from walk(it.children, ns)
        else:
            yield ns, it


# -------------------------------------------------------------------------------------- annotations
def annotations(comments, module=None):
    """[(kind, address, symbol or None)] of an item's comment lines (other modules skipped), nonmatching."""
    anns = []
    nonm = False
    for c in comments:
        m = ANN_RE.match(c)
        if m:
            if module and m.group(2) and m.group(2) != module:
                continue
            anns.append((m.group(1), m.group(3).lower(), m.group(4)))
        elif NONMATCHING_RE.match(c):
            nonm = True
    return anns, nonm


# ----------------------------------------------------------------------------------- classification
INST_RE = re.compile(r'^template\s+[^<\s]')
TYPEDEF_RE = re.compile(r'^(template\s*<[^{]*?>\s*)?(typedef\s+)?(class|struct|union|enum)\b[^;(]*\{')
TYPEDECL_RE = re.compile(r'^(typedef|using)\b')
FWDTYPE_RE = re.compile(r'^(class|struct|union|enum)\b[^{;(]*;$')


def classify(text):
    s = strip_comments(text).strip()
    if INST_RE.match(s):
        return 'instantiation'
    head = s.split('{')[0]
    if TYPEDEF_RE.match(s) and '(' not in head:
        return 'typedef'
    if TYPEDECL_RE.match(s):
        return 'typedecl'
    if FWDTYPE_RE.match(s):
        return 'fwdtype'
    hs = head.replace('operator==', 'operatorEQEQ').replace('operator=', 'operatorEQ')
    if s.endswith('}') and '(' in hs and '=' not in hs.split('(')[0]:
        return 'funcdef'
    if s.startswith('extern') and not s.startswith('extern "C" {'):
        return 'externdecl'
    if s.endswith(';') and '=' not in hs.split('(')[0]:
        pr = find_params(hs)
        if pr:
            rest = hs[pr[1] + 1:].strip()
            if not hs[pr[0] + 1:].lstrip().startswith('*') and rest in (';', 'const;', 'const ;'):
                return 'funcdecl'
    return 'vardef'


def split_top(s, sep=','):
    """Split at separators outside (), <>, [], {}."""
    parts, depth, cur = [], 0, []
    for ch in s:
        if ch in '([{<':
            depth += 1
        elif ch in ')]}>':
            depth -= 1
        if ch == sep and depth == 0:
            parts.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    if ''.join(cur).strip():
        parts.append(''.join(cur))
    return parts


NAME_BEFORE_PAREN = re.compile(r'([A-Za-z_~][\w:~]*|operator\s*\S+)$')


def _close(s, i):
    d = 0
    for j in range(i, len(s)):
        if s[j] == '(':
            d += 1
        elif s[j] == ')':
            d -= 1
            if d == 0:
                return j
    return None


def find_params(s):
    """(open, close) of the parameter list of the first function declarator in s, or None."""
    depth = 0
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch == '<':
            depth += 1
        elif ch == '>':
            depth -= 1
        elif ch == '(' and depth <= 0:
            m = NAME_BEFORE_PAREN.search(s[:i].rstrip())
            j = _close(s, i)
            if j is None:
                return None
            if m and m.group(1) not in ('__declspec', 'declspec', '__attribute__'):
                return i, j
            i = j
        i += 1
    return None


DEFAULT_TYPE_ALIASES = {
    'unsigned int': 'unsigned', 'signed int': 'int', 'uint8_t': 'unsigned char',
    'int8_t': 'signed char', 'uint16_t': 'unsigned short', 'int16_t': 'short', 'uint32_t': 'unsigned',
    'int32_t': 'int', 'size_t': 'unsigned',
}
PARAM_NAME_RE = re.compile(r'^(.*?[\s*&])([A-Za-z_]\w*)(\s*\[[^\]]*\])*$')


def norm_type(p, cfg):
    """Parameter text -> normalised type for signature keys (name, default, const-by-value dropped)."""
    p = re.sub(r'=[\s\S]*$', '', p).strip()
    p = re.sub(r'\s+', ' ', p)
    if p in ('void', ''):
        return ''
    if p == '...':
        return '...'
    m = PARAM_NAME_RE.match(p)
    if m and m.group(1).strip() not in ('', 'const', 'unsigned', 'signed', 'struct', 'enum', 'class', 'union'):
        p = m.group(1).strip() + ('[]' if m.group(3) else '')
    p = re.sub(r'\b(enum|struct|class|union)\s+', '', p)
    p = p.replace(' *', '*').replace(' &', '&').replace('* ', '*').replace('& ', '&')
    if '*' not in p and '&' not in p:
        p = re.sub(r'\bconst\b\s*', '', p).strip()
    p = re.sub(r'\bconst$', '', p).strip()
    for q in cfg.get('strip_qualifiers', []):
        p = p.replace(q, '')
    aliases = dict(DEFAULT_TYPE_ALIASES)
    aliases.update(cfg.get('type_aliases', {}))
    for k in sorted(aliases, key=lambda x: (-len(x), x)):
        p = re.sub(r'(?<![\w])' + re.escape(k) + r'(?![\w])', aliases[k], p)
    return p


FUNC_NAME_RE = re.compile(r'((?:[A-Za-z_]\w*\s*::\s*)*~?[A-Za-z_]\w*|(?:[A-Za-z_]\w*::)*operator\s*\S+?)\s*$')


class Func:
    pass


def parse_function(text, ns, cfg):
    """Signature info of a function definition or declaration: name, qualified name, class, key."""
    s = strip_comments(text)
    pr = find_params(s)
    if not pr:
        return None
    a, b = pr
    pre = s[:a]
    m = FUNC_NAME_RE.search(pre)
    name = re.sub(r'\s+', '', m.group(1)) if m else '?'
    after = s[b + 1:]
    nss = set(cfg.get('namespaces', []))
    parts = name.split('::')
    ns = [x for x in ns]
    while len(parts) > 1 and parts[0] in nss:
        ns.append(parts.pop(0))
    f = Func()
    f.name = '::'.join(parts)
    f.ns = ns
    f.qual = '::'.join([x for x in ns + [f.name] if x])
    ptypes = [norm_type(x, cfg) for x in split_top(s[a + 1:b])]
    f.ptypes = [] if ptypes == [''] else [x for x in ptypes if x != '']
    f.const = re.match(r'\s*const\b', after) is not None
    f.key = '%s(%s)%s' % (f.qual, ','.join(f.ptypes), ' const' if f.const else '')
    f.is_static = re.search(r'\bstatic\b', pre) is not None
    f.is_member = '::' in f.name
    f.cls = f.name.rsplit('::', 1)[0] if f.is_member else None
    return f


TYPE_NAME_RES = [re.compile(r'(\w+)\s*(\[[^\]]*\])?\s*;\s*$'), re.compile(r'\(\s*\*\s*(\w+)\s*\)')]
TYPEDEF_NAME_RE = re.compile(r'^(?:template\s*<[^{]*?>\s*)?(?:typedef\s+)?(?:class|struct|union|enum)\s+(\w+)')
TYPEDEF_TAIL_RE = re.compile(r'\}\s*(\w+)\s*;\s*$')


def type_name(text, cls):
    """Name a typedef/typedecl item defines (None for an anonymous enum/struct)."""
    s = strip_comments(text).strip()
    if cls == 'typedecl':
        m = re.match(r'^using\s+(\w+)\s*=', s)
        if m:
            return m.group(1)
        if '(' in s:
            m = TYPE_NAME_RES[1].search(s)
            if m:
                return m.group(1)
        m = TYPE_NAME_RES[0].search(s)
        return m.group(1) if m else None
    m = TYPEDEF_NAME_RE.match(s)
    if m:
        return m.group(1)
    m = TYPEDEF_TAIL_RE.search(s)
    return m.group(1) if m else None


VAR_RE = re.compile(r'^([\s\S]*?)\b([A-Za-z_]\w*)\s*((?:\[[^\]]*\])*)\s*(=[\s\S]*|\([\s\S]*\))?;$')


def var_name(text):
    """(name, is_static) of a variable definition, or (None, False)."""
    s = strip_comments(text).strip()
    m = VAR_RE.match(s)
    if not m:
        return None, False
    return m.group(2), re.match(r'^\s*static\b', s) is not None


# ------------------------------------------------------------------------------------- config, units
def load_config(path):
    """The cpp config (see references/cpp.md); missing keys get defaults."""
    with open(path, encoding='utf-8') as f:
        cfg = json.load(f)
    if not isinstance(cfg, dict):
        raise ValueError('config is not a JSON object')
    return cfg


def unit_id(cfg, filename):
    stem = os.path.splitext(os.path.basename(filename))[0]
    rx = cfg.get('unit_id')
    if rx:
        m = re.match(rx, stem)
        if m:
            return m.group(1) if m.groups() else m.group(0)
    return stem


def unit_files(units_dir, cfg):
    exts = tuple(cfg.get('unit_exts', ['.cpp', '.c']))
    names = sorted(f for f in os.listdir(units_dir) if f.endswith(exts) and os.path.isfile(os.path.join(units_dir, f)))
    return [os.path.join(units_dir, f) for f in names]


def full_re(rx_list):
    """One compiled regex matching a whole name against any of the patterns (None for an empty list)."""
    if not rx_list:
        return None
    return re.compile('^(?:' + '|'.join('(?:%s)' % r for r in rx_list) + ')$')


def unit_dests(cfg):
    """unit id -> destination file, from "unit_dest": {file: [unit ids]}."""
    out = {}
    for dest, units in cfg.get('unit_dest', {}).items():
        for u in units:
            out[u] = dest
    return out


class Placer:
    """Destination file of a function/variable: address > free-function name > class > unit > default."""

    def __init__(self, cfg):
        self.addr = {k.lower(): v for k, v in cfg.get('addr_dest', {}).items()}
        self.name = cfg.get('name_dest', {})
        self.cls = cfg.get('class_dest', {})
        self.unit = unit_dests(cfg)
        self.default = cfg.get('default_dest')

    def dest(self, unit, fn=None, addr=None):
        if addr and addr in self.addr:
            return self.addr[addr]
        if fn is not None and not fn.is_member and fn.name in self.name:
            return self.name[fn.name]
        if fn is not None and fn.is_member:
            c = fn.cls.split('::')[-1]
            if c in self.cls:
                return self.cls[c]
        return self.unit.get(unit, self.default)


def load_unit(path, cfg, module=None, pre_renames=None):
    """[(namespace list, item, annotations, nonmatching, class, Func or None)] of one unit."""
    text = read_text(path)
    if pre_renames:
        text = sub_idents(text, pre_renames, members=True)
    rows = []
    for ns, it in walk(split(text)):
        anns, nonm = annotations(it.comments, module)
        cls = classify(it.text) if it.kind == 'code' else None
        fn = parse_function(it.text, list(ns), cfg) if cls in ('funcdef', 'funcdecl') else None
        rows.append((list(ns), it, anns, nonm, cls, fn))
    return text, rows


# ------------------------------------------------------------------------------------------------ CLI
def item_row(ns, it, anns, nonm, cls, fn):
    r = {'line': it.line, 'kind': it.kind, 'class': cls}
    if fn is not None:
        r['name'] = fn.qual
        r['key'] = fn.key
    elif cls in ('typedef', 'typedecl'):
        r['name'] = type_name(it.text, cls)
    elif cls == 'vardef':
        r['name'] = var_name(it.text)[0]
    elif it.kind == 'pp':
        r['name'] = it.text.split('\n')[0][:60]
    if ns:
        r['ns'] = '::'.join(ns)
    if anns:
        r['annotations'] = [' '.join(x for x in a if x) for a in anns]
    if nonm:
        r['nonmatching'] = True
    return r


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [('--module', 'str', None), ('--items', 'flag', False),
                                               ('--json', 'str', None)], [('files', '+')])
    out = []
    for path in a['files']:
        try:
            _, rows = load_unit(path, {}, a['module'])
        except OSError as e:
            sys.stderr.write('%s: error: %s: %s\n' % (PROG, path, e.strerror))
            return 2
        kinds, anns = {}, {}
        nonm = 0
        for ns, it, an, nm, cls, fn in rows:
            k = cls or it.kind
            kinds[k] = kinds.get(k, 0) + 1
            for x in an:
                anns[x[0]] = anns.get(x[0], 0) + 1
            nonm += 1 if nm else 0
        rec = {'file': path, 'items': len(rows), 'kinds': dict(sorted(kinds.items())),
               'annotations': dict(sorted(anns.items())), 'nonmatching': nonm}
        if a['items']:
            rec['list'] = [item_row(*r) for r in rows]
        out.append(rec)
    js = rwlib.dumps(out)
    if a['json']:
        write_text(a['json'], js + '\n')
    sys.stdout.write(js + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

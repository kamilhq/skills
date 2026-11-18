#!/usr/bin/env python3
"""Generate the skeleton of a Rust rewrite: one stub per game function, with its address and C++ head.

  python3 -I gen_skeleton.py index --units DIR --out FUNCS.json [--cpp-config CFG.json] [--module NAME]
                                   [--names INDEX.json] [--headers DIR]
  python3 -I gen_skeleton.py generate --config RUST.json --index FUNCS.json --crate DIR [--names-out FILE]
                                   [--dry-run]

index: reads matched units (decomp phase 6, split by ../cpp/cppsplit.py; --cpp-config gives "module",
"namespaces", "unit_exts") and writes the function index: one record per `// FUNCTION` or `// STUB`
annotation on a function definition or declaration (address, name from --names or the definition, C++
head, unit = file name without extension, class, namespace, annotation, nonmatching, body) and the
file-scope variables (definitions, and `extern` declarations nothing defines; name, type, array dimensions,
address from a `// GLOBAL:` annotation or a trailing `// 0x...` comment, unit, namespace, static) and the data
member names of every class defined in the units or in the --headers folder (for the cx analysis). Annotations
on variables (dynamic initializers) and on no code (fragments) are listed with "code" "variable" / "none";
names that are Ghidra defaults (FUN_...) give way to the definition's name. Constants are left out. An index
made another way (e.g. from pseudocode) works the same: only "address" and "name" are required.

generate: places every function of the index by the config (skip rules, hand-written addresses, classes and
their roles, namespaces, name prefixes, names, addresses, units, default module), maps its C++ head to a
Rust signature (built-in C types plus the config's types; `cx: &mut Cx` first where the function needs game
state) and writes under --crate:
  src/<module>.rs, or src/<module>/mod.rs + src/<module>/<file>.rs: one stub per function, address order:
      // 0x<address>
      /// `<C++ head>`
      pub fn <name>(<params>) -> <ret> {
          stub!(0x<address>, "<C++ name>")
      }
    (methods of element classes inside `impl <Type>`);
  src/state/statics.rs (config "statics"; only with globals in the index): one `<Module>Statics` struct
    per module and `Statics` (cx.statics.<module>.<field>);
  names.tsv (--names-out, default <crate>/tools/names.tsv; always rewritten): address, C++ name, Rust path,
    Rust signature or skip reason, unit; globals as `global <name>` -> `cx.statics.<module>.<field>`.
It never overwrites a hand-edited file: <crate>/.gen_skeleton.json keeps the SHA-256 of every file it wrote,
and an existing file is rewritten only while it still has that hash; files it did not write, and the
config's "keep" list, are never touched. Afterwards it scans <crate>/src for `// 0x...` lines and
`stub!(0x` calls. Prints a JSON summary (placed and skipped per module, unmapped C++ types, files new /
updated / same / kept, functions missing from the tree, stubs left). Exit 0, 2 on bad input.
The config keys are described in references/rust.md. Python standard library only.
Port: ../js/rust/gen_skeleton.mjs.
"""
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'cpp'))
sys.path.insert(0, os.path.dirname(HERE))
import rwlib  # noqa: E402
import cppsplit as C  # noqa: E402

PROG = 'gen_skeleton'
A = re.ASCII

RUST_KEYWORDS = set('as break const continue crate else enum extern false fn for if impl in let loop match mod '
                    'move mut pub ref return self Self static struct super trait true type unsafe use where while '
                    'async await dyn abstract become box do final macro override priv typeof unsized virtual '
                    'yield try union'.split())

# C types every game has (MSVC x86: long is 32 bits, char is signed). The config's "types" extends/overrides.
BUILTIN_TYPES = {
    'int': 'i32', 'signed': 'i32', 'signed int': 'i32', 'long': 'i32', 'long int': 'i32', 'signed long': 'i32',
    'unsigned': 'u32', 'unsigned int': 'u32', 'unsigned long': 'u32', 'short': 'i16', 'short int': 'i16',
    'signed short': 'i16', 'unsigned short': 'u16', 'char': 'i8', 'signed char': 'i8', 'unsigned char': 'u8',
    'bool': 'bool', 'float': 'f32', 'double': 'f64', 'long double': 'f64', 'long long': 'i64', '__int64': 'i64',
    'unsigned long long': 'u64', 'unsigned __int64': 'u64', 'int8_t': 'i8', 'uint8_t': 'u8', 'int16_t': 'i16',
    'uint16_t': 'u16', 'int32_t': 'i32', 'uint32_t': 'u32', 'int64_t': 'i64', 'uint64_t': 'u64', 'size_t': 'usize',
    'intptr_t': 'isize', 'uintptr_t': 'usize', 'ptrdiff_t': 'isize', 'wchar_t': 'u16', 'BOOL': 'i32',
    'BYTE': 'u8', 'WORD': 'u16', 'DWORD': 'u32', 'std::string': 'String',
}
SCALARS = {'i8', 'u8', 'i16', 'u16', 'i32', 'u32', 'i64', 'u64', 'isize', 'usize', 'f32', 'f64', 'bool'}
SIZES = {'i8': 1, 'u8': 1, 'bool': 1, 'i16': 2, 'u16': 2, 'i32': 4, 'u32': 4, 'f32': 4, 'i64': 8, 'u64': 8,
         'f64': 8, 'isize': 4, 'usize': 4}
NOT_CALLS = {'if', 'while', 'for', 'switch', 'return', 'sizeof', 'static_cast', 'reinterpret_cast', 'const_cast',
             'dynamic_cast', 'defined', 'catch', 'throw', 'new', 'delete', 'case'}
SPECIFIERS = ('static', 'inline', '__inline', '__forceinline', 'virtual', 'extern', '__cdecl', '__stdcall',
              '__fastcall', '__thiscall', 'SDLCALL', 'DECLSPEC', 'friend', 'explicit', 'WINAPI', 'APIENTRY')
ADDR_LINE = re.compile(r'^[ \t]*//[ \t]*(0x[0-9a-fA-F]+)[ \t]*$', A | re.M)


class BadInput(Exception):
    pass


def compile_rx(rx):
    try:
        return re.compile(rx, A)
    except re.error:
        raise BadInput('bad regex in the config: %s' % rx)


# ------------------------------------------------------------------------------------------- naming
def snake(name):
    """C++ identifier -> snake_case: loadFileToMemory -> load_file_to_memory, isDown_buttons -> is_down_buttons."""
    s = name.lstrip('_')
    s = re.sub(r'([A-Z]+)([A-Z][a-z])', r'\1_\2', s, flags=A)
    s = re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', s, flags=A)
    s = re.sub(r'_+', '_', s.lower(), flags=A)
    if not s:
        s = 'f'
    if s[0].isdigit():
        s = '_' + s
    if s in RUST_KEYWORDS:
        s += '_'
    return s


def camel(name):
    return ''.join(p[:1].upper() + p[1:] for p in name.split('_') if p)


def split_qual(name):
    if '::' in name:
        i = name.rindex('::')
        return name[:i], name[i + 2:]
    return None, name


def addr_int(a):
    if isinstance(a, str) and re.match(r'^(0[xX])?[0-9a-fA-F]+$', a, A):
        return int(a, 16)
    return -1


# ------------------------------------------------------------------------------------------- C++ heads
def norm_ws(s):
    return ' '.join(s.split())


def parse_param(p):
    """'const std::string& name = \"\"' -> (ctype, name, default). Arrays decay to pointers."""
    default = None
    depth = 0
    for k, c in enumerate(p):
        if c in '(<[{':
            depth += 1
        elif c in ')>]}':
            depth -= 1
        elif c == '=' and depth == 0:
            default = p[k + 1:].strip()
            p = p[:k]
            break
    p = norm_ws(p)
    if p in ('void', '...', ''):
        return p, None, default
    m = re.match(r'^(.*)\(\s*\*\s*(\w*)\s*\)\s*\((.*)\)$', p, A)
    if m:
        return 'fnptr', m.group(2) or None, default
    arr = False
    m = re.match(r'^(.*?)\s*((?:\[[^\]]*\])+)$', p, A)
    if m:
        arr = True
        p = m.group(1)
    m = re.match(r'^(.*?[\s*&])(\w+)$', p, A)
    if m and m.group(1).strip() and m.group(1).strip() not in ('const', 'unsigned', 'signed', 'struct', 'enum',
                                                                 'class', 'union') \
            and m.group(2) not in ('int', 'char', 'float', 'double', 'bool', 'long', 'short', 'unsigned', 'signed',
                                   'const'):
        ctype, name = m.group(1).strip(), m.group(2)
    else:
        ctype, name = p, None
    if arr:
        ctype += '[]'
    return ctype, name, default


def parse_head(head):
    """C++ definition head (text before the body) -> {ret, qname, params, const} or None."""
    h = norm_ws(head)
    h = re.sub(r'\)\s*(const\s*)?throw\s*\(\s*\)\s*', r') \1', h, flags=A).strip()
    m = re.search(r'\)\s*(?:const\s*)?:(?!:)', h, A)
    if m:
        h = h[:m.start() + 1] + h[m.start() + 1:m.end() - 1]
    is_const = bool(re.search(r'\)\s*const\s*;?$', h, A))
    h = re.sub(r'\)\s*const\s*;?$', ')', h, flags=A)
    h = re.sub(r'\)\s*;$', ')', h, flags=A)
    end = h.rfind(')')
    if end < 0:
        return None
    depth, start = 0, None
    for k in range(end, -1, -1):
        if h[k] == ')':
            depth += 1
        elif h[k] == '(':
            depth -= 1
            if depth == 0:
                start = k
                break
    if start is None:
        return None
    pre = h[:start].strip()
    m = re.match(r'^(.*?)((?:[\w~]+\s*::\s*)*(?:operator\s*\S+|~?\w+))$', pre, A)
    if not m:
        return None
    ret = re.sub(r'__declspec\s*\([^)]*\)', ' ', m.group(1), flags=A)
    ret = re.sub(r'extern\s*"C(\+\+)?"', ' ', ret, flags=A)
    for kw in SPECIFIERS:
        ret = re.sub(r'(^|\s)' + re.escape(kw) + r'(?=\s|$)', ' ', ret, flags=A)
    params = []
    ps = h[start + 1:end]
    if ps.strip() not in ('', 'void'):
        params = [parse_param(x) for x in C.split_top(ps)]
    return {'ret': norm_ws(ret), 'qname': re.sub(r'\s+', '', m.group(2)), 'params': params, 'const': is_const}


# ------------------------------------------------------------------------------------------- index
def head_and_body(text):
    s = C.strip_comments(text)
    pr = C.find_params(s)
    if pr is None:
        return norm_ws(s.rstrip().rstrip(';')), ''
    b = s.find('{', pr[1])
    if b < 0:
        return norm_ws(s.rstrip().rstrip(';')), ''
    return norm_ws(s[:b]), s[b:].strip()


GHIDRA_NAME = re.compile(r'^(FUN|thunk_FUN|LAB|SUB|sub)_[0-9a-fA-F]+$', A)
VAR_RE = re.compile(r'^([\s\S]*?)\b([A-Za-z_]\w*)\s*((?:\[[^\]]*\])*)\s*(=[\s\S]*|\([\s\S]*\))?;$', A)


def variable(text):
    s = C.strip_comments(text).strip()
    m = VAR_RE.match(s)
    if not m or not m.group(1).strip() or (',' in m.group(1) and '<' not in m.group(1)):
        return None
    pre, name = m.group(1), m.group(2)
    q = re.search(r'((?:[A-Za-z_]\w*\s*::\s*)+)$', pre, A)
    if q:
        name = re.sub(r'\s+', '', q.group(1)) + name
        pre = pre[:q.start()]
    words = re.sub(r'extern\s*"C(\+\+)?"', ' ', pre, flags=A).split()
    static = 'static' in words
    ctype = norm_ws(' '.join(w for w in words if w not in ('static', 'extern')))
    if not ctype or ctype in ('return', 'typedef', 'using') or '(' in ctype or '"' in ctype:
        return None
    if m.group(4) and m.group(4).startswith('(') and re.match(r'^\s*extern\b', s, A):
        return None
    dims = [norm_ws(x) for x in re.findall(r'\[([^\]]*)\]', m.group(3), A)]
    init = norm_ws(m.group(4)[1:]) if m.group(4) and m.group(4).startswith('=') else ''
    return {'name': name, 'type': ctype, 'dims': dims, 'static': static, 'init': init}


def class_fields(text):
    """Names of the data members of a class/struct definition (declarations at the top level of its body
    without a parameter list; members of a nested anonymous union count as the class's)."""
    s = C.strip_comments(text)
    b, e = s.find('{'), s.rfind('}')
    if b < 0 or e < b:
        return []
    out, cur, nested = [], [], []
    for ch in s[b + 1:e]:
        if ch == '{':
            nested.append('(' in ''.join(cur) or (bool(nested) and nested[-1]))
            cur = []
            continue
        if ch == '}':
            if nested:
                nested.pop()
            cur = []
            continue
        if ch == ';':
            stmt = ''.join(cur)
            cur = []
            if (nested and nested[-1]) or '(' in stmt and not re.search(r'\(\s*\*', stmt, A):
                continue
            stmt = re.sub(r'^\s*((public|private|protected)\s*:\s*)+', '', stmt, flags=A).strip()
            if not stmt or re.match(r'^(typedef|using|friend|enum|class|struct|union|template)\b', stmt, A):
                continue
            for part in C.split_top(stmt):
                part = re.sub(r'=[\s\S]*$', '', part)
                part = re.sub(r':\s*[0-9]+\s*$', '', part)
                part = re.sub(r'(\[[^\]]*\]\s*)+$', '', part.strip())
                m = re.search(r'([A-Za-z_]\w*)\s*\)?\s*$', part, A)
                if m and m.group(1) not in out:
                    out.append(m.group(1))
            continue
        cur.append(ch)
    return out


def collect_classes(path, cpp_cfg, classes):
    _, rows = C.load_unit(path, cpp_cfg)
    for ns, it, anns, nonm, cls, fn in rows:
        if cls == 'typedef':
            name = C.type_name(it.text, cls)
            if name and name not in classes:
                fields = class_fields(it.text)
                if fields:
                    classes[name] = fields


def build_index(units, cpp_cfg, module, names, headers=None):
    funcs, globs, gkeys, classes, externs = [], [], set(), {}, {}
    counts = {'files': 0, 'header_files': 0, 'duplicate_addresses': 0, 'skipped_constants': 0,
              'extern_only_globals': 0}
    seen = set()
    if headers:
        for dp, dn, fn in os.walk(headers):
            dn.sort()
            for f in sorted(fn):
                if f.endswith(('.h', '.hpp', '.hh')):
                    counts['header_files'] += 1
                    collect_classes(os.path.join(dp, f), cpp_cfg, classes)
    for path in C.unit_files(units, cpp_cfg):
        counts['files'] += 1
        unit = os.path.splitext(os.path.basename(path))[0]
        text, rows = C.load_unit(path, cpp_cfg, module)
        for ns, it, anns, nonm, cls, fn in rows:
            if cls == 'typedef':
                tn = C.type_name(it.text, cls)
                if tn and tn not in classes:
                    fields = class_fields(it.text)
                    if fields:
                        classes[tn] = fields
            isfn = cls in ('funcdef', 'funcdecl') and fn is not None
            for kind, addr, sym in anns:
                if kind not in ('FUNCTION', 'STUB'):
                    continue
                if addr in seen:
                    counts['duplicate_addresses'] += 1
                    continue
                seen.add(addr)
                if isfn:
                    head, body = head_and_body(it.text)
                    nm = names.get(addr)
                    if not nm or GHIDRA_NAME.match(nm):
                        nm = fn.qual
                    funcs.append({'address': addr, 'name': nm, 'signature': head,
                                  'unit': unit, 'class': fn.cls, 'namespace': '::'.join(fn.ns) or None,
                                  'annotation': kind, 'nonmatching': nonm,
                                  'code': 'definition' if cls == 'funcdef' else 'declaration',
                                  'body': body if cls == 'funcdef' else ''})
                    continue
                vn = variable(it.text) if cls == 'vardef' else None
                funcs.append({'address': addr, 'name': names.get(addr) or sym or (vn['name'] if vn else ''),
                              'signature': None, 'unit': unit, 'class': None, 'namespace': '::'.join(ns) or None,
                              'annotation': kind, 'nonmatching': nonm,
                              'code': 'variable' if cls == 'vardef' else 'none', 'body': ''})
            if cls in ('vardef', 'externdecl'):
                v = variable(it.text)
                if v is None:
                    continue
                if re.match(r'^const\b', v['type'], A) and '*' not in v['type']:
                    counts['skipped_constants'] += 1
                    continue
                addr = None
                for kind, a, sym in anns:
                    if kind == 'GLOBAL':
                        addr = a
                if addr is None:
                    end = it.start + len(it.text)
                    m = re.match(r'[ \t]*//[ \t]*(0x[0-9a-fA-F]+)', text[end:end + 200], A)
                    if m:
                        addr = m.group(1).lower()
                nsn = '::'.join(ns) or None
                key = (unit if v['static'] else '', nsn or '', v['name'])
                v.update({'address': addr, 'unit': unit, 'namespace': nsn})
                rec = {k: v[k] for k in ('address', 'name', 'type', 'dims', 'init', 'unit', 'namespace', 'static')}
                if cls == 'externdecl':
                    if key not in externs:
                        externs[key] = rec
                    elif externs[key]['address'] is None:
                        externs[key]['address'] = addr
                    continue
                if key in gkeys:
                    continue
                gkeys.add(key)
                globs.append(rec)
    for key in externs:
        if key not in gkeys:
            rec = externs[key]
            rec['declared_only'] = True
            globs.append(rec)
            counts['extern_only_globals'] += 1
    funcs.sort(key=lambda f: (addr_int(f['address']), f['unit']))
    return funcs, globs, {k: classes[k] for k in sorted(classes)}, counts


def cmd_index(a):
    if not a['units'] or not a['out']:
        raise BadInput('index needs --units and --out')
    cpp_cfg = {}
    if a['cpp_config']:
        try:
            cpp_cfg = C.load_config(a['cpp_config'])
        except (OSError, ValueError):
            raise BadInput('cpp config cannot be read: %s' % a['cpp_config'])
    if not os.path.isdir(a['units']):
        raise BadInput('no such units folder: %s' % a['units'])
    names = {}
    if a['names']:
        try:
            with open(a['names'], encoding='utf-8') as f:
                d = json.load(f)
            fl = d.get('functions', []) if isinstance(d, dict) else d
            names = {str(x.get('address', '')).lower(): x.get('name', '') for x in fl if isinstance(x, dict)}
        except (OSError, ValueError):
            raise BadInput('names index cannot be read: %s' % a['names'])
    module = a['module'] or cpp_cfg.get('module')
    if a['headers'] and not os.path.isdir(a['headers']):
        raise BadInput('no such headers folder: %s' % a['headers'])
    funcs, globs, classes, counts = build_index(a['units'], cpp_cfg, module, names, a['headers'])
    C.write_text(a['out'], rwlib.dumps({'units': a['units'], 'module': module, 'functions': funcs,
                                         'globals': globs, 'classes': classes}) + '\n')
    codes = {}
    for f in funcs:
        codes[f['code']] = codes.get(f['code'], 0) + 1
    summary = {'out': a['out'], 'functions': len(funcs), 'code': {k: codes[k] for k in sorted(codes)},
               'nonmatching': sum(1 for f in funcs if f['nonmatching']), 'globals': len(globs),
               'globals_with_address': sum(1 for g in globs if g['address']), 'classes': len(classes)}
    summary.update(counts)
    sys.stdout.write(rwlib.dumps(summary) + '\n')
    return 0


# ------------------------------------------------------------------------------------------- types
class Types:
    def __init__(self, cfg):
        self.types = dict(BUILTIN_TYPES)
        self.types.update(cfg.get('types', {}))
        self.params = cfg.get('param_types', {})
        self.rets = cfg.get('return_types', {})
        self.drop = cfg.get('drop_params', {})
        self.enums = cfg.get('enums', {})
        self.classes = {k: v.get('rust', k) for k, v in cfg.get('classes', {}).items()}
        self.varargs = cfg.get('varargs', '&[VArg]')
        self.consts = cfg.get('constants', {})
        self.unmapped = {}

    def note(self, what):
        self.unmapped[what] = self.unmapped.get(what, 0) + 1

    @staticmethod
    def base(t):
        t = re.sub(r'\b(const|struct|enum|class|volatile|mutable|typename|union)\b', ' ', t, flags=A)
        return norm_ws(t).replace(' *', '*').replace(' &', '&')

    @staticmethod
    def is_const(t):
        return re.search(r'\bconst\b', t, A) is not None

    def named(self, bt):
        last = bt.split('::')[-1]
        for table in (self.enums, self.classes):
            if bt in table:
                return table[bt]
            if last in table:
                return table[last]
        return None

    def value(self, t):
        """C++ type of a field, global, container element or return value -> Rust, or None."""
        bt = self.base(t)
        if bt in self.types:
            return self.types[bt]
        if bt == 'char*':
            return 'String'
        m = re.match(r'^std::vector<(.*)>$', bt, A)
        if m:
            inner = self.value(m.group(1).strip())
            return 'Vec<%s>' % inner if inner else None
        m = re.match(r'^std::map<(.*)>$', bt, A)
        if m:
            kv = [x.strip() for x in C.split_top(m.group(1))]
            if len(kv) == 2:
                k, v = self.value(kv[0]), self.value(kv[1])
                if k and v:
                    return 'BTreeMap<%s, %s>' % (k, v)
            return None
        return self.named(bt)

    def param(self, ctype, name, body, nxt, idx):
        """-> (rust name, rust type or None = dropped, note)."""
        rn = snake(name) if name else 'arg%d' % idx
        if ctype == 'fnptr':
            if 'fnptr' in self.params:
                return rn, self.params['fnptr'], None
            self.note('param fnptr')
            return rn, 'Unmapped /* function pointer */', None
        if ctype in ('...', 'va_list'):
            return 'args', self.varargs, None
        bt = self.base(ctype)
        const = self.is_const(ctype)
        key = ('const ' if const else '') + bt
        for k in (key, bt):
            if k in self.drop:
                return rn, None, self.drop[k]
            if k in self.params:
                return rn, self.params[k], None
        nul = nullable(body, name)
        if bt in self.types and not bt.endswith(('*', '&')):
            if bt == 'std::string':
                return rn, '&str', None
            return rn, self.types[bt], None
        if bt in self.types:
            return rn, self.types[bt], None
        if bt in ('char*', 'char[]'):
            if not const and (bt == 'char[]' or (nxt and self.base(nxt[0]) in ('size_t', 'int', 'unsigned', 'unsigned int')
                                                 and re.search(r'size|len|max', nxt[1] or '', A))):
                return rn, '&mut [u8]', None
            return rn, 'Option<&str>' if nul else '&str', None
        if bt.endswith('[]'):
            inner = self.value(bt[:-2])
            if inner is not None:
                return rn, ('&[%s]' if const else '&mut [%s]') % inner, None
            bt = bt[:-2] + '*'
        if bt == 'std::string&':
            return rn, '&str' if const else '&mut String', None
        if bt == 'std::string*':
            return rn, ('Option<&str>' if nul else '&str') if const else (
                'Option<&mut String>' if nul else '&mut String'), None
        m = re.match(r'^std::vector<(.*)>([&*]?)$', bt, A)
        if m:
            inner = self.value(m.group(1).strip())
            if inner is None:
                self.note('param ' + key)
                return rn, 'Unmapped /* %s */' % ctype, None
            if m.group(2) and const:
                return rn, '&[%s]' % inner, None
            if m.group(2):
                return rn, '&mut Vec<%s>' % inner, None
            return rn, 'Vec<%s>' % inner, None
        if bt == 'void*':
            return rn, '&[u8]' if const else 'usize', None
        m = re.match(r'^(.*?)([*&])$', bt, A)
        if m and not m.group(1).endswith(('*', '&')):
            inner_c = m.group(1)
            inner = self.types.get(inner_c) if inner_c in self.types and inner_c != 'std::string' else None
            if inner is None:
                inner = self.named(inner_c)
            if inner is not None:
                if m.group(2) == '*' and inner in SCALARS and const:
                    return rn, '&[%s]' % inner, None
                ref = ('&%s' if const else '&mut %s') % inner
                if m.group(2) == '*' and nul:
                    return rn, 'Option<%s>' % ref, None
                return rn, ref, None
        named = self.named(bt)
        if named:
            return rn, named, None
        self.note('param ' + key)
        return rn, 'Unmapped /* %s */' % ctype, None

    def ret(self, ctype, body):
        t = norm_ws(ctype)
        bt = self.base(t)
        if bt in ('', 'void'):
            return None
        key = ('const ' if self.is_const(t) else '') + bt
        for k in (key, bt):
            if k in self.rets:
                return self.rets[k]
        if bt == 'char*':
            return 'Option<String>' if re.search(r'return\s+(NULL|nullptr|0)\s*;', body or '', A) else 'String'
        v = self.value(t)
        if v is not None:
            return v
        self.note('return ' + key)
        return 'Unmapped /* %s */' % t

    def dim(self, d):
        """An array dimension: integer literals, config "constants", + - * / % and parentheses; or None."""
        toks = re.findall(r'0x[0-9a-fA-F]+|[0-9]+|[A-Za-z_]\w*|[-+*/%()]|\S', d, A)
        pos = [0]

        def peek():
            return toks[pos[0]] if pos[0] < len(toks) else None

        def atom():
            t = peek()
            pos[0] += 1
            if t == '(':
                v = expr()
                if peek() != ')':
                    raise ValueError
                pos[0] += 1
                return v
            if t == '-':
                return -atom()
            if t is not None and re.match(r'^(0x[0-9a-fA-F]+|[0-9]+)$', t, A):
                return int(t, 16) if t.startswith('0x') else int(t)
            v = self.consts.get(t) if t is not None else None
            if isinstance(v, int) and not isinstance(v, bool):
                return v
            raise ValueError

        def term():
            v = atom()
            while peek() in ('*', '/', '%'):
                op = peek()
                pos[0] += 1
                r = atom()
                if op == '*':
                    v = v * r
                elif r == 0:
                    raise ValueError
                else:
                    q = abs(v) // abs(r) * (1 if (v < 0) == (r < 0) else -1)
                    v = q if op == '/' else v - q * r
            return v

        def expr():
            v = term()
            while peek() in ('+', '-'):
                op = peek()
                pos[0] += 1
                r = term()
                v = v + r if op == '+' else v - r
            return v

        try:
            v = expr()
        except ValueError:
            return None
        return v if pos[0] == len(toks) and v >= 0 else None


def nullable(body, name):
    if not name or not body:
        return False
    n = re.escape(name)
    return re.search(r'\b%s\s*[!=]=\s*(?:NULL|nullptr|0)\b|\b(?:NULL|nullptr)\s*[!=]=\s*%s\b|!\s*%s\b(?!\s*[.\[(-])|'
                     r'\(\s*%s\s*\)\s*(?:\?|&&|\|\|)|if\s*\(\s*%s\s*\)' % (n, n, n, n, n), body, A) is not None


# ------------------------------------------------------------------------------------------- placement
def dest(s, default_file=None):
    """'module' or 'module/file' -> (module, file or default_file)."""
    if '/' in s:
        m, f = s.split('/', 1)
        return m, f
    return s, default_file


def first_match(rules, unit):
    for rx, val in rules:
        if unit is not None and re.search(rx, unit, A):
            return val
    return None


class Placer:
    def __init__(self, cfg):
        self.cfg = cfg
        self.default = cfg.get('default_module', 'app')
        self.classes = cfg.get('classes', {})
        self.namespaces = cfg.get('namespaces', {})
        self.prefixes = cfg.get('prefixes', [])
        self.names = cfg.get('names', {})
        self.name_patterns = cfg.get('name_patterns', [])
        self.addresses = {k.lower(): v for k, v in cfg.get('addresses', {}).items()}
        self.units = cfg.get('units', [])
        self.module_files = cfg.get('module_files', {})
        self.skip = cfg.get('skip', [])
        self.hand = {k.lower(): v for k, v in cfg.get('handwritten', {}).items()}
        self.rename = {k.lower(): v for k, v in cfg.get('rename', {}).items()}
        rxs = [rx for r in self.skip for rx in r.get('names', []) + r.get('units', [])]
        rxs += [r[0] for r in self.units] + [r[0] for r in self.name_patterns] + [r[0] for rules in self.module_files.values() for r in rules]
        rxs += [r[0] for spec in self.classes.values() for r in spec.get('files', [])]
        for rx in rxs:
            compile_rx(rx)

    def class_of(self, f):
        cls = f.get('class')
        if cls is None and 'class' not in f:
            q, _ = split_qual(f['name'])
            if q is not None and q.split('::')[0] not in self.namespaces:
                cls = q
        return cls

    def skipped(self, f, cls, base):
        unit = f.get('unit') or ''
        for r in self.skip:
            if any(re.search(rx, f['name'], A) for rx in r.get('names', [])) or \
                    any(re.search(rx, unit, A) for rx in r.get('units', [])) or base in r.get('bases', []):
                return r.get('reason', 'skipped by the config')
        if f.get('code') == 'variable':
            return 'annotation on a variable (dynamic initializer): the global itself'
        if f.get('code') == 'none':
            return 'no code in the source (fragment of another function, library object)'
        if base.startswith('~'):
            return 'destructor: Drop'
        if cls is not None:
            spec = self.classes.get(cls.split('::')[-1])
            if spec and spec.get('role', 'value') == 'value' and base == cls.split('::')[-1]:
                return 'constructor of a value type: Default'
        return None

    def file_for(self, module, given, unit):
        if given:
            return given
        rules = self.module_files.get(module)
        if rules:
            f = first_match(rules, unit)
            if f:
                return f
        return module

    def place(self, f):
        """-> dict(module, file, rust_name, style, cls?) or dict(skip=reason)."""
        name, addr, unit = f['name'], f['address'].lower(), f.get('unit')
        cls = self.class_of(f)
        q, base = split_qual(name)
        reason = self.skipped(f, cls, base)
        if reason:
            return {'skip': reason}
        if addr in self.hand:
            path = self.hand[addr]
            mod, rn = path.split('::', 1) if '::' in path else (self.default, path)
            return {'module': mod, 'file': mod, 'rust_name': rn, 'style': 'handwritten'}
        p = self._place(f, cls, q, base, unit)
        if addr in self.addresses:
            mod, fl = dest(self.addresses[addr])
            p['module'], p['file'] = mod, self.file_for(mod, fl, unit)
        if addr in self.rename:
            p['rust_name'] = self.rename[addr]
        return p

    def _place(self, f, cls, q, base, unit):
        if cls is not None:
            short = cls.split('::')[-1]
            spec = self.classes.get(short)
            if spec:
                return self._class(spec, short, base, unit)
            ns = cls.split('::')[0]
            if ns in self.namespaces:
                mod, fl = dest(self.namespaces[ns])
                return {'module': mod, 'file': self.file_for(mod, fl, unit), 'style': 'free',
                        'rust_name': snake(base)}
            return {'module': self.default, 'file': self.file_for(self.default, None, unit), 'style': 'free',
                    'rust_name': snake(f['name'].replace('::', '_'))}
        nsn = f.get('namespace') or (q.split('::')[0] if q else None)
        if f['name'] in self.names:
            mod, fl = dest(self.names[f['name']])
            return {'module': mod, 'file': self.file_for(mod, fl, unit), 'style': 'free', 'rust_name': snake(base)}
        d = first_match(self.name_patterns, f['name'])
        if d:
            mod, fl = dest(d)
            return {'module': mod, 'file': self.file_for(mod, fl, unit), 'style': 'free', 'rust_name': snake(base)}
        if nsn and nsn.split('::')[0] in self.namespaces:
            mod, fl = dest(self.namespaces[nsn.split('::')[0]])
            return {'module': mod, 'file': self.file_for(mod, fl, unit), 'style': 'free', 'rust_name': snake(base)}
        for pre, d, strip in self.prefixes:
            if base.startswith(pre):
                mod, fl = dest(d)
                rn = snake(base[len(pre):]) if strip and len(base) > len(pre) else snake(base)
                return {'module': mod, 'file': self.file_for(mod, fl, unit), 'style': 'free', 'rust_name': rn}
        d = first_match(self.units, unit)
        mod, fl = dest(d) if d else (self.default, None)
        return {'module': mod, 'file': self.file_for(mod, fl, unit), 'style': 'free', 'rust_name': snake(base)}

    def _class(self, spec, short, base, unit):
        role = spec.get('role', 'value')
        rust = spec.get('rust', short)
        mod = spec.get('module', self.default)
        fl = spec.get('file') or first_match(spec.get('files', []), unit) or self.file_for(mod, None, unit)
        if role == 'element':
            rn = 'new' if base == short else snake(base)
            return {'module': mod, 'file': fl, 'rust_name': rn, 'style': 'element', 'cls': short, 'rust_type': rust,
                    'ctor': base == short}
        if role == 'subobject':
            pre = spec.get('prefix', snake(short) + '_')
            return {'module': mod, 'file': fl, 'rust_name': pre + snake(base), 'style': 'method', 'cls': short}
        if role == 'singleton':
            return {'module': mod, 'file': fl, 'rust_name': snake(base), 'style': 'method', 'cls': short}
        return {'module': mod, 'file': fl, 'rust_name': snake(short) + '_' + snake(base), 'style': 'free',
                'cls': short}


# ------------------------------------------------------------------------------------------- cx analysis
CALL_RE = re.compile(r'(?<![\w.>])((?:\w+::)*~?\w+)\s*\(', A)


IDENT_RE = re.compile(r'(?<![\w.>:])([A-Za-z_]\w*)\b(?!\s*::)', A)


def needs_cx(funcs, places, cfg, globs, gmods, fields):
    cxc = cfg.get('cx', {})
    mode = cxc.get('mode', 'all')
    pure = set(cxc.get('pure', []))
    needs = set(cxc.get('needs', []))
    live = [f for f in funcs if 'skip' not in places[f['address']]]
    if mode in ('all', 'none'):
        out = {f['address']: mode == 'all' for f in live}
    else:
        state = [compile_rx(rx) for rx in cxc.get('state', [])]
        gnames, by_mod = set(), {}
        if cxc.get('globals'):
            ign = set(cxc.get('ignore_globals', []))
            for g in globs:
                short = split_qual(g['name'])[1]
                by_mod.setdefault(gmods.get(g['name']), set()).add(short)
                if len(short) >= cxc.get('global_min_len', 5) and short not in ign:
                    gnames.add(short)
        always_methods = cxc.get('methods', 'always') == 'always'
        by_q, by_base = {}, {}
        for f in live:
            by_q.setdefault(f['name'], []).append(f['address'])
            by_base.setdefault(split_qual(f['name'])[1], []).append(f['address'])
        out, calls = {}, {}
        for f in live:
            p = places[f['address']]
            body = f.get('body') or ''
            idents = set(IDENT_RE.findall(body)) if (gnames or by_mod or fields) else set()
            direct = any(r.search(body) for r in state) or not gnames.isdisjoint(idents) or \
                not by_mod.get(p['module'], set()).isdisjoint(idents)
            if p['style'] == 'method':
                own = 'this' in idents or not set(fields.get(p.get('cls'), [])).isdisjoint(idents)
                direct = direct or always_methods or own
            out[f['address']] = direct
            cs = []
            cls = p.get('cls')
            for m in CALL_RE.finditer(body):
                c = m.group(1)
                if c in NOT_CALLS:
                    continue
                cands = by_q.get(c) or (by_q.get(cls + '::' + c) if cls else None) or \
                    (by_base.get(c) if '::' not in c else by_base.get(c.split('::')[-1]))
                for a in cands or []:
                    if a != f['address'] and a not in cs:
                        cs.append(a)
            calls[f['address']] = cs
        changed = True
        while changed:
            changed = False
            for f in live:
                a = f['address']
                if not out[a] and f['name'] not in pure and any(out.get(c) for c in calls[a]):
                    out[a] = True
                    changed = True
    for f in live:
        if f['name'] in needs:
            out[f['address']] = True
        if f['name'] in pure:
            out[f['address']] = False
    return out


# ------------------------------------------------------------------------------------------- emit
def rust_sig(f, p, need, types, cxc):
    sig = parse_head(f['signature']) if f.get('signature') else None
    params, dropped = [], []
    if p['style'] == 'element' and not p.get('ctor'):
        params.append('&self' if sig and sig['const'] else '&mut self')
    if need:
        params.append('%s: &mut %s' % (cxc.get('name', 'cx'), cxc.get('type', 'Cx')))
    used = {cxc.get('name', 'cx'), 'self'}
    plist = sig['params'] if sig else []
    for i, (ct, nm, dv) in enumerate(plist):
        if ct in ('void', ''):
            continue
        nxt = plist[i + 1] if i + 1 < len(plist) else None
        rn, rt, why = types.param(ct, nm, f.get('body') or '', nxt, i)
        if rt is None:
            dropped.append('%s (%s)' % (nm or 'arg%d' % i, why))
            continue
        if rn in used:
            rn = '%s_%d' % (rn, i)
        used.add(rn)
        params.append('%s: %s%s' % (rn, rt, ' /* = %s */' % dv if dv else ''))
    ret = types.ret(sig['ret'], f.get('body') or '') if sig else None
    if p.get('ctor'):
        ret = 'Self'
    return params, ret, dropped


def emit_stub(f, p, need, types, cfg):
    params, ret, dropped = rust_sig(f, p, need, types, cfg.get('cx', {}))
    macro = cfg.get('stub_macro', 'stub')
    lines = ['// %s' % f['address'],
             '/// `%s`%s' % ((f.get('signature') or f['name']).replace('`', "'"),
                             ' (NONMATCHING in the matched source)' if f.get('nonmatching') else '')]
    if dropped:
        lines.append('/// dropped parameter: %s' % '; '.join(dropped))
    lines.append('pub fn %s(%s)%s {' % (p['rust_name'], ', '.join(params), ' -> ' + ret if ret else ''))
    lines.append('    %s!(%s, "%s")' % (macro, f['address'], f['name'].replace('\\', '\\\\').replace('"', '\\"')))
    lines.append('}')
    if p['style'] == 'element':
        lines = ['    ' + x for x in lines]
    return '\n'.join(lines), '(%s)%s' % (', '.join(params), ' -> ' + ret if ret else '')


def file_header(cfg, module, fl, units):
    doc = cfg.get('modules', {}).get(module, '')
    out = ['//! Module `%s`%s%s' % (module, ', file `%s`' % fl if fl != module else '', ': ' + doc if doc else ''),
           '//! Generated by gen_skeleton.py: one stub per C++ function, in address order, with its address and C++',
           '//! head. Fill in the bodies (references/rust.md); `stub!` logs the first call and returns Default.',
           '//! Units: %s' % (', '.join(units) if units else '-'),
           '#![allow(unused_variables, unused_imports, dead_code, clippy::all)]', '']
    out += cfg.get('imports', ['use crate::cx::Cx;', 'use crate::state::*;', 'use crate::stub;'])
    return '\n'.join(out)


def statics_text(cfg, globs, types):
    """src/state/statics.rs and the names rows of the globals."""
    by_mod, rows = {}, []
    for g in globs:
        by_mod.setdefault(g['_module'], []).append(g)
    parts = ['//! File-scope globals of the C++ code, per module (`cx.statics.<module>.<field>`). Generated by',
             '//! gen_skeleton.py from the function index; edit freely afterwards (function-local statics are added',
             '//! by the translator of the function).',
             '#![allow(dead_code, clippy::all)]', '']
    parts += cfg.get('statics_imports', ['use crate::cbuf::CBuf;', 'use crate::state::*;',
                                         'use std::collections::BTreeMap;'])
    for mod in sorted(by_mod):
        sname = camel(mod) + 'Statics'
        fields, inits, seen = [], [], set()
        for g in by_mod[mod]:
            field = snake(split_qual(g['name'])[1])
            if field in seen:
                field = '%s_%s' % (field, (g.get('address') or 'x')[2:])
            seen.add(field)
            t, init = global_type(g, types)
            where = ' '.join(x for x in (g.get('address'), g.get('unit')) if x)
            init_c = g.get('init') or ''
            if len(init_c) > 40:
                init_c = init_c[:37] + '...'
            cdecl = '%s %s%s%s' % (g['type'], g['name'], ''.join('[%s]' % d for d in g.get('dims', [])),
                                   ' = ' + init_c if init_c else '')
            if t is None:
                types.note('global ' + Types.base(g['type']) + ''.join('[%s]' % d for d in g.get('dims', [])))
                fields.append('    // %s: %s (%s) -- type not mapped, add by hand' % (field, cdecl, where))
                rows.append((g.get('address') or '-', 'global ' + g['name'], 'cx.statics.%s.%s' % (mod, field),
                             'Unmapped /* %s */' % g['type'], g.get('unit') or '-'))
                continue
            fields.append('    pub %s: %s, // %s (%s)' % (field, t, cdecl, where))
            inits.append('            %s: %s,' % (field, init))
            rows.append((g.get('address') or '-', 'global ' + g['name'], 'cx.statics.%s.%s' % (mod, field), t,
                         g.get('unit') or '-'))
        parts.append('')
        parts.append('/// Globals of module `%s`.' % mod)
        parts.append('#[derive(Clone, Debug)]')
        parts.append('pub struct %s {' % sname)
        parts += fields
        parts.append('}')
        parts.append('')
        parts.append('impl Default for %s {' % sname)
        parts.append('    fn default() -> Self {')
        parts.append('        Self {')
        parts += inits
        parts.append('        }')
        parts.append('    }')
        parts.append('}')
    parts.append('')
    parts.append('/// All module globals: `cx.statics.<module>`.')
    parts.append('#[derive(Clone, Debug, Default)]')
    parts.append('pub struct Statics {')
    for mod in sorted(by_mod):
        parts.append('    pub %s: %sStatics,' % (mod, camel(mod)))
    parts.append('}')
    return '\n'.join(parts) + '\n', rows


def global_type(g, types):
    """(Rust type, initialiser) of a global, or (None, None)."""
    dims = g.get('dims', [])
    bt = Types.base(g['type'])
    if bt == 'char' and len(dims) == 1:
        n = types.dim(dims[0])
        return ('CBuf<%d>' % n, 'CBuf::new()') if n is not None else (None, None)
    rt = types.value(g['type'])
    if rt is None:
        return None, None
    zero = {'f32': '0.0', 'f64': '0.0', 'bool': 'false'}.get(rt, '0' if rt in SCALARS else 'Default::default()')
    if not dims:
        return rt, zero
    sizes = [types.dim(d) for d in dims]
    if any(s is None for s in sizes):
        return None, None
    t, init = rt, zero
    for n in reversed(sizes):
        t = '[%s; %d]' % (t, n)
    total = 1
    for n in sizes:
        total *= n
    if rt in SCALARS:
        for n in reversed(sizes):
            init = '[%s; %d]' % (init, n)
    else:
        for n in reversed(sizes):
            init = 'std::array::from_fn(|_| %s)' % init
    if total * SIZES.get(rt, 16) > 4096:
        return 'Box<%s>' % t, 'Box::new(%s)' % init
    return t, init


def global_module(g, placer, unit_mod):
    gm = placer.cfg.get('global_modules', {})
    if g['name'] in gm:
        return gm[g['name']]
    q = split_qual(g['name'])[0]
    if q is not None and q.split('::')[-1] in placer.classes:
        return placer.classes[q.split('::')[-1]].get('module', placer.default)
    ns = (g.get('namespace') or '').split('::')[0]
    if ns and ns in placer.namespaces:
        return dest(placer.namespaces[ns])[0]
    counts = unit_mod.get(g.get('unit'))
    if counts:
        return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    return placer.default


def sha256_text(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def scan_tree(src, macro):
    addrs, stubs = set(), []
    if not os.path.isdir(src):
        return addrs, stubs
    for dp, dn, fn in os.walk(src):
        dn.sort()
        for f in sorted(fn):
            if not f.endswith('.rs'):
                continue
            t = C.read_text(os.path.join(dp, f))
            for m in ADDR_LINE.finditer(t):
                addrs.add(m.group(1).lower())
            for m in re.finditer(r'\b%s!\(\s*(0x[0-9a-fA-F]+)' % re.escape(macro), t, A):
                stubs.append(m.group(1).lower())
    return addrs, stubs


def cmd_generate(a):
    if not a['config'] or not a['index'] or not a['crate']:
        raise BadInput('generate needs --config, --index and --crate')
    try:
        with open(a['config'], encoding='utf-8') as f:
            cfg = json.load(f)
        if not isinstance(cfg, dict):
            raise ValueError
    except (OSError, ValueError):
        raise BadInput('config cannot be read: %s' % a['config'])
    try:
        with open(a['index'], encoding='utf-8') as f:
            idx = json.load(f)
    except (OSError, ValueError):
        raise BadInput('index cannot be read: %s' % a['index'])
    funcs = idx.get('functions', []) if isinstance(idx, dict) else idx
    globs = idx.get('globals', []) if isinstance(idx, dict) else []
    fields = idx.get('classes', {}) if isinstance(idx, dict) else {}
    if not isinstance(globs, list) or not all(isinstance(g, dict) and isinstance(g.get('name'), str) and
                                              isinstance(g.get('type'), str) for g in globs):
        raise BadInput('index globals need "name" and "type"')
    if not isinstance(fields, dict):
        raise BadInput('index "classes" must be an object')
    if not isinstance(funcs, list):
        raise BadInput('index "functions" must be a list')
    for i, f in enumerate(funcs):
        if not isinstance(f, dict) or not isinstance(f.get('address'), str) or not isinstance(f.get('name'), str):
            raise BadInput('index function without "address" and "name" (entry %d)' % i)
        f['address'] = f['address'].lower()
    funcs = sorted(funcs, key=lambda f: (addr_int(f['address']), f.get('unit') or ''))
    placer = Placer(cfg)
    types = Types(cfg)
    places = {}
    for f in funcs:
        places[f['address']] = placer.place(f)
    unit_mod = {}
    for f in funcs:
        p = places[f['address']]
        if 'skip' not in p:
            c = unit_mod.setdefault(f.get('unit'), {})
            c[p['module']] = c.get(p['module'], 0) + 1
    sg = cfg.get('skip_globals', {})
    sgn = [compile_rx(rx) for rx in sg.get('names', [])]
    sgu = [compile_rx(rx) for rx in sg.get('units', [])]
    nglobs = len(globs)
    globs = [g for g in globs if not any(r.search((g['namespace'] + '::' if g.get('namespace') else '') + g['name'])
                                         for r in sgn)
             and not any(r.search(g.get('unit') or '') for r in sgu)]
    gmods = {}
    for g in globs:
        g['_module'] = global_module(g, placer, unit_mod)
        gmods.setdefault(g['name'], g['_module'])
    need = needs_cx(funcs, places, cfg, globs, gmods, fields)
    # name collisions inside a module (free functions and methods) or inside an impl
    seen = {}
    for f in funcs:
        p = places[f['address']]
        if 'skip' in p or p['style'] == 'handwritten':
            continue
        key = (p['module'], p.get('rust_type') if p['style'] == 'element' else None, p['rust_name'])
        if key in seen:
            p['rust_name'] = '%s_%s' % (p['rust_name'].rstrip('_'), f['address'][2:])
        seen[key] = f['address']
    rows, by_file, per_mod, skipped = [], {}, {}, {}
    for f in funcs:
        p = places[f['address']]
        unit = f.get('unit') or '-'
        if 'skip' in p:
            rows.append((f['address'], f['name'], '-', p['skip'], unit))
            skipped[p['skip']] = skipped.get(p['skip'], 0) + 1
            continue
        mod = p['module']
        pm = per_mod.setdefault(mod, {'stubs': 0, 'handwritten': 0})
        if p['style'] == 'handwritten':
            rows.append((f['address'], f['name'], '%s::%s' % (mod, p['rust_name']), '(hand-written)', unit))
            pm['handwritten'] += 1
            continue
        text, sig = emit_stub(f, p, need.get(f['address'], False), types, cfg)
        path = '%s::%s::%s' % (mod, p['rust_type'], p['rust_name']) if p['style'] == 'element' else \
            '%s::%s' % (mod, p['rust_name'])
        rows.append((f['address'], f['name'], path, sig, unit))
        by_file.setdefault((mod, p['file']), []).append((f, p, text))
        pm['stubs'] += 1
    out = {}
    files_of = {}
    for mod, fl in by_file:
        files_of.setdefault(mod, []).append(fl)
    for (mod, fl) in sorted(by_file):
        items = by_file[(mod, fl)]
        units = sorted({f.get('unit') for f, p, t in items if f.get('unit')})
        body = [file_header(cfg, mod, fl, units)]
        impls = {}
        for f, p, text in items:
            if p['style'] == 'element':
                impls.setdefault(p['rust_type'], []).append(text)
            else:
                body.append(text)
        for rt in sorted(impls):
            body.append('impl %s {\n%s\n}' % (rt, '\n\n'.join(impls[rt])))
        rel = 'src/%s.rs' % mod if files_of[mod] == [mod] else 'src/%s/%s.rs' % (mod, fl)
        out[rel] = '\n\n'.join(body) + '\n'
    for mod in sorted(files_of):
        if files_of[mod] != [mod]:
            doc = cfg.get('modules', {}).get(mod, '')
            lines = ['//! Module `%s`%s' % (mod, ': ' + doc if doc else ''),
                     '//! (generated by gen_skeleton.py; the files group the C++ functions by origin)', '']
            lines += ['pub mod %s;' % fl for fl in sorted(files_of[mod])] + ['']
            lines += ['pub use %s::*;' % fl for fl in sorted(files_of[mod])]
            out['src/%s/mod.rs' % mod] = '\n'.join(lines) + '\n'
    statics_rel = cfg.get('statics', 'src/state/statics.rs')
    if globs and statics_rel:
        text, grows = statics_text(cfg, globs, types)
        out[statics_rel] = text
        rows += grows
    rows.sort(key=lambda r: (r[0] == '-', addr_int(r[0]), r[1]))
    tsv = '\n'.join(['# address\tC++ name\tRust path\tRust signature (or skip reason)\tunit'] +
                    ['\t'.join(r) for r in rows]) + '\n'
    # ------------------------------------------------------------- write, never over a hand edit
    crate = a['crate']
    man_path = os.path.join(crate, '.gen_skeleton.json')
    manifest = {}
    if os.path.isfile(man_path):
        try:
            with open(man_path, encoding='utf-8') as fh:
                manifest = json.load(fh).get('files', {})
        except (OSError, ValueError, AttributeError):
            raise BadInput('manifest cannot be read: %s' % man_path)
    keep = set(cfg.get('keep', []))
    status = {'new': [], 'updated': [], 'same': [], 'kept_edited': [], 'kept_not_generated': [], 'kept_config': []}
    for rel in sorted(out):
        text = out[rel]
        path = os.path.join(crate, rel)
        if rel in keep:
            status['kept_config'].append(rel)
            continue
        if os.path.exists(path):
            cur = sha256_text(C.read_text(path)) if os.path.isfile(path) else None
            if rel not in manifest:
                status['kept_not_generated'].append(rel)
                continue
            if cur != manifest[rel]:
                status['kept_edited'].append(rel)
                continue
            if cur == sha256_text(text):
                status['same'].append(rel)
                continue
            status['updated'].append(rel)
        else:
            status['new'].append(rel)
        if not a['dry_run']:
            C.write_text(path, text)
            manifest[rel] = sha256_text(text)
    names_out = a['names_out'] or os.path.join(crate, 'tools', 'names.tsv')
    if not a['dry_run']:
        C.write_text(names_out, tsv)
        C.write_text(man_path, rwlib.dumps({'generator': 'gen_skeleton.py',
                                            'files': {k: manifest[k] for k in sorted(manifest)}}) + '\n')
    macro = cfg.get('stub_macro', 'stub')
    tree, stubs = scan_tree(os.path.join(crate, 'src'), macro)
    want = [f['address'] for f in funcs if 'skip' not in places[f['address']]
            and places[f['address']]['style'] != 'handwritten']
    missing = [x for x in want if x not in tree]
    summary = {
        'functions': len(funcs),
        'placed': sum(v['stubs'] for v in per_mod.values()),
        'handwritten': sum(v['handwritten'] for v in per_mod.values()),
        'skipped': sum(skipped.values()),
        'skip_reasons': {k: skipped[k] for k in sorted(skipped)},
        'modules': {m: per_mod[m] for m in sorted(per_mod)},
        'need_cx': sum(1 for x in want if need.get(x)),
        'globals': len(globs),
        'globals_skipped': nglobs - len(globs),
        'names_rows': len(rows),
        'names_out': names_out,
        'unmapped_types': {k: types.unmapped[k] for k in sorted(types.unmapped)},
        'files': {'new': len(status['new']), 'updated': len(status['updated']), 'same': len(status['same']),
                  'kept_edited': status['kept_edited'], 'kept_not_generated': status['kept_not_generated'],
                  'kept_config': status['kept_config']},
        'dry_run': bool(a['dry_run']),
        'tree': {'address_lines': len(tree), 'missing': len(missing), 'first_missing': missing[:20],
                 'stubs_left': len(stubs)},
    }
    sys.stdout.write(rwlib.dumps(summary) + '\n')
    return 0


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [
        ('--units', 'str', None), ('--out', 'str', None), ('--cpp-config', 'str', None), ('--module', 'str', None),
        ('--names', 'str', None), ('--headers', 'str', None), ('--config', 'str', None), ('--index', 'str', None), ('--crate', 'str', None),
        ('--names-out', 'str', None), ('--dry-run', 'flag', False)], [('command', '1')])
    try:
        if a['command'] == 'index':
            return cmd_index(a)
        if a['command'] == 'generate':
            return cmd_generate(a)
        raise BadInput('unknown command %s (index or generate)' % a['command'])
    except BadInput as e:
        sys.stdout.write(rwlib.dumps({'error': str(e)}) + '\n')
        return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

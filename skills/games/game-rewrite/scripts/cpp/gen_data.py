#!/usr/bin/env python3
"""Write C++ definitions of data the matched units only declared `extern`, from the original exe's sections.

  python3 -I gen_data.py --config CFG.json [--pe EXE] [--only NAME[,NAME]] [--out FILE] [--project DIR]

Matched units often declare tables as `extern` and match against the original's data; a rewrite needs real
definitions. The config (a JSON file, or the "data" section of the cpp config) lists them:
  "pe": "work/game/Game.exe",
  "symbols": [{"base": "0x623660", "stride": 5, "count": 55, "expr": "glyph[{i}]"}],
  "items": [{"name": "areamusic", "va": "0x51bfb0", "type": "int32", "count": 400, "per_line": 20,
             "width": 2, "decl": "static const int areamusic[20 * 20]", "file": "music/Music.cpp"}, ...]
Item keys: "name", "va" (virtual address with the image base), "type", "count" (elements) or "dims"
([rows, columns, ...]: nested braces, one innermost row per line), "per_line" (default 16, strings 1),
"width" (right-justify numbers), "format" ("dec", "hex" or "hexN": 0x%0NX), "decl" (the text before
` = {`; default `<C type> <name>[<count>]`), "file" (where it goes, shown in the comment), "stride" (bytes
per element, default the type's size), "fields" (type "struct": ["uint32:hex4", "bool", ...], read in order).
Types: int8 uint8 int16 uint16 int32 uint32 int64 uint64 float32 float64 bool, cstr (a pointer to a
NUL-terminated string: a C literal, NULL, or a "symbols" expression), ptr (a "symbols" expression, NULL,
or (void*)0x...). Floats are written with the fewest digits that read back to the same bits.
An item whose bytes all lie past its section's raw data (.bss) becomes a zero definition (`<decl>;`); one
that is partly initialised reads the rest as zeros.
Without --out the C++ text goes to stdout; with --out it goes to the file and a JSON summary to stdout
(items, zero_initialised, unresolved_pointers). Exit 0, 2 on bad input (address outside every section,
unknown type or format, missing key, bad number, non-finite float). Python standard library only. Port: ../js/cpp/gen_data.mjs.
"""
import json
import math
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import rwlib  # noqa: E402
import cppsplit as C  # noqa: E402

PROG = 'gen_data'
TYPES = {  # name: (struct code, size, C type)
    'int8': ('b', 1, 'signed char'), 'uint8': ('B', 1, 'unsigned char'), 'int16': ('h', 2, 'short'),
    'uint16': ('H', 2, 'unsigned short'), 'int32': ('i', 4, 'int'), 'uint32': ('I', 4, 'unsigned int'),
    'int64': ('q', 8, 'long long'), 'uint64': ('Q', 8, 'unsigned long long'), 'float32': ('f', 4, 'float'),
    'float64': ('d', 8, 'double'), 'bool': ('B', 1, 'bool'), 'cstr': ('I', 4, 'const char*'),
    'ptr': ('I', 4, 'const void*'),
}


class DataError(Exception):
    pass


class PE:
    def __init__(self, path):
        with open(path, 'rb') as f:
            self.data = d = f.read()
        if d[:2] != b'MZ' or len(d) < 0x40:
            raise DataError('%s: not a PE file' % path)
        pe = struct.unpack_from('<I', d, 0x3c)[0]
        if d[pe:pe + 4] != b'PE\0\0' or len(d) < pe + 24 + 2:
            raise DataError('%s: not a PE file' % path)
        nsec = struct.unpack_from('<H', d, pe + 6)[0]
        optsz = struct.unpack_from('<H', d, pe + 20)[0]
        magic = struct.unpack_from('<H', d, pe + 24)[0]
        if len(d) < pe + 24 + optsz + 40 * nsec or optsz < 0x20:
            raise DataError('%s: truncated PE headers' % path)
        self.ptr_size = 8 if magic == 0x20b else 4
        self.base = struct.unpack_from('<Q', d, pe + 24 + 24)[0] if magic == 0x20b else \
            struct.unpack_from('<I', d, pe + 24 + 28)[0]
        self.sections = []
        off = pe + 24 + optsz
        for _ in range(nsec):
            name = d[off:off + 8].rstrip(b'\0').decode('latin-1')
            vsize, va, rawsize, rawptr = struct.unpack_from('<IIII', d, off + 8)
            self.sections.append((name, self.base + va, vsize, rawptr, rawsize))
            off += 40

    def section(self, va):
        for s in self.sections:
            if s[1] <= va < s[1] + max(s[2], s[4]):
                return s
        return None

    def read(self, va, n):
        """(bytes, number of initialised bytes); bytes past the raw data read as 0."""
        s = self.section(va)
        if s is None or va + n > s[1] + max(s[2], s[4]):
            raise DataError('address range 0x%x+%d is not inside one section' % (va, n))
        o = va - s[1]
        raw = max(0, min(n, s[4] - o))
        b = self.data[s[3] + o:s[3] + o + raw] if raw > 0 else b''
        return b + b'\0' * (n - len(b)), raw

    def cstr(self, va):
        out = bytearray()
        while True:
            b = self.read(va + len(out), 1)[0][0]
            if b == 0:
                return bytes(out)
            out.append(b)


def c_string(b):
    out = []
    for ch in b:
        if ch == 0x22:
            out.append('\\"')
        elif ch == 0x5c:
            out.append('\\\\')
        elif ch == 0x0a:
            out.append('\\n')
        elif ch == 0x09:
            out.append('\\t')
        elif 32 <= ch < 127:
            out.append(chr(ch))
        else:
            out.append('\\x%02x' % ch)
    s = ''.join(out)
    s = re.sub(r'(\\x[0-9a-f]{2})(?=[0-9a-fA-F])', r'\1""', s)
    return '"' + s + '"'


FLT_MAX = 3.4028234663852886e+38
FLT_HALFWAY = 3.4028235677973366e+38   # between FLT_MAX and 2**128: from here on a float rounds to inf


def f32(x):
    """x rounded to float32 (as a C compiler reads a float literal; struct.pack refuses x > FLT_MAX)."""
    try:
        return struct.unpack('<f', struct.pack('<f', x))[0]
    except OverflowError:
        return math.copysign(FLT_MAX if abs(x) < FLT_HALFWAY else math.inf, x)


def fmt_float(v, single):
    if math.isnan(v) or math.isinf(v):
        raise DataError('non-finite float value')
    for p in range(1, 18):
        s = '%.*g' % (p, v)
        back = f32(float(s)) if single else float(s)
        if back == v:
            break
    if not re.search(r'[.e]', s):
        s += '.0'
    return s + ('f' if single else '')


def fmt_int(v, fmt):
    if not re.match(r'^(dec|hex|hex[0-9]+)$', fmt):
        raise DataError('unknown format %s' % fmt)
    if fmt == 'hex' or (fmt.startswith('hex') and v < 0):
        return '0x%X' % v if v >= 0 else '-0x%X' % -v
    if fmt.startswith('hex'):
        return '0x%0*X' % (int(fmt[3:]), v)
    return str(v)


def int_val(n):
    """An int from a JSON number or a decimal/0x string."""
    if isinstance(n, bool) or not isinstance(n, (int, str)):
        raise DataError('bad number (not an integer or a string)')
    if isinstance(n, int):
        return n
    m = re.match(r'^(-?)(0[xX][0-9a-fA-F]+|[0-9]+)$', n)
    if not m:
        raise DataError('bad number: %s' % n)
    v = int(m.group(2)[2:], 16) if m.group(2)[:2] in ('0x', '0X') else int(m.group(2))
    return -v if m.group(1) else v


class Gen:
    def __init__(self, pe, symbols):
        self.pe = pe
        self.symbols = [(int_val(s['base']), int_val(s.get('stride', 1)), int_val(s.get('count', 1)), s['expr'])
                        for s in symbols]
        self.unresolved = 0

    def symbol(self, p):
        for base, stride, count, expr in self.symbols:
            if base <= p < base + stride * count and (p - base) % stride == 0:
                return expr.replace('{i}', str((p - base) // stride))
        return None

    def value(self, va, typ, fmt):
        if typ not in TYPES:
            raise DataError('unknown type %s' % typ)
        code, size, _ = TYPES[typ]
        if typ in ('cstr', 'ptr') and self.pe.ptr_size == 8:
            code, size = 'Q', 8
        b, _ = self.pe.read(va, size)
        v = struct.unpack('<' + code, b)[0]
        if typ in ('cstr', 'ptr'):
            if v == 0:
                return 'NULL'
            sym = self.symbol(v)
            if sym is not None:
                return sym
            if typ == 'cstr':
                return c_string(self.pe.cstr(v))
            self.unresolved += 1
            return '(void*)0x%X' % v
        if typ == 'bool':
            return 'true' if v else 'false'
        if typ in ('float32', 'float64'):
            return fmt_float(v, typ == 'float32')
        return fmt_int(v, fmt)

    def element(self, va, item):
        typ = item['type']
        if typ == 'struct':
            vals, off = [], 0
            for f in item['fields']:
                t, _, fm = f.partition(':')
                vals.append(self.value(va + off, t, fm or 'dec'))
                off += self.size_of(t)
            return '{' + ', '.join(vals) + '}'
        return self.value(va, typ, item.get('format', 'dec'))

    def size_of(self, typ):
        if typ not in TYPES:
            raise DataError('unknown type %s' % typ)
        return self.pe.ptr_size if typ in ('cstr', 'ptr') else TYPES[typ][1]

    def item(self, item):
        name = item['name']
        va = int_val(item['va'])
        typ = item['type']
        dims = [int_val(x) for x in item['dims']] if item.get('dims') else [int_val(item.get('count', 1))]
        if any(x < 1 for x in dims):
            raise DataError('%s: count and dims must be at least 1' % name)
        total = 1
        for x in dims:
            total *= x
        if typ == 'struct':
            if 'stride' not in item:
                raise DataError('%s: a struct item needs "stride"' % name)
            stride = int_val(item['stride'])
        else:
            size = self.size_of(typ)
            stride = int_val(item.get('stride', size))
        _, raw = self.pe.read(va, stride * total)
        sec = self.pe.section(va)[0]
        decl = item.get('decl') or ('%s %s%s' % (TYPES[typ][2] if typ in TYPES else 'struct', name,
                                                    ''.join('[%d]' % x for x in dims)))
        head = '// %s: 0x%x (%s), %d x %s%s' % (name, va, sec, total, typ,
                                                  ', for ' + item['file'] if item.get('file') else '')
        if raw == 0:
            return head + ', zero-initialised (no raw data)\n%s;\n' % decl, True
        width = int_val(item.get('width', 0))
        vals = [self.element(va + i * stride, item).rjust(width) for i in range(total)]
        per = int_val(item.get('per_line', 1 if typ in ('cstr', 'struct') else 16))
        if per < 1:
            raise DataError('%s: per_line must be at least 1' % name)
        body = self.nest(vals, dims, 1) if len(dims) > 1 else \
            '\n'.join('    ' + ', '.join(vals[i:i + per]) + ',' for i in range(0, len(vals), per))
        return '%s\n%s = {\n%s\n};\n' % (head, decl, body), False

    def nest(self, vals, dims, depth):
        ind = '    ' * depth
        n = len(vals) // dims[0]
        lines = []
        for i in range(dims[0]):
            sub = vals[i * n:(i + 1) * n]
            if len(dims) == 2:
                lines.append(ind + '{' + ', '.join(sub) + '},')
            else:
                lines.append(ind + '{\n' + self.nest(sub, dims[1:], depth + 1) + '\n' + ind + '},')
        return '\n'.join(lines)


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [
        ('--config', 'str', rwlib.REQUIRED), ('--pe', 'str', None), ('--only', 'str', None), ('--out', 'str', None),
        ('--project', 'str', '.')])
    try:
        with open(a['config'], encoding='utf-8') as f:
            cfg = json.load(f)
        cfg = cfg.get('data', cfg)
    except (OSError, ValueError, AttributeError):
        sys.stdout.write(rwlib.dumps({'error': 'config cannot be read: %s' % a['config']}) + '\n')
        return 2
    pe_path = a['pe'] or (os.path.join(a['project'], cfg['pe']) if cfg.get('pe') else None)
    if not pe_path:
        sys.stdout.write(rwlib.dumps({'error': 'no exe (--pe or "pe" in the config)'}) + '\n')
        return 2
    only = [x for x in a['only'].split(',') if x] if a['only'] else None
    items = [it for it in cfg.get('items', []) if only is None or it.get('name') in only]
    if only:
        missing = [n for n in only if n not in [it.get('name') for it in items]]
        if missing:
            sys.stdout.write(rwlib.dumps({'error': 'no such item: %s' % missing[0]}) + '\n')
            return 2
    try:
        pe = PE(pe_path)
        g = Gen(pe, cfg.get('symbols', []))
        out, zero = [], []
        for it in items:
            text, z = g.item(it)
            out.append(text)
            if z:
                zero.append(it['name'])
    except OSError as e:
        sys.stdout.write(rwlib.dumps({'error': '%s: %s' % (pe_path, e.strerror)}) + '\n')
        return 2
    except (DataError, KeyError) as e:
        sys.stdout.write(rwlib.dumps({'error': str(e) if isinstance(e, DataError) else 'missing key: %s' % e}) + '\n')
        return 2
    text = '\n'.join(out)
    if a['out']:
        C.write_text(a['out'], text)
        sys.stdout.write(rwlib.dumps({'items': len(items), 'zero_initialised': zero,
                                      'unresolved_pointers': g.unresolved, 'out': a['out']}) + '\n')
    else:
        sys.stdout.write(text)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

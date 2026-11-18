#!/usr/bin/env python3
"""rich_header.py <pe> [<pe> ...]
   rich_header.py --compare <original_pe> <your_build_pe>

Decode the MSVC "Rich" header of each PE (the XOR-keyed list of build tools that produced its objects) and
the linker version from the optional header. Output: one JSON line per binary with the linker version and
EVERY (product_id, build, count) entry in header order, plus `tool` = the product id's name from the public
"prodid" enumeration (e.g. 10 Utc12_C = VC6 C compiler, 11 Utc12_CPP = VC6 C++ compiler, 14 Masm613,
4 Linker600, 6 Cvtres500, 1 Import0 = imported symbols) and `largest_compiler` = the compiler (Utc*) entry
with the most objects.
Always quote the full entry list: the biggest C++ group is usually the game's own code, while small C/MASM
groups at another build are often the prebuilt CRT/libs.

The tool names come from a public table and the build -> service-pack mapping (e.g. 8966 = VC6 SP5) from public
lists: label both as inferred. The `cl` banner does NOT print the Rich build (VC6 SP5/SP6 cl says 12.00.8804).
To confirm a toolchain, compile and link a trivial program with it and use --compare: it lists the
(product_id, build) pairs of the original that your build reproduces and those it does not.

Exit 0 ok; 1 a file is not a PE / has no Rich header (reported in its JSON line); 2 bad arguments.
Stdlib only; run with -I.
"""
import json, struct, sys

# Microsoft "prodid" enumeration, low values only (VC5-VC7.1 era); names from public Rich-header research.
PRODID = {
    0: 'Unknown', 1: 'Import0', 2: 'Linker510', 3: 'Cvtomf510', 4: 'Linker600', 5: 'Cvtomf600', 6: 'Cvtres500',
    7: 'Utc11_Basic', 8: 'Utc11_C', 9: 'Utc12_Basic', 10: 'Utc12_C', 11: 'Utc12_CPP', 12: 'AliasObj60',
    13: 'VisualBasic60', 14: 'Masm613', 15: 'Masm710', 16: 'Linker511', 17: 'Cvtomf511', 18: 'Masm614',
    19: 'Linker512', 20: 'Cvtomf512', 21: 'Utc12_C_Std', 22: 'Utc12_CPP_Std', 23: 'Utc12_C_Book',
    24: 'Utc12_CPP_Book', 25: 'Implib700', 26: 'Cvtomf700', 27: 'Utc13_Basic', 28: 'Utc13_C', 29: 'Utc13_CPP',
    30: 'Linker610', 31: 'Cvtomf610', 32: 'Linker601', 33: 'Cvtomf601', 34: 'Utc12_1_Basic', 35: 'Utc12_1_C',
    36: 'Utc12_1_CPP', 37: 'Linker620', 38: 'Cvtomf620', 39: 'AliasObj70', 40: 'Linker621', 41: 'Cvtomf621',
    42: 'Masm615', 43: 'Utc13_LTCG_C', 44: 'Utc13_LTCG_CPP', 45: 'Masm620', 46: 'ILAsm100', 47: 'Utc12_2_Basic',
    48: 'Utc12_2_C', 49: 'Utc12_2_CPP', 50: 'Utc12_2_C_Std', 51: 'Utc12_2_CPP_Std', 52: 'Utc12_2_C_Book',
    53: 'Utc12_2_CPP_Book', 54: 'Implib622', 55: 'Cvtomf622', 56: 'Cvtres501', 57: 'Utc13_C_Std',
    58: 'Utc13_CPP_Std', 59: 'Cvtpgd1300', 60: 'Linker622', 61: 'Linker700', 62: 'Export622', 63: 'Export700',
    64: 'Masm700', 65: 'Utc13_POGO_I_C', 66: 'Utc13_POGO_I_CPP', 67: 'Utc13_POGO_O_C', 68: 'Utc13_POGO_O_CPP',
    69: 'Cvtres700', 70: 'Cvtres710p', 71: 'Linker710p', 72: 'Cvtomf710p', 73: 'Export710p', 74: 'Implib710p',
    75: 'Masm710p', 76: 'Utc1310p_C', 77: 'Utc1310p_CPP',
}


def rich(d, o):
    end = d.find(b'Rich', 0x40, o)
    if end < 0:
        return None, []
    key = d[end + 4:end + 8]
    unx = lambda b: bytes(x ^ y for x, y in zip(b, key))
    start = end - 4
    while start >= 0x40 and unx(d[start:start + 4]) != b'DanS':
        start -= 4
    if start < 0x40:
        return None, []
    entries = []
    for k in range(start + 16, end, 8):
        comp, count = struct.unpack('<II', unx(d[k:k + 4]) + unx(d[k + 4:k + 8]))
        pid = comp >> 16
        entries.append({'product_id': pid, 'build': comp & 0xffff, 'count': count,
                        'tool': PRODID.get(pid, f'prodid_{pid} (not in table)')})
    return key.hex(), entries


def decode(p):
    try:
        d = open(p, 'rb').read()
    except OSError as e:
        return {'file': p, 'error': str(e)}
    if len(d) < 0x40 or d[:2] != b'MZ':
        return {'file': p, 'error': 'not a PE file (no MZ header)'}
    o = struct.unpack_from('<I', d, 0x3c)[0]
    if o + 28 > len(d) or d[o:o + 4] != b'PE\0\0':
        return {'file': p, 'error': 'not a PE file (MZ only, no PE signature)'}
    major, minor = d[o + 24 + 2], d[o + 24 + 3]
    key, entries = rich(d, o)
    r = {'file': p, 'linker': f'{major}.{minor:02d}', 'rich_key': key, 'entries': entries}
    if not entries:
        r['error'] = 'no Rich header (not MSVC-linked, or stripped)'
    else:
        comp = [e for e in entries if e['tool'].startswith('Utc')]
        big = max(comp, key=lambda e: e['count']) if comp else None
        r['largest_compiler'] = {k: big[k] for k in ('product_id', 'build', 'count', 'tool')} if big else None
    return r


def main(argv):
    if argv and argv[0] == '--compare':
        if len(argv) != 3:
            print(__doc__, file=sys.stderr)
            return 2
        a, b = decode(argv[1]), decode(argv[2])
        for r in (a, b):
            if r.get('error'):
                print(json.dumps(r))
                return 1
        pairs = lambda r: {(e['product_id'], e['build']): e['tool'] for e in r['entries']}
        A, B = pairs(a), pairs(b)
        fmt = lambda ks, src: [{'product_id': k[0], 'build': k[1], 'tool': src[k]} for k in sorted(ks)]
        print(json.dumps({'original': a['file'], 'original_linker': a['linker'], 'build': b['file'],
                          'build_linker': b['linker'], 'matched': fmt(A.keys() & B.keys(), A),
                          'only_in_original': fmt(A.keys() - B.keys(), A),
                          'only_in_build': fmt(B.keys() - A.keys(), B)}, indent=1))
        return 0
    rc = 0
    for p in argv:
        r = decode(p)
        rc |= 1 if r.get('error') else 0
        print(json.dumps(r))
    return rc


if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))

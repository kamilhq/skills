#!/usr/bin/env python3
"""peek.py <binary> <address> [<address> ...]

Print what is at each virtual address of a 32-bit PE: the full C string (cp1252), a UTF-16LE string, or
32 raw bytes. Ghidra truncates string labels (s_Error_cargando_l_00712345) and leaves many strings as
DAT_ references; naming agents use this to read the real text.

<address> is a VA in hex with or without 0x (0x1000e280, 1000e280) or a Ghidra label that ends in one
(DAT_1000e280, s_Error_cargando_l_00712345, PTR_FUN_1000e20c). Headers (VA below the first section) are
file-backed; .bss-style tails of a section print <uninitialised>. Exit 0 ok, 1 an address could not be
read, 2 bad arguments or not a PE. Stdlib only; run with -I.
"""
import re, struct, sys


def sections(d):
    if d[:2] != b'MZ' or len(d) < 0x40:
        raise ValueError('no MZ header')
    o = struct.unpack_from('<I', d, 0x3c)[0]
    if d[o:o + 4] != b'PE\0\0':
        raise ValueError('no PE signature')
    n = struct.unpack_from('<H', d, o + 6)[0]
    opt = o + 24
    base = struct.unpack_from('<I', d, opt + 28)[0]
    hdrs = struct.unpack_from('<I', d, opt + 60)[0]          # SizeOfHeaders
    so = opt + struct.unpack_from('<H', d, o + 20)[0]
    return base, hdrs, [struct.unpack_from('<8sIIII', d, so + 40 * i) for i in range(n)]


def parse_addr(a):
    m = re.fullmatch(r'(?:0x)?([0-9a-fA-F]{1,8})', a) or re.fullmatch(r'.*_([0-9a-fA-F]{8})', a)
    return int(m.group(1), 16) if m else None


def main():
    try:
        d = open(sys.argv[1], 'rb').read()
        base, hdrs, secs = sections(d)
    except (OSError, ValueError, struct.error) as e:
        print(f'{sys.argv[1]}: not a readable PE ({e})', file=sys.stderr)
        return 2
    addrs = [(a, parse_addr(a)) for a in sys.argv[2:]]
    bad = [a for a, v in addrs if v is None]
    if bad:
        print('not an address (hex VA or a Ghidra label ending in _<8 hex digits>): ' + ' '.join(bad), file=sys.stderr)
        return 2
    rc = 0
    for a, va in addrs:
        rva, p, why = va - base, None, None
        if rva < 0:
            why = f'below the image base 0x{base:x} (pass a virtual address, not a file offset or RVA)'
        elif rva < hdrs:
            p = rva                                           # headers are mapped 1:1
        else:
            for nm, vs, sva, rs, ro in secs:
                if sva <= rva < sva + max(vs, rs):
                    if rva - sva < rs:
                        p = ro + rva - sva
                    else:
                        why = f'<uninitialised: beyond the file data of {nm.rstrip(bytes(1)).decode("latin1")}>'
                    break
            else:
                why = '<outside every section>'
        if p is None or p >= len(d):
            print(a, why or '<not backed by file bytes>')
            rc = 1
            continue
        raw = d[p:p + 512]
        z = raw.find(b'\0')
        if z > 1 and all(32 <= c < 127 or c in (9, 10, 13) or c >= 0xA0 for c in raw[:z]):
            print(a, repr(raw[:z].decode('cp1252', 'replace')))
        elif len(raw) > 2 and raw[1] == 0 and raw[0] != 0:
            z = raw.find(b'\0\0')
            z = len(raw) & ~1 if z < 0 else z
            print(a, 'utf16', repr(raw[:z + (z & 1)].decode('utf-16-le', 'replace')))
        else:
            print(a, 'bytes', raw[:32].hex(' '))
    return rc


if __name__ == '__main__':
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    sys.exit(main())

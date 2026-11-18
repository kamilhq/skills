#!/usr/bin/env python3
"""Replace functions in a Rust file by new versions, matched by their `// 0x<address>` line.

  python3 -I replace_fn.py TARGET.rs NEW.rs [--dry-run]

NEW.rs holds one or more functions, each starting at its address line (`// 0x401000` alone on a line, the
convention of gen_skeleton.py), with its doc comments and attributes below it; text before the first address
line is ignored, and a block ends where the next address line starts (trailing blank lines dropped). In
TARGET.rs each block replaces the function under the same address line: from that line through the first
line after it that is exactly `}` at the address line's indentation (so a function inside an `impl` block is
found at its own indentation). The new block is re-indented to the target's indentation when its own differs.
Address lines compare case-insensitively. An address that occurs twice in TARGET.rs is not touched. Line ends
of TARGET.rs (LF or CRLF) are kept. Prints a JSON summary (replaced, not_found, duplicates, written).
Exit 0 when every block was replaced, 1 when some were not (the others are still written unless
--dry-run), 2 on bad input. Python standard library only. Port: ../js/rust/replace_fn.mjs.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import rwlib  # noqa: E402

PROG = 'replace_fn'
A = re.ASCII
ADDR = re.compile(r'^([ \t]*)//[ \t]*(0x[0-9a-fA-F]+)[ \t]*$', A)


def read(path):
    with open(path, 'rb') as f:
        return f.read().decode('utf-8', 'replace')


def blocks(text):
    """[(address, indent, [lines])] of the replacement file."""
    out, cur = [], None
    for line in text.split('\n'):
        m = ADDR.match(line)
        if m:
            cur = (m.group(2).lower(), m.group(1), [line])
            out.append(cur)
        elif cur is not None:
            cur[2].append(line)
    res = []
    for addr, ind, lines in out:
        while lines and not lines[-1].strip():
            lines.pop()
        res.append((addr, ind, lines))
    return res


def reindent(lines, old, new):
    if old == new:
        return list(lines)
    out = []
    for ln in lines:
        if not ln.strip():
            out.append('')
        elif ln.startswith(old):
            out.append(new + ln[len(old):])
        else:
            out.append(new + ln.lstrip(' \t'))
    return out


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [('--dry-run', 'flag', False)], [('target', '1'), ('new', '1')])
    try:
        raw = read(a['target'])
        new = read(a['new']).replace('\r\n', '\n')
    except OSError as e:
        sys.stdout.write(rwlib.dumps({'error': 'cannot read: %s' % (e.filename or e)}) + '\n')
        return 2
    crlf = '\r\n' in raw
    lines = raw.replace('\r\n', '\n').split('\n')
    bl = blocks(new)
    if not bl:
        sys.stdout.write(rwlib.dumps({'error': 'no `// 0x<address>` line in %s' % a['new']}) + '\n')
        return 2
    replaced, missing, dups = [], [], []
    for addr, ind, body in bl:
        hits = [i for i, ln in enumerate(lines) if ADDR.match(ln) and ADDR.match(ln).group(2).lower() == addr]
        if len(hits) > 1:
            dups.append(addr)
            continue
        if not hits:
            missing.append(addr)
            continue
        i = hits[0]
        tind = ADDR.match(lines[i]).group(1)
        end = None
        for j in range(i + 1, len(lines)):
            if lines[j].rstrip(' \t') == tind + '}':
                end = j
                break
            if j > i + 1 and ADDR.match(lines[j]):
                break
        if end is None:
            missing.append(addr)
            continue
        lines[i:end + 1] = reindent(body, ind, tind)
        replaced.append(addr)
    text = '\n'.join(lines)
    if crlf:
        text = text.replace('\n', '\r\n')
    written = bool(replaced) and not a['dry_run']
    if written:
        with open(a['target'], 'w', encoding='utf-8', newline='') as f:
            f.write(text)
    sys.stdout.write(rwlib.dumps({'target': a['target'], 'blocks': len(bl), 'replaced': replaced,
                                  'not_found': missing, 'duplicates': dups, 'written': written}) + '\n')
    return 0 if not missing and not dups else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

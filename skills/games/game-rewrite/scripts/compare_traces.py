#!/usr/bin/env python3
"""Compare two per-frame state traces (references/harness.md "Trace format") frame by frame.

  python3 -I compare_traces.py A.trace B.trace [--ignore F1,F2] [--only F1,F2] [--json OUT] [--show N]
         [--quiet] [--project DIR]

A is the reference (the oracle), B the program under test (the rewrite). A trace is a header line, then one
line per logic frame: fields "name=value" separated by single spaces, in a fixed order, the frame number
first. The project's decomp.json "rewrite.trace" section (optional) gives:
  header       the required first line (else: B's first line must equal A's)
  frame_field  name of the frame-number field (default "f")
  fields       the contract's field order without the frame field; when set, a trace whose fields differ
               from it is reported in "format_errors" and is not identical
  decode       {field: "f32" | "f64"}: values that are IEEE-754 bit patterns (hex, comma-separated) are also
               shown as numbers in the report
Prints the first differing frame with every field that differs there (to stderr), then a JSON summary:
  identical, frames_a, frames_b, compared_fields, ignored, first_diff_frame, first_diff {field: [A, B]},
  differing_frames, fields {field: {"first", "count"}}, only_in_a / only_in_b {"first", "count"},
  unknown_fields (in one trace only), format_errors.
--show N also prints the next N differing frames. Exit 0 identical, 1 different, 2 bad input.
Python standard library only.
"""
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rwlib  # noqa: E402

PROG = 'compare_traces'


class TraceError(Exception):
    pass


def parse(path, header=None, frame_field='f'):
    """-> (header line, frame numbers in order, {frame: {field: value}}, field order)"""
    try:
        with open(path, encoding='utf-8', errors='replace') as f:
            text = f.read()
    except OSError as e:
        raise TraceError('%s: %s' % (path, e.strerror))
    lines = text.split('\n')
    head = lines[0].rstrip('\r') if lines else ''
    if not head:
        raise TraceError('%s: no header line' % path)
    if header is not None and head != header:
        raise TraceError('%s: first line is not "%s"' % (path, header))
    frames, rows, order = [], {}, []
    for n, line in enumerate(lines[1:], 2):
        line = line.rstrip('\r')
        if not line:
            continue
        row = {}
        for tok in line.split(' '):
            if '=' not in tok:
                raise TraceError('%s:%d: field without "=": %s' % (path, n, tok))
            k, v = tok.split('=', 1)
            if k in row:
                raise TraceError('%s:%d: field %s twice' % (path, n, k))
            row[k] = v
            if k not in order:
                order.append(k)
        if frame_field not in row:
            raise TraceError('%s:%d: no frame number (%s=)' % (path, n, frame_field))
        if not rwlib.INT_RE.match(row[frame_field]):
            raise TraceError('%s:%d: bad frame number %s' % (path, n, row[frame_field]))
        f = int(row[frame_field])
        if f in rows:
            raise TraceError('%s:%d: frame %d twice' % (path, n, f))
        if frames and f <= frames[-1]:
            raise TraceError('%s:%d: frame %d after frame %d' % (path, n, f, frames[-1]))
        frames.append(f)
        rows[f] = row
    return head, frames, rows, order


def float_repr(x):
    return repr(x)


def decode(kind, value):
    """Readable form of a value holding IEEE-754 bit patterns ("3f800000,bf000000")."""
    if kind not in ('f32', 'f64') or value in (None, '-'):
        return value
    out = []
    for x in value.split(','):
        try:
            if kind == 'f32':
                out.append(float_repr(struct.unpack('<f', struct.pack('<I', int(x, 16)))[0]))
            else:
                out.append(float_repr(struct.unpack('<d', struct.pack('<Q', int(x, 16)))[0]))
        except (ValueError, struct.error, OverflowError):
            return value
    return ','.join(out)


def format_errors(name, order, frame_field, fields):
    want = [frame_field] + list(fields)
    if order == want:
        return []
    for i in range(max(len(order), len(want))):
        got = order[i] if i < len(order) else '(none)'
        exp = want[i] if i < len(want) else '(none)'
        if got != exp:
            return ['%s: field %d is %s, the contract says %s' % (name, i + 1, got, exp)]
    return []


def compare(a_path, b_path, ignore=(), only=None, rw=None):
    rw = rw or {}
    header = rwlib.get(rw, 'trace.header')
    ff = rwlib.get(rw, 'trace.frame_field', 'f')
    ha, fa, ra, oa = parse(a_path, header, ff)
    hb, fb, rb, ob = parse(b_path, header if header is not None else ha, ff)
    order = oa + [k for k in ob if k not in oa]
    fields = [k for k in order if k != ff and k not in ignore and (only is None or k in only)]
    common = [f for f in fa if f in rb]
    only_a = [f for f in fa if f not in rb]
    only_b = [f for f in fb if f not in ra]
    per, diffs = {}, []
    for f in common:
        d = {}
        for k in fields:
            x, y = ra[f].get(k), rb[f].get(k)
            if x != y:
                d[k] = [x, y]
                p = per.setdefault(k, {'first': f, 'count': 0})
                p['count'] += 1
        if d:
            diffs.append((f, d))
    first = diffs[0][0] if diffs else None
    first_d = diffs[0][1] if diffs else {}
    ends = [x[0] for x in (only_a, only_b) if x]
    if ends and (first is None or min(ends) < first):
        first = min(ends)
        first_d = {ff: ['present' if first in ra else 'missing', 'present' if first in rb else 'missing']}
    errs = []
    want = rwlib.get(rw, 'trace.fields')
    if want:
        errs = format_errors('A', oa, ff, want) + format_errors('B', ob, ff, want)
    summary = {
        'a': a_path, 'b': b_path,
        'identical': not diffs and not only_a and not only_b and not errs,
        'frames_a': len(fa), 'frames_b': len(fb), 'compared_fields': fields, 'ignored': sorted(ignore),
        'first_diff_frame': first, 'first_diff': first_d, 'differing_frames': len(diffs), 'fields': per,
        'only_in_a': {'first': only_a[0], 'count': len(only_a)} if only_a else None,
        'only_in_b': {'first': only_b[0], 'count': len(only_b)} if only_b else None,
        'unknown_fields': sorted(set(oa) ^ set(ob)),
        'format_errors': errs,
    }
    return summary, diffs


def show_frame(f, d, dec, out):
    out.write('frame %d:\n' % f)
    for k, (x, y) in d.items():
        dx, dy = decode(dec.get(k), x), decode(dec.get(k), y)
        extra = '   (%s | %s)' % (dx, dy) if (dx, dy) != (x, y) else ''
        out.write('  %-7s A=%s  B=%s%s\n' % (k, x, y, extra))


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [
        ('--ignore', 'str', ''), ('--only', 'str', None), ('--json', 'str', None), ('--show', 'int', 0),
        ('--quiet', 'flag', False), ('--project', 'str', '.')], [('a', '1'), ('b', '1')])
    try:
        _, rw = rwlib.load_config(a['project'])
    except (OSError, ValueError):
        sys.stdout.write(rwlib.dumps({'error': 'decomp.json cannot be read or is not valid JSON'}) + '\n')
        return 2
    ignore = {x for x in a['ignore'].split(',') if x}
    only = {x for x in a['only'].split(',') if x} if a['only'] else None
    try:
        summary, diffs = compare(a['a'], a['b'], ignore, only, rw)
    except TraceError as e:
        sys.stdout.write(rwlib.dumps({'error': str(e)}) + '\n')
        return 2
    dec = rwlib.get(rw, 'trace.decode') or {}
    if not a['quiet']:
        err = sys.stderr
        for e in summary['format_errors']:
            err.write('format: %s\n' % e)
        if summary['identical']:
            err.write('identical: %d frames\n' % summary['frames_a'])
        elif summary['first_diff_frame'] is not None:
            f = summary['first_diff_frame']
            err.write('first difference at frame %d\n' % f)
            if diffs and diffs[0][0] == f:
                show_frame(f, diffs[0][1], dec, err)
            else:
                ab = list(summary['first_diff'].values())[0]
                err.write('  frame %d is %s in A, %s in B\n' % (f, ab[0], ab[1]))
            for f2, d in diffs[1:1 + a['show']]:
                show_frame(f2, d, dec, err)
            err.write('%d differing frame(s); fields: %s\n' % (summary['differing_frames'], ', '.join(
                '%s (from %d, %dx)' % (k, v['first'], v['count']) for k, v in summary['fields'].items())))
    js = rwlib.dumps(summary)
    if a['json']:
        with open(a['json'], 'w', encoding='utf-8') as f:
            f.write(js + '\n')
    sys.stdout.write(js + '\n')
    return 0 if summary['identical'] else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

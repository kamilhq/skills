#!/usr/bin/env python3
"""Account for every function annotation of the matched units: where it went, or why it is not there.

  python3 -I account.py --config CFG.json [--units DIR] [--tree DIR] [--names INDEX.json] [--map OUT.json]
                        [--project DIR]

Reads every `// FUNCTION:` and `// STUB:` annotation of the units (cppsplit.py; other kinds are counted
only) and puts each in exactly one category:
  thunk          a dynamic initializer / atexit thunk: symbol matching "thunk_symbols" (default ??__E/??__F),
                 name (from --names) matching "thunk_names", or an annotation on a variable definition; the
                 compiler makes it again from the global's definition
  in_tree        --tree given: a comment `// 0x<address>` (or `/* 0x<address>`) at the start of a line of a
                 .c/.cpp/.h file of the tree (the rewrite); the file is recorded
  planned        no --tree: a function of a game unit with a destination file (emit.py's placement rules)
  library_unit   in a unit of "library_units" (CRT, STL instances, library copies: not rewritten)
  stub           a // STUB (Ghidra fragment of another function, CRT object, code the rewrite replaces)
  dropped        listed in the config's "dropped" {address: reason}
  not_a_definition  the annotation is not on a function definition (e.g. an implicit member)
  unaccounted    none of the above: a function the rewrite lost (or one without a destination)
NONMATCHING tags are counted, and how many of them are in the tree. Addresses that the tree has but no
annotation has are listed as "tree_only" (functions written new, e.g. a rewritten WinMain).
--names reads the decomp skill's function index ({"functions": [{"address", "name"}]}) for names and the
thunk test. --map writes one row per annotation (address, name, unit, annotation, nonmatching, category,
file, reason). Prints a JSON summary. Exit 0, 1 when something is unaccounted, 2 on bad input.
Python standard library only. Port: ../js/cpp/account.mjs.
"""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))
import rwlib  # noqa: E402
import cppsplit as C  # noqa: E402

PROG = 'account'
ADDR_LINE = re.compile(r'^[ \t]*(?://|/\*)[ \t]*(0x[0-9a-fA-F]+)\b')


def scan_tree(root):
    """{address: first file (relative, '/') whose line starts with a comment holding it}."""
    found = {}
    for dp, dn, fn in os.walk(root):
        dn.sort()
        for f in sorted(fn):
            if not f.endswith(('.c', '.cpp', '.h', '.hpp', '.cc', '.cxx')):
                continue
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            for line in C.read_text(p).split('\n'):
                m = ADDR_LINE.match(line)
                if m:
                    found.setdefault(m.group(1).lower(), rel)
    return found


def load_names(path):
    with open(path, encoding='utf-8') as f:
        d = json.load(f)
    fns = d.get('functions', []) if isinstance(d, dict) else d
    return {str(x.get('address', '')).lower(): x.get('name', '') for x in fns if isinstance(x, dict)}


def account(cfg, units_dir, tree, names):
    module = cfg.get('module')
    libs = set(cfg.get('library_units', []))
    placer = C.Placer(cfg)
    thunk_sym = re.compile(cfg.get('thunk_symbols', r'^\?\?__[EF]'))
    thunk_name = re.compile(cfg.get('thunk_names', r'^(dynamic_initializer_for|dynamic_atexit_destructor_for)'))
    dropped = {k.lower(): v for k, v in cfg.get('dropped', {}).items()}
    pre = cfg.get('renames', {}).get('members', {})
    in_tree = scan_tree(tree) if tree else {}
    rows, other = [], {}
    for path in C.unit_files(units_dir, cfg):
        u = C.unit_id(cfg, path)
        _, items = C.load_unit(path, cfg, module, pre)
        for ns, it, anns, nonm, cls, fn in items:
            for kind, addr, sym in anns:
                if kind not in ('FUNCTION', 'STUB'):
                    other[kind] = other.get(kind, 0) + 1
                    continue
                name = names.get(addr) or (fn.qual if fn is not None else (sym or ''))
                cat, f, reason = None, None, None
                if (sym and thunk_sym.search(sym)) or thunk_name.search(names.get(addr, '')) or cls == 'vardef':
                    cat = 'thunk'
                elif tree and addr in in_tree:
                    cat, f = 'in_tree', in_tree[addr]
                elif u in libs:
                    cat = 'library_unit'
                elif kind == 'STUB':
                    cat = 'stub'
                elif addr in dropped:
                    cat, reason = 'dropped', dropped[addr]
                elif cls != 'funcdef':
                    cat = 'not_a_definition'
                elif tree:
                    cat, reason = 'unaccounted', 'not in the tree'
                else:
                    f = placer.dest(u, fn, addr)
                    cat = 'planned' if f else 'unaccounted'
                    reason = None if f else 'no destination'
                rows.append({'addr': addr, 'name': name, 'unit': u, 'annotation': kind, 'nonmatching': nonm,
                             'category': cat, 'file': f, 'reason': reason})
    rows.sort(key=lambda r: (int(r['addr'], 16), r['unit']))
    cats, by_kind, files = {}, {}, {}
    for r in rows:
        cats[r['category']] = cats.get(r['category'], 0) + 1
        k = '%s %s' % (r['annotation'], r['category'])
        by_kind[k] = by_kind.get(k, 0) + 1
        if r['file']:
            files[r['file']] = files.get(r['file'], 0) + 1
    annotated = {r['addr'] for r in rows}
    tree_only = sorted((a for a in in_tree if a not in annotated), key=lambda x: int(x, 16))
    un = [r for r in rows if r['category'] == 'unaccounted']
    summary = {
        'annotations': len(rows),
        'functions': sum(1 for r in rows if r['annotation'] == 'FUNCTION'),
        'stubs': sum(1 for r in rows if r['annotation'] == 'STUB'),
        'other_annotations': dict(sorted(other.items())),
        'nonmatching': sum(1 for r in rows if r['nonmatching']),
        'nonmatching_placed': sum(1 for r in rows if r['nonmatching'] and r['category'] in ('in_tree', 'planned')),
        'categories': dict(sorted(cats.items())),
        'by_annotation': dict(sorted(by_kind.items())),
        'files': dict(sorted(files.items())),
        'tree_only': {'count': len(tree_only), 'addresses': tree_only[:50]},
        'unaccounted': {'count': len(un), 'first': ['%s %s (%s, %s)' % (r['addr'], r['name'], r['unit'], r['reason'])
                                                    for r in un[:50]]},
    }
    return summary, rows


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [
        ('--config', 'str', rwlib.REQUIRED), ('--units', 'str', None), ('--tree', 'str', None),
        ('--names', 'str', None), ('--map', 'str', None), ('--project', 'str', '.')])
    try:
        cfg = C.load_config(a['config'])
    except (OSError, ValueError):
        sys.stdout.write(rwlib.dumps({'error': 'config cannot be read: %s' % a['config']}) + '\n')
        return 2
    units = a['units'] or (os.path.join(a['project'], cfg['units']) if cfg.get('units') else None)
    if not units or not os.path.isdir(units):
        sys.stdout.write(rwlib.dumps({'error': 'no units folder (--units or "units" in the config)'}) + '\n')
        return 2
    if a['tree'] and not os.path.isdir(a['tree']):
        sys.stdout.write(rwlib.dumps({'error': 'no such tree: %s' % a['tree']}) + '\n')
        return 2
    names = {}
    if a['names']:
        try:
            names = load_names(a['names'])
        except (OSError, ValueError):
            sys.stdout.write(rwlib.dumps({'error': 'names index cannot be read: %s' % a['names']}) + '\n')
            return 2
    summary, rows = account(cfg, units, a['tree'], names)
    if a['map']:
        C.write_text(a['map'], rwlib.dumps(rows) + '\n')
    sys.stdout.write(rwlib.dumps(summary) + '\n')
    return 1 if summary['unaccounted']['count'] else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

#!/usr/bin/env python3
"""The release gate of a clean-room rewrite (references/cleanroom.md): may this source tree be published?

  python3 -I release_check.py [TREE] [--project DIR] [--json OUT] [--quiet]

TREE (default: decomp.json "rewrite.cleanroom.tree", else rewrite/clean) is the source that would be published.
Files matching "tree_exclude" (default third_party/, vendor/, target/, build/, .git/) are not checked. Settings
come from decomp.json "rewrite.cleanroom" (keys and defaults in references/cleanroom.md). Checks:
  log         the clean-room log verifies (hash chain intact, an init and at least one pack entry)
  assets      no file equals (SHA-256) a file of the game, extracted or decoded folders ("assets")
  markers     no address annotations (// FUNCTION: 0x..., // 0x<address> lines), stub!(0x..), and no Ghidra
              names (FUN_, DAT_, undefined4, iVar1, param_1, in_EAX ...) anywhere in a source file
  tables      no embedded numeric table of >= table_items numbers or string table of >= string_items strings
              (game data is read from the user's own files at run time)
  strings     string literals of >= min_string characters shared with the reference: <= string_bytes in total
  names       function definitions named like a name the analysts gave the original ("names" files): <= names_pct %
              (applies from names_min definitions on)
  similarity  fingerprints of the tree found in the reference code (the decompilation, raw and named, and any
              other folder listed in "reference"): code (token 12-grams, identifiers abstracted, with at least two
              significant numbers or strings, winnowed) <= code_pct %, constant sequences (5-grams of numbers
              >= 32 or non-trivial floats) <= const_pct %, and no file with >= file_min fingerprints above
              file_pct %
  notices     a LICENSE (or COPYING) and a README at the top of the tree; with libraries in
              "rewrite.libraries", a third-party notice (THIRD_PARTY*, LICENSES*, NOTICE*)
An allow file ("allow", default cleanroom/allow.json: {"findings": [{"check", "file", "line"?, "reason"}]})
accepts single findings with a written reason; they are listed under "allowed". Prints findings to stderr
(unless --quiet) and a JSON summary: passed, tree, files, checks {name: {passed, findings_total, findings (the
first 200), ...}}, allowed, manual (what no script can check).
Exit 0 passed, 1 failed, 2 bad input. Python standard library only.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rwlib  # noqa: E402
import cleanlib as C  # noqa: E402

PROG = 'release_check'
MANUAL = [
    'the name and the README do not suggest the rewrite is the original or endorsed by its owner; '
    'no logos or artwork of the original',
    'the README says that the original game is required and not included',
    'the licence of the rewrite covers only the rewrite\'s own code',
    'no game data, saves, screenshots or recordings of the original in the repository history either',
    'the clean-room log was kept for every implementer and the specs went through cleanroom.py lint',
]
MAX_FINDINGS = 200
CHECKS = ('log', 'assets', 'markers', 'tables', 'strings', 'names', 'similarity', 'notices')


class InputError(Exception):
    pass


def load_allow(project, path):
    p = os.path.join(project, path)
    if not os.path.exists(p):
        return []
    try:
        with open(p, encoding='utf-8') as f:
            d = json.load(f)
    except (OSError, ValueError):
        raise InputError('%s: not a readable JSON file' % path)
    items = d.get('findings') if isinstance(d, dict) else None
    if not isinstance(items, list):
        raise InputError('%s: expected {"findings": [...]}' % path)
    for i, a in enumerate(items):
        if not isinstance(a, dict) or not a.get('check') or not a.get('file') or not str(a.get('reason') or '').strip():
            raise InputError('%s: finding %d needs "check", "file" and a non-empty "reason"' % (path, i))
    return items


def load_names(project, files):
    """Normalized phase-5 function names (last :: part, lower case, no underscores, >= 6 characters)."""
    out = set()
    for f in files:
        p = os.path.join(project, f)
        if not os.path.exists(p):
            continue
        vals = []
        if f.endswith('.json'):
            try:
                with open(p, encoding='utf-8') as fh:
                    d = json.load(fh)
            except (OSError, ValueError):
                raise InputError('%s: not a readable JSON file' % f)
            items = d.values() if isinstance(d, dict) else (d if isinstance(d, list) else [])
            for v in items:
                if isinstance(v, dict):
                    v = v.get('name')
                if isinstance(v, str):
                    vals.append(v)
        else:
            for line in C.read_text(p).split('\n'):
                cols = line.rstrip('\r').split('\t')
                if len(cols) >= 2:
                    vals.append(cols[1])
        for v in vals:
            if v.startswith(('FUN_', 'thunk_', 'FID_conflict', 'LAB_', 'DAT_', 'switchD_')):
                continue
            n = normalize_name(v.split('::')[-1])
            if len(n) >= 6:
                out.add(n)
    return out


def normalize_name(n):
    return n.replace('_', '').lower()


def function_defs(toks, rust):
    """[(name, line)] of function definitions in a token list (comments already dropped)."""
    out = []
    n = len(toks)
    for i, (kind, t, ln) in enumerate(toks):
        if rust:
            if kind == 'ident' and t == 'fn' and i + 1 < n and toks[i + 1][0] == 'ident':
                out.append((toks[i + 1][1], toks[i + 1][2]))
            continue
        if kind != 'ident' or t in C.NOT_FN or i + 1 >= n or toks[i + 1][1] != '(':
            continue
        if i and toks[i - 1][1] in ('.', '->', '=', 'new', 'return', 'else'):
            continue
        depth, j = 0, i + 1
        while j < n:
            if toks[j][1] == '(':
                depth += 1
            elif toks[j][1] == ')':
                depth -= 1
                if depth == 0:
                    break
            elif toks[j][1] in (';', '{', '}') and depth > 0:
                j = n
                break
            j += 1
        j += 1
        while j < n and toks[j][0] == 'ident' and toks[j][1] in C.FN_SKIP:
            j += 1
        if j < n and toks[j][1] == '{':
            out.append((t, ln))
    return out


def tables(toks, th):
    """Runs of numeric (or string) literal list items -> [(kind, count, line)]."""
    out = []
    num_ok = {',', '-', '{', '}', '[', ']', '(', ')'}
    str_ok = {',', '{', '}', '[', ']', '&'}
    for kind_name, item, ok, limit in (('numbers', 'number', num_ok, th['table_items']),
                                        ('strings', 'string', str_ok, th['string_items'])):
        count, start = 0, None
        for kind, t, ln in toks + [('end', '', 0)]:
            if kind == item:
                if start is None:
                    start = ln
                count += 1
            elif kind == 'punct' and t in ok:
                continue
            else:
                if count >= limit:
                    out.append((kind_name, count, start))
                count, start = 0, None
    return out


def pct(a, b):
    return a * 100 // b if b else 0


def main(argv):
    a = rwlib.parse_args(PROG, __doc__, argv, [('--project', 'str', '.'), ('--json', 'str', None),
                                                ('--quiet', 'flag', False)], [('tree', '?')])
    project = os.path.abspath(a['project'])
    try:
        s = C.settings(project)
        th = s['thresholds']
        allow = load_allow(project, s['allow'])
        names = load_names(project, s['names'])
    except (InputError, ValueError) as e:
        sys.stderr.write('%s: error: %s\n' % (PROG, e))
        return 2
    tree = a['tree'] if a['tree'] is not None else s['tree']
    tree_rel = C.rel(project, os.path.join(project, tree) if not os.path.isabs(tree) else tree)
    if tree_rel is None or not os.path.isdir(os.path.join(project, tree_rel)):
        sys.stderr.write('%s: error: %s: not a folder inside the project\n' % (PROG, tree))
        return 2
    hit = C.glob_match(tree_rel, s['forbidden'])
    files = C.walk(project, tree_rel, [tree_rel + '/' + x for x in s['tree_exclude']])
    checks = {c: {'passed': True, 'findings': []} for c in CHECKS}

    def find(check, file, line, detail):
        checks[check]['findings'].append({'file': file, 'line': line, 'detail': detail})

    if hit:
        find('log', tree_rel, 0, 'the tree is inside a forbidden area (%s): it is not a clean-room tree' % hit)

    # log
    v = C.verify_log(os.path.join(project, s['log']))
    checks['log'].update({'entries': v['entries'], 'events': v['events'], 'waves': v['waves']})
    if s['require_log']:
        for p in v['problems']:
            find('log', s['log'], 0, p)
        if v['entries'] and not v['events'].get('pack'):
            find('log', s['log'], 0, 'no pack entry: no implementer workspace was recorded')

    # assets
    sizes = {}
    for f in files:
        sizes.setdefault(os.path.getsize(os.path.join(project, f)), []).append(f)
    asset_files = 0
    tree_hash = {}
    for d in s['assets']:
        if not os.path.exists(os.path.join(project, d)):
            continue
        for g in C.walk(project, d):
            asset_files += 1
            size = os.path.getsize(os.path.join(project, g))
            if size == 0 or size not in sizes:
                continue
            gh = rwlib.sha256_file(os.path.join(project, g))
            for f in sizes[size]:
                if f not in tree_hash:
                    tree_hash[f] = rwlib.sha256_file(os.path.join(project, f))
                if tree_hash[f] == gh:
                    find('assets', f, 0, 'identical to %s' % g)
    checks['assets']['asset_files'] = asset_files

    # source checks
    corpus = C.Corpus(project, s['reference'], s['reference_exclude'])
    checks['similarity'].update({'reference_files': len(corpus.files), 'reference_missing': corpus.missing})
    tot = {'code': [0, 0], 'consts': [0, 0]}
    per_file = []
    shared_strings = {}
    defs_total, defs_shared, shared_examples = 0, 0, []
    for f in files:
        p = os.path.join(project, f)
        if not f.lower().endswith(C.CODE_EXTS) or not C.is_text(p):
            continue
        text = C.read_text(p)
        for n, line in enumerate(text.split('\n'), 1):
            m = C.GHIDRA_RE.search(line)
            if m:
                find('markers', f, n, 'Ghidra name %s' % m.group(0))
            m = C.STUB_RE.search(line)
            if m:
                find('markers', f, n, 'address stub %s' % m.group(0))
        fp = C.file_fingerprints(text)
        for kind, t, ln in C.tokens(text):
            if kind == 'comment':
                for k, cl in enumerate(t.split('\n')):
                    cl = cl.strip(C.WS)
                    if C.ADDR_COMMENT_RE.search(cl):
                        find('markers', f, ln + k, 'address annotation: %s' % cl[:80])
        for kind, count, ln in tables(fp['toks'], th):
            find('tables', f, ln, 'embedded table of %d %s' % (count, kind))
        for lit, ln in fp['strings'].items():
            sv = C.string_value(lit)
            if len(sv) >= th['min_string'] and sv in corpus.strings and sv not in shared_strings:
                shared_strings[sv] = (f, ln)
        fc = [sum(1 for _, h in fp['code'] if h in corpus.code), len(fp['code'])]
        fk = [sum(1 for _, h in fp['consts'] if h in corpus.consts), len(fp['consts'])]
        tot['code'][0] += fc[0]
        tot['code'][1] += fc[1]
        tot['consts'][0] += fk[0]
        tot['consts'][1] += fk[1]
        n_fp = fc[1] + fk[1]
        if n_fp:
            per_file.append({'file': f, 'fingerprints': n_fp, 'shared': fc[0] + fk[0], 'pct': pct(fc[0] + fk[0], n_fp)})
        for name, ln in function_defs(fp['toks'], f.endswith('.rs')):
            nn = normalize_name(name)
            if len(nn) < 6:
                continue
            defs_total += 1
            if nn in names:
                defs_shared += 1
                if len(shared_examples) < 20:
                    shared_examples.append('%s:%d %s' % (f, ln, name))

    sb = sum(len(x.encode('utf-8')) for x in shared_strings)
    checks['strings'].update({'shared_strings': len(shared_strings), 'shared_bytes': sb})
    if sb > th['string_bytes']:
        for sv, (f, ln) in sorted(shared_strings.items(), key=lambda x: (x[1][0], x[1][1], x[0]))[:50]:
            find('strings', f, ln, 'string shared with the reference: "%s"' % sv[:60])
        find('strings', tree_rel, 0, '%d bytes of string literals shared with the reference (max %d)' %
             (sb, th['string_bytes']))

    checks['names'].update({'definitions': defs_total, 'shared': defs_shared, 'pct': pct(defs_shared, defs_total),
                            'examples': shared_examples, 'names_known': len(names)})
    if defs_total >= th['names_min'] and defs_shared * 100 > th['names_pct'] * defs_total:
        find('names', tree_rel, 0, '%d of %d function definitions (%d%%) carry a name of the original (max %d%%)' %
             (defs_shared, defs_total, pct(defs_shared, defs_total), th['names_pct']))

    per_file.sort(key=lambda x: (-x['pct'], x['file']))
    checks['similarity'].update({
        'code': {'fingerprints': tot['code'][1], 'shared': tot['code'][0], 'pct': pct(*tot['code'])},
        'consts': {'fingerprints': tot['consts'][1], 'shared': tot['consts'][0], 'pct': pct(*tot['consts'])},
        'top_files': per_file[:10]})
    if not corpus.files:
        find('similarity', tree_rel, 0, 'no reference code found (%s): nothing to compare against' %
             ', '.join(s['reference']))
    for k, lim in (('code', th['code_pct']), ('consts', th['const_pct'])):
        sh, n = tot[k]
        if sh * 100 > lim * n:
            find('similarity', tree_rel, 0, '%s fingerprints: %d of %d (%d%%) found in the reference (max %d%%)' %
                 (k, sh, n, pct(sh, n), lim))
    for x in per_file:
        if x['fingerprints'] >= th['file_min'] and x['shared'] * 100 > th['file_pct'] * x['fingerprints']:
            find('similarity', x['file'], 0, '%d of %d fingerprints (%d%%) found in the reference (max %d%%)' %
                 (x['shared'], x['fingerprints'], x['pct'], th['file_pct']))

    # notices
    top = sorted(os.listdir(os.path.join(project, tree_rel)))
    low = [t.lower() for t in top]
    if not any(t.startswith(('license', 'licence', 'copying', 'unlicense')) for t in low):
        find('notices', tree_rel, 0, 'no LICENSE or COPYING file at the top of the tree')
    if not any(t.startswith('readme') for t in low):
        find('notices', tree_rel, 0, 'no README at the top of the tree')
    libs = s['libraries']
    nlibs = 0
    if libs and os.path.exists(os.path.join(project, libs)):
        try:
            with open(os.path.join(project, libs), encoding='utf-8') as fh:
                ld = json.load(fh)
            nlibs = len(ld.get('libraries') or []) if isinstance(ld, dict) else 0
        except (OSError, ValueError):
            nlibs = 0
    checks['notices']['libraries'] = nlibs
    if nlibs and not any(t.startswith(('third_party', 'third-party', 'thirdparty', 'licenses', 'notice'))
                         for t in low):
        find('notices', tree_rel, 0, '%d libraries in %s but no third-party notice (THIRD_PARTY*, LICENSES*, '
             'NOTICE*)' % (nlibs, libs))

    # allow-list
    allowed = []
    for c in CHECKS:
        keep = []
        for fnd in checks[c]['findings']:
            ok = None
            for al in allow:
                if al['check'] == c and al['file'] == fnd['file'] and al.get('line', fnd['line']) == fnd['line']:
                    ok = al
                    break
            if ok:
                allowed.append({'check': c, 'file': fnd['file'], 'line': fnd['line'], 'detail': fnd['detail'],
                                'reason': ok['reason']})
            else:
                keep.append(fnd)
        checks[c]['passed'] = not keep
        checks[c]['findings_total'] = len(keep)
        checks[c]['findings'] = keep[:MAX_FINDINGS]
    passed = all(checks[c]['passed'] for c in CHECKS)
    if not a['quiet']:
        for c in CHECKS:
            if checks[c]['findings_total'] > MAX_FINDINGS:
                sys.stderr.write('%s: %d findings, the first %d shown\n' % (c, checks[c]['findings_total'], MAX_FINDINGS))
            for fnd in checks[c]['findings']:
                sys.stderr.write('%s: %s%s: %s\n' % (c, fnd['file'], ':%d' % fnd['line'] if fnd['line'] else '',
                                                     fnd['detail']))
        failed = [c for c in CHECKS if not checks[c]['passed']]
        sys.stderr.write('%s: %s\n' % (PROG, 'PASSED' if passed else 'FAILED (%s)' % ', '.join(failed)))
    summary = {'passed': passed, 'tree': tree_rel, 'files': len(files), 'checks': checks, 'allowed': allowed,
               'manual': MANUAL}
    text = rwlib.dumps(summary)
    if a['json']:
        with open(a['json'], 'w', encoding='utf-8') as f:
            f.write(text + '\n')
    sys.stdout.write(text + '\n')
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

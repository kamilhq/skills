#!/usr/bin/env python3
"""Step 2 census (and archive extraction): what a game tree contains, and which files are disguised.

  inventory.py <game_dir> [--json out.json]
  inventory.py <game_dir> --extract <out_dir> [--only GLOB ...] [--force] [--json out.json]

Census: for every file, extension, size, first 16 bytes, container/format detected by magic, and whether the
file is a known format hidden under a whole-file single-byte XOR (key reported). ZIP-based archives (even
under a non-.zip extension, even XORed) are opened and their members counted per archive and by extension;
"game archives" (not .zip/.hashdb and not GOG/installer files) are totalled separately from other zips so the
member count can be checked against the extracted tree. Files no magic matched are listed as UNCLASSIFIED:
the phase-2 gate is that every one of them is explained.

--extract: unpack every ZIP-based archive (after removing its XOR) into
  <out_dir>/<archive path relative to game_dir, without extension>/      e.g. extracted/DATA/Textos/
(if two archives would share that folder, the extension is kept: DATA/Textos_pak/). --only GLOB (repeatable,
fnmatch on the relative path, case-insensitive) limits which archives, e.g. --only 'DATA/*.pak'. Every member's
CRC-32 is checked while reading; names that are absolute, contain '..' or a drive letter, or that collide with
another member when case is ignored are refused and reported, never written. An existing non-empty target
folder is skipped unless --force. Writes <out_dir>/extract_report.json. Exit 0 ok, 1 any archive or member
failed, 2 bad arguments.
Stdlib only; run with -I.
"""
import collections, fnmatch, io, json, os, shutil, sys, zipfile

MAGICS = [
    (b'PK\x03\x04', 'zip'), (b'PK\x05\x06', 'zip(empty)'), (b'Rar!', 'rar'), (b'7z\xbc\xaf', '7z'),
    (b'MZ', 'pe/mz'), (b'RIFF', 'riff'), (b'OggS', 'ogg'), (b'BIK', 'bink'), (b'KB2', 'bink2'),
    (b'SMK2', 'smacker'), (b'DDS ', 'dds'), (b'BM', 'bmp'), (b'\x89PNG', 'png'), (b'\xff\xd8\xff', 'jpeg'),
    (b'GIF8', 'gif'), (b'ID3', 'mp3'), (b'\xff\xfb', 'mp3'), (b'%PDF', 'pdf'), (b'\x1f\x8b', 'gzip'),
    (b'BZh', 'bzip2'), (b'\x00\x00\x01\x00', 'ico'), (b'\xef\xbb\xbf', 'utf8-bom text'),
    (b'\xff\xfe', 'utf16le-bom text'), (b'MThd', 'midi'), (b'FORM', 'iff'), (b'XPDS', '?'),
]
NOT_GAME_ARCHIVE = ('.zip', '.hashdb')          # GOG launcher/web caches, not game data


def detect(head):
    for m, name in MAGICS:
        if head.startswith(m):
            return name
    if head and all(32 <= c < 127 or c in (9, 10, 13) for c in head[:16]):
        return 'text?'
    return None


def xor_detect(head):
    """Return (key, format) if the first bytes are a known magic XORed with one constant byte."""
    if len(head) < 4:
        return None
    for m, name in MAGICS:
        if len(m) < 3:
            continue
        k = head[0] ^ m[0]
        if k and all(head[i] ^ k == m[i] for i in range(len(m))):
            return k, name
    return None


def open_zip(path, xor):
    if not xor:
        return zipfile.ZipFile(path)
    data = open(path, 'rb').read().translate(bytes(i ^ xor for i in range(256)))
    return zipfile.ZipFile(io.BytesIO(data))


def census(root):
    rows, archives = [], []
    for r, ds, fs in os.walk(root):
        ds.sort()
        for f in sorted(fs):
            p = os.path.join(r, f)
            with open(p, 'rb') as fh:
                head = fh.read(16)
            fmt, xor = detect(head), None
            if not fmt:
                x = xor_detect(head)
                if x:
                    xor, fmt = x
            ext = os.path.splitext(f)[1].lower() or '(none)'
            rel = os.path.relpath(p, root).replace(os.sep, '/')
            rows.append(dict(path=rel, ext=ext, size=os.path.getsize(p), head=head.hex(' '), format=fmt, xor_key=xor))
            if fmt == 'zip':
                a = dict(path=rel, xor_key=xor, game=ext not in NOT_GAME_ARCHIVE and not f.lower().startswith('goggame'),
                         members=0, by_ext={}, error=None)
                try:
                    with open_zip(p, xor) as z:
                        c = collections.Counter(os.path.splitext(i.filename)[1].lower() or '(none)'
                                                for i in z.infolist() if not i.is_dir())
                    a['members'], a['by_ext'] = sum(c.values()), dict(c.most_common())
                except (zipfile.BadZipFile, OSError) as e:
                    a['error'] = str(e)
                archives.append(a)
    return rows, archives


def safe_name(n):
    n = n.replace('\\', '/')
    parts = [x for x in n.split('/') if x not in ('', '.')]
    if n.startswith('/') or ':' in n or any(x == '..' for x in parts) or not parts:
        return None
    return '/'.join(parts)


def extract(root, archives, out, only, force):
    targets, report, failed = {}, [], False
    for a in archives:
        if only and not any(fnmatch.fnmatch(a['path'].lower(), g.lower()) for g in only):
            continue
        if a['error']:
            report.append(dict(archive=a['path'], xor_key=a['xor_key'], dest=None, members=0, bytes=0, refused=[],
                               errors=['unreadable archive: ' + a['error']]))
            print(f'{a["path"]:40} UNREADABLE: {a["error"]}')
            failed = True
            continue
        targets.setdefault(os.path.splitext(a['path'])[0].lower(), []).append(a)
    for key, group in sorted(targets.items()):
        for a in group:
            stem, ext = os.path.splitext(a['path'])
            dest = os.path.join(out, stem + ('_' + ext[1:] if len(group) > 1 else ''))
            rec = dict(archive=a['path'], xor_key=a['xor_key'], dest=os.path.relpath(dest, out), members=0, bytes=0,
                       refused=[], errors=[])
            report.append(rec)
            if os.path.isdir(dest) and os.listdir(dest):
                if not force:
                    rec['errors'].append('destination exists and is not empty (use --force)')
                    print(f'{a["path"]:40} -> {rec["dest"]:32} SKIPPED: destination exists and is not empty (--force)')
                    failed = True
                    continue
                shutil.rmtree(dest)
            seen = {}
            with open_zip(os.path.join(root, a['path']), a['xor_key']) as z:
                for i in z.infolist():
                    n = safe_name(i.filename)
                    if n is None:
                        rec['refused'].append(f'{i.filename}: unsafe path')
                        continue
                    if n.lower() in seen and not i.is_dir():
                        rec['refused'].append(f'{i.filename}: collides with {seen[n.lower()]} when case is ignored')
                        continue
                    target = os.path.join(dest, *n.split('/'))
                    if i.is_dir():
                        os.makedirs(target, exist_ok=True)
                        continue
                    seen[n.lower()] = i.filename
                    try:
                        data = z.read(i)                 # raises BadZipFile on a CRC mismatch
                    except (zipfile.BadZipFile, NotImplementedError, RuntimeError, OSError) as e:
                        rec['errors'].append(f'{i.filename}: {e}')
                        continue
                    os.makedirs(os.path.dirname(target), exist_ok=True)
                    with open(target, 'wb') as fh:
                        fh.write(data)
                    rec['members'] += 1
                    rec['bytes'] += len(data)
            failed |= bool(rec['refused'] or rec['errors'])
            print(f'{a["path"]:40} -> {rec["dest"]:32} {rec["members"]:6} members {rec["bytes"] / 1e6:9.2f} MB'
                  + (f'  REFUSED {len(rec["refused"])}' if rec['refused'] else '')
                  + (f'  ERRORS {len(rec["errors"])}' if rec['errors'] else ''))
    os.makedirs(out, exist_ok=True)
    json.dump(report, open(os.path.join(out, 'extract_report.json'), 'w'), indent=1)
    print(f'extracted {sum(r["members"] for r in report)} members from {len(report)} archives into {out}'
          + ('  (FAILURES: see extract_report.json)' if failed else ''))
    return 1 if failed else 0


def take(argv, name, multi=False):
    vals = []
    while name in argv:
        i = argv.index(name)
        if i + 1 >= len(argv):
            sys.exit(f'{name} needs a value')
        vals.append(argv[i + 1]); del argv[i:i + 2]
    return vals if multi else (vals[-1] if vals else None)


def main():
    argv = sys.argv[1:]
    force = '--force' in argv
    argv = [a for a in argv if a != '--force']
    jpath, out, only = take(argv, '--json'), take(argv, '--extract'), take(argv, '--only', multi=True)
    if len(argv) != 1 or not os.path.isdir(argv[0]):
        print(__doc__, file=sys.stderr)
        return 2
    root = argv[0]
    rows, archives = census(root)
    by = collections.defaultdict(list)
    for x in rows:
        by[x['ext']].append(x)
    print(f'{"ext":10} {"files":>6} {"MB":>9}  format (xor)        example')
    for ext, xs in sorted(by.items(), key=lambda kv: -sum(x['size'] for x in kv[1])):
        fmts = collections.Counter(f"{x['format']}{'^%02x' % x['xor_key'] if x['xor_key'] else ''}" for x in xs)
        print(f'{ext:10} {len(xs):6} {sum(x["size"] for x in xs) / 1e6:9.2f}  '
              f'{",".join(f"{k}:{v}" for k, v in fmts.most_common(3)):20} {xs[0]["path"]}')
    members = collections.Counter()
    if archives:
        print('\nzip-based archives (members per archive):')
        for a in archives:
            top = ', '.join(f'{e}:{c}' for e, c in list(a['by_ext'].items())[:4])
            print(f'  {a["path"]:40} {"xor^%02x" % a["xor_key"] if a["xor_key"] else "":7} {a["members"]:6}  '
                  f'{"" if a["game"] else "(not game data) "}{a["error"] or top}')
            if a['game']:
                members.update(a['by_ext'])
        g = [a for a in archives if a['game']]
        print(f'  game archives: {len(g)}, members: {sum(a["members"] for a in g)}; other zips: '
              f'{len(archives) - len(g)}, members: {sum(a["members"] for a in archives if not a["game"])}')
        print('\nmembers of game archives by extension:')
        for e, c in members.most_common():
            print(f'  {e:10} {c}')
    unk = [x for x in rows if x['format'] is None]
    print(f'\nUNCLASSIFIED (no known magic, not XORed): {len(unk)} file(s)')
    for x in unk[:20]:
        print(f'  {x["path"]}  head={x["head"]}')
    if jpath:
        json.dump({'files': rows, 'archives': archives, 'archive_members': members,
                   'unclassified': [x['path'] for x in unk]}, open(jpath, 'w'), indent=1)
    if out:
        print()
        return extract(root, archives, out, only, force)
    return 0


if __name__ == '__main__':
    sys.exit(main())

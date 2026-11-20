#!/usr/bin/env python3
"""protection_check.py <game_dir_or_file> [...] [--json OUT]

Step 1 gate: look for copy protection (DRM) and executable packers in a game before any analysis. Working
around copy protection is unlawful in most countries even for a game you own (US DMCA 17 U.S.C. 1201, EU
InfoSoc Directive art. 6), independently of copyright in the code, so the pipeline stops when it finds one.

Every file under each argument is checked (folders recursively, in sorted order):
  - file names of known protection components (SafeDisc, StarForce, LaserLock, CD-Cops), any folder;
  - in every PE file (MZ + PE signature): section names of known protections and packers (SafeDisc,
    SecuROM, StarForce, the Steam DRM wrapper, UPX, ASPack, MPRESS, PECompact, Petite, NsPack, Themida /
    WinLicense, VMProtect, Enigma), imported DLLs of known protections, the SafeDisc signature string;
  - entry-point heuristics for unknown packers: entry point outside every section, in a writable code
    section, or in a section whose raw data has entropy >= 7.2 bits per byte (packed or encrypted code).
Steamworks (steam_api.dll) and GOG Galaxy imports are reported as "info": they are platform APIs, not DRM.

Prints one JSON summary: scanned_files, pe_files, verdict ("clean", "protected" or "review"), findings
[{file, kind, product, evidence}] with kind "drm", "packer", "warning" (heuristic) or "info".
"protected" = a drm or packer finding: stop and tell the user (a GOG release of the same game is usually
DRM-free). "review" = only heuristic warnings: show them to the user and continue only with their decision.
Exit 0 clean (info findings allowed), 1 protected or review, 2 bad arguments or nothing to scan.
Stdlib only; run with -I.
"""
import json
import math
import os
import struct
import sys

# known protection component file names (lower case)
FILE_NAMES = {
    '00000001.tmp': ('drm', 'SafeDisc'), 'clcd16.dll': ('drm', 'SafeDisc'), 'clcd32.dll': ('drm', 'SafeDisc'),
    'clokspl.exe': ('drm', 'SafeDisc'), 'dplayerx.dll': ('drm', 'SafeDisc'), 'drvmgt.dll': ('drm', 'SafeDisc'),
    'secdrv.sys': ('drm', 'SafeDisc'), 'protect.dll': ('drm', 'StarForce'), 'protect.exe': ('drm', 'StarForce'),
    'laserlok.in': ('drm', 'LaserLock'), 'laserlok.o10': ('drm', 'LaserLock'), 'laserlok.o11': ('drm', 'LaserLock'),
    'cdcops.dll': ('drm', 'CD-Cops'),
}
# imported DLLs (lower case)
IMPORTS = dict(FILE_NAMES)
IMPORTS.update({'steam_api.dll': ('info', 'Steamworks API'), 'galaxy.dll': ('info', 'GOG Galaxy API')})
# section names (lower case, NULs stripped)
SECTIONS = {
    'stxt371': ('drm', 'SafeDisc'), 'stxt774': ('drm', 'SafeDisc'), '.stxt371': ('drm', 'SafeDisc'),
    '.stxt774': ('drm', 'SafeDisc'), '.securom': ('drm', 'SecuROM'), '.cms_t': ('drm', 'SecuROM'),
    '.cms_d': ('drm', 'SecuROM'), '.sforce': ('drm', 'StarForce'), '.sforce3': ('drm', 'StarForce'),
    '.bind': ('drm', 'Steam DRM wrapper'),
    'upx0': ('packer', 'UPX'), 'upx1': ('packer', 'UPX'), 'upx2': ('packer', 'UPX'), '.aspack': ('packer', 'ASPack'),
    '.adata': ('packer', 'ASPack'), '.mpress1': ('packer', 'MPRESS'), '.mpress2': ('packer', 'MPRESS'),
    'pec2': ('packer', 'PECompact'), 'pecompact2': ('packer', 'PECompact'), '.petite': ('packer', 'Petite'),
    '.nsp0': ('packer', 'NsPack'), '.nsp1': ('packer', 'NsPack'), '.themida': ('packer', 'Themida/WinLicense'),
    '.winlice': ('packer', 'Themida/WinLicense'), '.vmp0': ('packer', 'VMProtect'), '.vmp1': ('packer', 'VMProtect'),
    '.enigma1': ('packer', 'Enigma'), '.enigma2': ('packer', 'Enigma'),
}
STRINGS = [(b'BoG_ *90.0&!!  Yy>', 'drm', 'SafeDisc')]
ENTROPY_LIMIT = 720          # hundredths of a bit per byte
SCN_EXEC, SCN_WRITE = 0x20000000, 0x80000000

USAGE = 'usage: protection_check.py <game_dir_or_file> [...] [--json OUT]\n'


def entropy100(b):
    """Shannon entropy of b in hundredths of a bit per byte (floored)."""
    if not b:
        return 0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return int(e * 100)


def parse_pe(d):
    """-> None (not a PE) or {'sections': [(name, va, vsize, rawptr, rawsize, chars)], 'entry', 'imports'}"""
    if len(d) < 0x40 or d[:2] != b'MZ':
        return None
    pe = struct.unpack_from('<I', d, 0x3c)[0]
    if pe + 24 > len(d) or d[pe:pe + 4] != b'PE\0\0':
        return None
    nsec, = struct.unpack_from('<H', d, pe + 6)
    optsize, = struct.unpack_from('<H', d, pe + 20)
    opt = pe + 24
    if opt + 2 > len(d):
        return None
    magic, = struct.unpack_from('<H', d, opt)
    entry = struct.unpack_from('<I', d, opt + 16)[0] if opt + 20 <= len(d) else 0
    dd = opt + (96 if magic == 0x10b else 112)
    imp_rva = 0
    if dd + 16 <= opt + optsize and dd + 16 <= len(d):
        imp_rva = struct.unpack_from('<I', d, dd + 8)[0]
    sections = []
    so = opt + optsize
    for i in range(nsec):
        o = so + 40 * i
        if o + 40 > len(d):
            break
        name = d[o:o + 8].rstrip(b'\0').decode('latin-1')
        vsize, va, rawsize, rawptr = struct.unpack_from('<IIII', d, o + 8)
        chars, = struct.unpack_from('<I', d, o + 36)
        sections.append((name, va, vsize, rawptr, rawsize, chars))

    def off(rva):
        for _, va, vs, rp, rs, _c in sections:
            if va <= rva < va + max(vs, rs) and rva - va < rs:
                return rp + rva - va
        return None

    imports = []
    o = off(imp_rva) if imp_rva else None
    while o is not None and o + 20 <= len(d) and len(imports) < 512:
        name_rva = struct.unpack_from('<I', d, o + 12)[0]
        if name_rva == 0:
            break
        no = off(name_rva)
        if no is not None:
            end = d.find(b'\0', no, no + 256)
            if end > no:
                imports.append(d[no:end].decode('latin-1'))
        o += 20
    return {'sections': sections, 'entry': entry, 'imports': imports}


def check_file(path, rel):
    found = []
    base = os.path.basename(rel).lower()
    if base in FILE_NAMES:
        kind, product = FILE_NAMES[base]
        found.append({'file': rel, 'kind': kind, 'product': product, 'evidence': 'file name ' + os.path.basename(rel)})
    try:
        with open(path, 'rb') as f:
            head = f.read(2)
            if head != b'MZ':
                return found, False
            d = head + f.read()
    except OSError:
        return found, False
    pe = parse_pe(d)
    if pe is None:
        return found, False
    seen = set()
    for name, va, vsize, rawptr, rawsize, chars in pe['sections']:
        hit = SECTIONS.get(name.lower())
        if hit and (hit, name) not in seen:
            seen.add((hit, name))
            found.append({'file': rel, 'kind': hit[0], 'product': hit[1], 'evidence': 'section ' + name})
    for dll in pe['imports']:
        hit = IMPORTS.get(dll.lower())
        if hit:
            found.append({'file': rel, 'kind': hit[0], 'product': hit[1], 'evidence': 'imports ' + dll})
    for sig, kind, product in STRINGS:
        at = d.find(sig)
        if at >= 0:
            found.append({'file': rel, 'kind': kind, 'product': product, 'evidence': 'signature string at file offset 0x%x' % at})
    entry = pe['entry']
    if entry:
        sec = None
        for s in pe['sections']:
            if s[1] <= entry < s[1] + max(s[2], s[4]):
                sec = s
                break
        if sec is None:
            found.append({'file': rel, 'kind': 'warning', 'product': 'unknown packer',
                          'evidence': 'entry point 0x%x outside every section' % entry})
        else:
            name, va, vsize, rawptr, rawsize, chars = sec
            if chars & SCN_WRITE and chars & SCN_EXEC:
                found.append({'file': rel, 'kind': 'warning', 'product': 'unknown packer',
                              'evidence': 'entry point in writable code section %s' % (name or '(unnamed)')})
            if rawsize >= 4096:
                e = entropy100(d[rawptr:rawptr + rawsize])
                if e >= ENTROPY_LIMIT:
                    found.append({'file': rel, 'kind': 'warning', 'product': 'unknown packer',
                                  'evidence': 'entry point section %s has entropy %d.%02d bits/byte' %
                                  (name or '(unnamed)', e // 100, e % 100)})
    return found, True


def main(argv):
    args, out = [], None
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ('-h', '--help'):
            sys.stdout.write(__doc__.strip() + '\n')
            return 0
        if a == '--json':
            if i + 1 >= len(argv):
                sys.stderr.write(USAGE + 'protection_check.py: error: --json needs a value\n')
                return 2
            out = argv[i + 1]
            i += 2
            continue
        if a.startswith('--'):
            sys.stderr.write(USAGE + 'protection_check.py: error: unknown option %s\n' % a)
            return 2
        args.append(a)
        i += 1
    if not args:
        sys.stderr.write(USAGE + 'protection_check.py: error: nothing to scan\n')
        return 2
    files = []
    for a in args:
        if os.path.isdir(a):
            for root, dirs, names in os.walk(a):
                dirs.sort()
                for n in sorted(names):
                    p = os.path.join(root, n)
                    if os.path.isfile(p) and not os.path.islink(p):
                        files.append((p, os.path.relpath(p, a).replace(os.sep, '/')))
        elif os.path.isfile(a):
            files.append((a, os.path.basename(a)))
        else:
            sys.stderr.write('protection_check.py: error: %s: no such file or folder\n' % a)
            return 2
    findings, npe = [], 0
    for p, rel in files:
        f, is_pe = check_file(p, rel)
        findings += f
        npe += is_pe
    kinds = {f['kind'] for f in findings}
    verdict = 'protected' if kinds & {'drm', 'packer'} else ('review' if 'warning' in kinds else 'clean')
    summary = {'scanned_files': len(files), 'pe_files': npe, 'verdict': verdict, 'findings': findings}
    for f in findings:
        if f['kind'] != 'info':
            sys.stderr.write('%s: %s %s (%s)\n' % (f['file'], f['kind'], f['product'], f['evidence']))
    text = json.dumps(summary, indent=1)
    if out:
        with open(out, 'w', encoding='utf-8') as fh:
            fh.write(text + '\n')
    sys.stdout.write(text + '\n')
    return 0 if verdict == 'clean' else 1


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

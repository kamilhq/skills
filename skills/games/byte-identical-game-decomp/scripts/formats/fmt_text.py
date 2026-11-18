"""Text files (template: set EXTS to the project's text extensions).

Decoded form (outdir):
  text<ext>   the content as UTF-8 with LF line endings (open/edit with any editor)
  text.json   encoding facts: original encoding, BOM, line-ending layout, so the exact bytes come back

The line-ending layout is stored as runs of ("crlf"|"lf"|"cr", count) in file order, one entry per line
break of the LF-normalised text; a uniform file is a single run. Nothing is kept uninterpreted, so
opaque_bytes is 0. Encodings are tried in order utf-8, cp1252, latin-1; latin-1 accepts any byte, so a
binary-looking file would decode as latin-1 text rather than fail: route only real text files here. The
decoded text never contains CR (every CR is a recorded line ending), so an editor that re-saves it
with CRLF does not change the rebuilt file.
"""
import json, os

EXTS = ['.txt', '.xml', '.ini']      # edit: every text extension of the game (e.g. .cfg, .info, .fontmeta)

ENCODINGS = ['utf-8', 'cp1252', 'latin-1']     # first that round-trips wins; latin-1 always does


def text_to_facts(data):
    """bytes -> (normalised str, facts dict). Shared with fmt_level."""
    bom = data.startswith(b'\xef\xbb\xbf')
    body = data[3:] if bom else data
    for enc in ENCODINGS:
        try:
            s = body.decode(enc)
        except UnicodeDecodeError:
            continue
        if s.encode(enc) == body:
            break
    else:                                      # unreachable: latin-1 decodes anything
        raise ValueError('no encoding round-trips')
    runs, out, i, n = [], [], 0, len(s)
    start = 0
    while i < n:
        c = s[i]
        if c == '\r' or c == '\n':
            out.append(s[start:i])
            if c == '\r' and i + 1 < n and s[i + 1] == '\n':
                kind, i = 'crlf', i + 2
            else:
                kind, i = ('cr' if c == '\r' else 'lf'), i + 1
            if runs and runs[-1][0] == kind:
                runs[-1][1] += 1
            else:
                runs.append([kind, 1])
            start = i
        else:
            i += 1
    out.append(s[start:])
    norm = '\n'.join(out)
    return norm, dict(encoding=enc, bom=bom, line_endings=runs)


def facts_to_bytes(norm, facts):
    lines = norm.split('\n')
    seps = []
    for kind, count in facts['line_endings']:
        seps.extend([{'crlf': '\r\n', 'lf': '\n', 'cr': '\r'}[kind]] * count)
    if len(seps) != len(lines) - 1:
        # the text was edited and the number of lines changed: use the dominant ending for all
        tot = {}
        for kind, count in facts['line_endings']:
            tot[kind] = tot.get(kind, 0) + count
        dom = max(tot, key=tot.get) if tot else 'lf'
        seps = [{'crlf': '\r\n', 'lf': '\n', 'cr': '\r'}[dom]] * (len(lines) - 1)
    parts = []
    for i, line in enumerate(lines):
        parts.append(line)
        if i < len(seps):
            parts.append(seps[i])
    raw = ''.join(parts).encode(facts['encoding'])
    return (b'\xef\xbb\xbf' if facts['bom'] else b'') + raw


def write_text(path, s):
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(s)


def read_text(path):
    """Decoded text as written by write_text; CRLF/CR from an editor are folded back to LF."""
    with open(path, 'r', encoding='utf-8', newline='') as f:
        return f.read().replace('\r\n', '\n').replace('\r', '\n')


def decode_to_dir(data, outdir, ext='.txt'):
    norm, facts = text_to_facts(data)
    # the harness passes only data; the extension is recovered from the decoded dir name it creates
    base = os.path.basename(os.path.normpath(outdir))
    e = os.path.splitext(base)[1].lower() or ext
    facts['file'] = 'text' + e
    write_text(os.path.join(outdir, facts['file']), norm)
    json.dump(facts, open(os.path.join(outdir, 'text.json'), 'w'), indent=1)
    notes = [f"encoding {facts['encoding']}{' +BOM' if facts['bom'] else ''}",
             'line endings ' + ', '.join(f'{k}x{c}' for k, c in facts['line_endings'])]
    return dict(opaque_bytes=0, notes=notes)


def encode_from_dir(outdir):
    facts = json.load(open(os.path.join(outdir, 'text.json')))
    return facts_to_bytes(read_text(os.path.join(outdir, facts['file'])), facts)

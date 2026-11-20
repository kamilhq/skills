#!/usr/bin/env python3
"""Round-trip verifier shared by every format decoder (step 3d).

Contract for a format module  <formats_dir>/fmt_<name>.py :
    EXTS = ['.ptx', ...]                          # lower-case extensions handled (matched case-insensitively)
    def decode_to_dir(data: bytes, outdir: str) -> dict
        Write the decoded, human-usable representation of `data` into `outdir`
        (JSON / PNG / WAV / text / OBJ ...). Return {"opaque_bytes": N, "notes": [...]}
        where N = number of source bytes stored without interpretation (unknown fields kept as raw
        hex/blobs). N is reported, so be honest.
    def encode_from_dir(outdir: str) -> bytes
        Rebuild the original file using ONLY what is in `outdir`. Never read the original file, never
        read outside outdir, never stash a hash or a whole copy of the original.

Check: encode_from_dir(decode_to_dir(x)) == x for every file, byte for byte (SHA-256), decoding into a fresh
directory each time. Writes <report>/<module>.json with per-file results and exits non-zero on any failure.

Usage:
    python3 -I verify.py <module> --src <dir> [--formats-dir tools/formats] [--out decoded] [--report reports]
"""
import argparse, hashlib, importlib.util, json, os, shutil, sys, time, traceback


def load_module(formats_dir, name):
    path = os.path.join(formats_dir, f'fmt_{name}.py')
    sys.path.insert(0, os.path.abspath(formats_dir))      # helpers (pngio, fmt_<name>_*.py) import by name
    spec = importlib.util.spec_from_file_location(f'fmt_{name}', path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('module')
    ap.add_argument('--src', required=True, help='directory tree holding the original files')
    ap.add_argument('--formats-dir', default='tools/formats')
    ap.add_argument('--out', default='decoded')
    ap.add_argument('--report', default='reports')
    ap.add_argument('--limit', type=int, default=0, help='debug: only the first N files')
    a = ap.parse_args()
    mod = load_module(a.formats_dir, a.module)
    exts = {e.lower() for e in mod.EXTS}
    files = sorted(os.path.join(r, f) for r, _, fs in os.walk(a.src) for f in fs
                   if os.path.splitext(f)[1].lower() in exts)
    if a.limit:
        files = files[:a.limit]
    res = dict(module=a.module, exts=sorted(exts), src=os.path.basename(os.path.abspath(a.src)), files=len(files),
               passed=0, failed=0, total_bytes=0, opaque_bytes=0, failures=[], per_file=[])
    t0 = time.time()
    for p in files:
        rel = os.path.relpath(p, a.src)
        outdir = os.path.join(a.out, a.module, rel)
        if os.path.exists(outdir):
            shutil.rmtree(outdir)
        os.makedirs(outdir)
        data = open(p, 'rb').read()
        digest = hashlib.sha256(data).hexdigest()
        res['total_bytes'] += len(data)
        try:
            info = mod.decode_to_dir(data, outdir) or {}
            rebuilt = mod.encode_from_dir(outdir)
            ok = hashlib.sha256(rebuilt).hexdigest() == digest
            op = int(info.get('opaque_bytes', 0))
            res['opaque_bytes'] += op
            res['per_file'].append(dict(file=rel, bytes=len(data), opaque=op, ok=ok, sha256=digest))
            if ok:
                res['passed'] += 1
            else:
                res['failed'] += 1
                first = next((i for i, (x, y) in enumerate(zip(data, rebuilt)) if x != y), min(len(data), len(rebuilt)))
                res['failures'].append(dict(file=rel, error='mismatch', orig_len=len(data),
                                            rebuilt_len=len(rebuilt), first_diff=first))
        except Exception:
            res['failed'] += 1
            res['failures'].append(dict(file=rel, error=traceback.format_exc()[-1500:]))
    res['seconds'] = round(time.time() - t0, 1)
    res['opaque_ratio'] = round(res['opaque_bytes'] / res['total_bytes'], 6) if res['total_bytes'] else 0
    os.makedirs(a.report, exist_ok=True)
    json.dump(res, open(os.path.join(a.report, f'{a.module}.json'), 'w'), indent=1)
    summary = {k: v for k, v in res.items() if k != 'per_file'}
    summary['failures'] = res['failures'][:5]
    print(json.dumps(summary, indent=1))
    sys.exit(0 if res['failed'] == 0 and res['files'] > 0 else 1)


if __name__ == '__main__':
    main()

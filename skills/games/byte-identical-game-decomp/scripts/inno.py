#!/usr/bin/env python3
r"""inno.py - pure-Python (3.9+ stdlib only) extractor for GOG Inno Setup installers.

Replaces `innoextract --gog --exclude-temp` for this skill: same file set, same
bytes, same paths (and same mtimes) as innoextract 1.9, so trees compare 1:1.
Never calls innoextract or any other external tool.

Usage (run with `python3 -I`):
  inno.py info    <setup.exe> [--json]
  inno.py list    <setup.exe> [--json] [--include-temp] [--language L]
  inno.py extract <setup.exe> <out_dir> [--language L] [--include-temp]
                  [--collisions overwrite|error|rename] [--no-mtime] [--quiet]
  inno.py verify  <setup.exe>   decompress every data entry (temp files too), check
                                every stored checksum, write nothing

  Temp files ({tmp}, flag deleteafterinstall = innoextract's [temp]) are skipped by
  default (--exclude-temp); --include-temp extracts them to tmp/.
  --language L keeps files whose language condition matches L plus files without
  one (innoextract --language). GOG languages look like "en-US".
  --collisions: two entries mapping to the same path (case-insensitive):
  overwrite (default, later entry wins), error (exit 1), rename (path$1, ...).
  extract prints a JSON summary on stdout; progress goes to stderr.

Output layout (identical to innoextract --gog):
  GOG Galaxy installers (all tested ones) store each game file as zlib parts in
  {tmp}\xx\yy\<md5> entries plus before_install/after_install/check_if_install
  script calls; those are reassembled (part MD5s, whole-file MD5 verified) and
  written to the relative path GOG gives, i.e. the GAME FILES ARE AT <out_dir>/
  (e.g. <out_dir>/Game.exe, <out_dir>/DATA/...). __redist/... (redistributables,
  e.g. __redist/ISI/scriptinterpreter.exe, __redist/DirectX/*.cab) also comes from
  Galaxy "dependency" entries.
  Plain Inno entries keep their constant as a folder name: {app}\x -> app/x (on GOG
  installers that is installer-only support stuff: app/goggame-<id>.ico,
  app/webcache.zip, [Dirs] like app/Save/), {commonappdata}\x -> commonappdata/x,
  {tmp}\x -> tmp/x, any {const} -> const/ ("{code:X}" -> "code$X").
  "\" becomes "/", "." and empty segments are dropped, ".." pops a segment; a path
  that would escape <out_dir> (or write through a symlink) is refused (exit 1).
  Directories from [Dirs] entries are created (even if empty).
  So for intake: game root = <out_dir> minus {app/, __redist/, commonappdata/,
  tmp/}; goggame-<id>.info/.hashdb/.ico at the root are GOG metadata.
  Non-GOG installers (publisher/URLs without gog.com) get no Galaxy handling:
  their {app} files land under app/, exactly like innoextract.

Integrity (any failure -> exit 1, partial output files are removed):
  loader offset-table CRC32, header block CRC32s (one per 4 KiB chunk), chunk
  magic "zlb\x1a", every data entry's stored checksum (SHA-1 for 5.3.9+, MD5
  4.2.0-5.3.8, CRC32 / Adler-32 older) after decompression and x86 call-filter
  decoding, GOG part MD5 + size, GOG whole-file MD5. Files are written as
  *.inno-partial and renamed only when complete and verified.

Tested (byte-identical vs innoextract 1.9, every checksum verified):
  Inno Setup data 5.5.7 (u) and 5.6.2 (u), single-file (data embedded in the exe),
  LZMA2 + stored chunks, x86 call filter 5.3.9, GOG Galaxy split files.
Implemented from the documented structures but UNTESTED: 4.0.0-6.2.x ANSI and
  unicode header layouts, LZMA1 / zlib / bzip2 chunks, x86 filters 4.1.8 and 5.2.0,
  external disk slices (setup-N.bin / setup-Na.bin, "idska32"). An untested
  version that fails a structural sanity check is reported as unsupported (exit 2)
  instead of producing garbage; `info` marks untested versions.

Unsupported (exit 2): encrypted chunks (password-protected setups), GOG's old
  RAR-based setup-N.bin parts ("Rar!" signature: use an installed copy of the game
  instead), Inno Setup 6.3+ and pre-4.0 / 16-bit installers, non-Inno files.

Exit codes: 0 ok; 1 extraction / verification / I/O error (checksum, CRC, bad
  chunk, truncated data, path traversal, --collisions error hit); 2 bad arguments
  or unsupported installer.
"""

import argparse
import bz2
import hashlib
import json
import lzma
import os
import re
import shutil
import struct
import sys
import time
import zlib

EXIT_OK, EXIT_FAIL, EXIT_UNSUPPORTED = 0, 1, 2

TESTED_VERSIONS = {(5, 5, 7), (5, 6, 2)}


class InnoError(Exception):
    exit_code = EXIT_FAIL


class Unsupported(InnoError):
    exit_code = EXIT_UNSUPPORTED


def V(a, b, c, d=0):
    return (a, b, c, d)


# ---------------------------------------------------------------------------
# PE resource lookup + setup loader offset table
# ---------------------------------------------------------------------------

LOADER_MAGICS = [
    (b"rDlPtS02\x87eVx", V(1, 2, 10)),
    (b"rDlPtS04\x87eVx", V(4, 0, 0)),
    (b"rDlPtS05\x87eVx", V(4, 0, 3)),
    (b"rDlPtS06\x87eVx", V(4, 0, 10)),
    (b"rDlPtS07\x87eVx", V(4, 1, 6)),
    (b"rDlPtS\xcd\xe6\xd7\x7b\x0b\x2a", V(5, 1, 5)),
    (b"nS5W7dT\x83\xaa\x1b\x0f\x6a", V(5, 1, 5)),
]


def _pe_rcdata(f, res_id=11111, res_type=10):
    """Return file offset of RT_RCDATA resource `res_id`, or None."""
    f.seek(0)
    mz = f.read(64)
    if len(mz) < 64 or mz[:2] != b"MZ":
        return None
    pe = struct.unpack_from("<I", mz, 0x3C)[0]
    f.seek(pe)
    h = f.read(24)
    if len(h) < 24 or h[:4] != b"PE\0\0":
        return None
    nsec, = struct.unpack_from("<H", h, 6)
    optsz, = struct.unpack_from("<H", h, 20)
    opt = f.read(optsz)
    magic, = struct.unpack_from("<H", opt, 0)
    ddoff = 96 if magic == 0x10B else 112
    if len(opt) < ddoff + 24:
        return None
    rsrc_rva, rsrc_size = struct.unpack_from("<II", opt, ddoff + 16)
    if not rsrc_rva:
        return None
    secs = []
    sdata = f.read(40 * nsec)
    for i in range(nsec):
        vsize, va, rawsize, rawptr = struct.unpack_from("<IIII", sdata, i * 40 + 8)
        secs.append((va, max(vsize, rawsize), rawptr))

    def rva2off(rva):
        for va, sz, raw in secs:
            if va <= rva < va + sz:
                return rva - va + raw
        return None

    base = rva2off(rsrc_rva)
    if base is None:
        return None
    f.seek(base)
    blob = f.read(max(rsrc_size, 16))

    def entries(off):
        nn, ni = struct.unpack_from("<HH", blob, off + 12)
        for k in range(nn + ni):
            name, ptr = struct.unpack_from("<II", blob, off + 16 + 8 * k)
            yield name, ptr

    try:
        for name, ptr in entries(0):
            if name == res_type and ptr & 0x80000000:
                for name2, ptr2 in entries(ptr & 0x7FFFFFFF):
                    if name2 == res_id and ptr2 & 0x80000000:
                        for _lang, ptr3 in entries(ptr2 & 0x7FFFFFFF):
                            if ptr3 & 0x80000000:
                                continue
                            rva, _size = struct.unpack_from("<II", blob, ptr3)
                            return rva2off(rva)
    except struct.error:
        return None
    return None


class Offsets:
    pass


def _parse_offset_table(f, pos):
    f.seek(pos)
    data = f.read(64)
    if len(data) < 12:
        return None
    ver = None
    for magic, v in LOADER_MAGICS:
        if data[:12] == magic:
            ver = v
            break
    if ver is None:
        return None
    p = 12

    def u32():
        nonlocal p
        v = struct.unpack_from("<I", data, p)[0]
        p += 4
        return v

    o = Offsets()
    o.loader_version = ver
    if ver >= V(5, 1, 5):
        o.revision = u32()
    u32()  # total size
    o.exe_offset = u32()
    if ver < V(4, 1, 6):
        u32()  # exe compressed size
    o.exe_uncompressed_size = u32()
    o.exe_crc = u32()
    if ver < V(4, 0, 0):
        u32()  # message offset (not covered by CRC, irrelevant here)
    o.header_offset = u32()
    o.data_offset = u32()
    if ver >= V(4, 0, 10):
        crc_end = p
        expected = u32()
        if zlib.crc32(data[:crc_end]) & 0xFFFFFFFF != expected:
            raise InnoError("setup loader offset table CRC32 mismatch at 0x%x" % pos)
    return o


def find_offsets(f):
    off = _pe_rcdata(f)
    if off is not None:
        o = _parse_offset_table(f, off)
        if o:
            return o
    f.seek(0x30)
    h = f.read(12)
    if len(h) == 12 and h[:4] == b"Inno":
        a, b = struct.unpack_from("<II", h, 4)
        if a == (~b & 0xFFFFFFFF):
            o = _parse_offset_table(f, a)
            if o:
                return o
    # last resort: scan the first 32 MiB for a loader table signature
    f.seek(0)
    blob = f.read(32 << 20)
    for magic, _v in LOADER_MAGICS:
        i = blob.find(magic)
        while i >= 0:
            try:
                o = _parse_offset_table(f, i)
                if o:
                    return o
            except InnoError:
                pass
            i = blob.find(magic, i + 1)
    return None


# ---------------------------------------------------------------------------
# Compressed header blocks
# ---------------------------------------------------------------------------

def lzma1_decompressor(props5):
    d = props5[0]
    if d >= 9 * 5 * 5:
        raise InnoError("bad LZMA1 properties byte %d" % d)
    lc = d % 9
    d //= 9
    lp = d % 5
    pb = d // 5
    dict_size = struct.unpack_from("<I", props5, 1)[0]
    return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA1, "dict_size": max(dict_size, 4096),
        "lc": lc, "lp": lp, "pb": pb}])


def lzma2_decompressor(prop):
    if prop > 40:
        raise InnoError("bad LZMA2 dictionary property %d" % prop)
    if prop == 40:
        ds = 0xFFFFFFFF
    else:
        ds = (2 | (prop & 1)) << (prop // 2 + 11)
    return lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA2, "dict_size": ds}])


def read_block(f, version):
    """Read one Inno 'block' (setup.0 header / data-entry block). Returns bytes."""
    start = f.tell()
    if version >= V(4, 0, 9):
        h = f.read(9)
        if len(h) < 9:
            raise InnoError("truncated header block at 0x%x" % start)
        expected, stored_size, compressed = struct.unpack("<IIB", h)
        if zlib.crc32(h[4:9]) & 0xFFFFFFFF != expected:
            raise InnoError("header block CRC32 mismatch at 0x%x" % start)
        if compressed:
            comp = "lzma1" if version >= V(4, 1, 6) else "zlib"
        else:
            comp = "stored"
    else:
        h = f.read(12)
        expected, csize, usize = struct.unpack("<III", h)
        if zlib.crc32(h[4:12]) & 0xFFFFFFFF != expected:
            raise InnoError("header block CRC32 mismatch at 0x%x" % start)
        if csize == 0xFFFFFFFF:
            stored_size, comp = usize, "stored"
        else:
            stored_size, comp = csize, "zlib"
        stored_size += -(-stored_size // 4096) * 4
    raw = f.read(stored_size)
    if len(raw) != stored_size:
        raise InnoError("truncated header block at 0x%x" % start)
    parts = []
    p = 0
    n = 0
    while p < len(raw):
        if len(raw) - p < 5:
            raise InnoError("bad header block chunk size at 0x%x" % (start + p))
        crc = struct.unpack_from("<I", raw, p)[0]
        chunk = raw[p + 4:p + 4 + 4096]
        if zlib.crc32(chunk) & 0xFFFFFFFF != crc:
            raise InnoError("header block chunk %d CRC32 mismatch (block at 0x%x)" % (n, start))
        parts.append(chunk)
        p += 4 + len(chunk)
        n += 1
    data = b"".join(parts)
    if comp == "stored":
        return data
    if comp == "zlib":
        return zlib.decompress(data)
    dec = lzma1_decompressor(data[:5])
    return dec.decompress(data[5:])


# ---------------------------------------------------------------------------
# Record reader
# ---------------------------------------------------------------------------

class Reader:
    __slots__ = ("b", "p", "unicode", "ansi_cp")

    def __init__(self, b, unicode, ansi_cp="cp1252"):
        self.b = b
        self.p = 0
        self.unicode = unicode
        self.ansi_cp = ansi_cp

    def need(self, n):
        if self.p + n > len(self.b):
            raise InnoError("header data truncated (record parse overran block)")

    def u8(self):
        self.need(1)
        v = self.b[self.p]
        self.p += 1
        return v

    def _st(self, fmt, n):
        self.need(n)
        v = struct.unpack_from(fmt, self.b, self.p)[0]
        self.p += n
        return v

    def u16(self): return self._st("<H", 2)
    def i16(self): return self._st("<h", 2)
    def u32(self): return self._st("<I", 4)
    def i32(self): return self._st("<i", 4)
    def u64(self): return self._st("<Q", 8)
    def i64(self): return self._st("<q", 8)

    def raw(self, n):
        self.need(n)
        v = bytes(self.b[self.p:self.p + n])
        self.p += n
        return v

    def bstr(self):
        n = self.u32()
        if n > len(self.b) - self.p:
            raise InnoError("implausible string length %d at 0x%x" % (n, self.p - 4))
        return self.raw(n)

    def s(self):
        """Delphi 'String': UTF-16LE in unicode builds, ANSI otherwise."""
        b = self.bstr()
        if self.unicode:
            if len(b) & 1:
                raise InnoError("odd-length UTF-16 string at 0x%x" % self.p)
            return b.decode("utf-16-le", "surrogatepass")
        return b.decode(self.ansi_cp, "replace")

    def a(self):
        """Delphi 'AnsiString'."""
        return self.bstr().decode(self.ansi_cp, "replace")

    def flags(self, names):
        """Delphi set: one bit per name, ceil(n/8) bytes, 3 bytes padded to 4."""
        nb = (len(names) + 7) // 8
        v = int.from_bytes(self.raw(nb), "little")
        if nb == 3:
            self.u8()
        return {nm for i, nm in enumerate(names) if nm and v >> i & 1}


def parse_version(s):
    m = re.search(r"\((\d+)\.(\d+)\.(\d+)(?:\.(\d+))?\)", s)
    if not m:
        return None, False
    v = tuple(int(x or 0) for x in m.groups())
    unicode = bool(re.search(r"\((u|U)\)", s)) or v >= V(6, 3, 0)
    return v, unicode


# ---------------------------------------------------------------------------
# Setup info parsing
# ---------------------------------------------------------------------------

class Setup:
    pass


def _winver(r, v):
    if v >= V(1, 3, 19):
        r.raw(20)
    else:
        r.raw(16)


def _conditions(r, v, e):
    e["components"] = r.s() if v >= V(2, 0, 0) else ""
    e["tasks"] = r.s() if v >= V(2, 0, 0) else ""
    e["languages"] = r.s() if v >= V(4, 0, 1) else ""
    e["check"] = r.s() if v >= V(3, 0, 8) else ""
    if v >= V(4, 1, 0):
        e["after_install"] = r.s()
        e["before_install"] = r.s()
    else:
        e["after_install"] = e["before_install"] = ""


def _parse_header(r, v):
    h = {}
    S = r.s
    h["app_name"] = S()
    h["app_versioned_name"] = S()
    h["app_id"] = S()
    h["app_copyright"] = S()
    h["app_publisher"] = S()
    h["app_publisher_url"] = S()
    if v >= V(5, 1, 13):
        h["app_support_phone"] = S()
    h["app_support_url"] = S()
    h["app_updates_url"] = S()
    h["app_version"] = S()
    h["default_dir_name"] = S()
    h["default_group_name"] = S()
    if v < V(3, 0, 0):
        r.a()
    h["base_filename"] = S()
    if v < V(5, 2, 5):
        r.a(); r.a(); r.a()  # license, info before, info after
    h["uninstall_files_dir"] = S()
    h["uninstall_name"] = S()
    h["uninstall_icon"] = S()
    h["app_mutex"] = S()
    if v >= V(3, 0, 0):
        S(); S()  # default user name / org
    if v >= V(4, 0, 0):
        S()  # default serial
    if V(4, 0, 0) <= v < V(5, 0, 4):
        r.bstr()  # compiled code
    if v >= V(4, 2, 4):
        S(); S(); S(); S()  # readme, contact, comments, modify path
    if v >= V(5, 3, 8):
        S()  # create uninstall registry key
    if v >= V(5, 3, 10):
        S()  # uninstallable
    if v >= V(5, 5, 0):
        S()  # close applications filter
    if v >= V(5, 5, 6):
        S()  # setup mutex
    if v >= V(5, 6, 1):
        S(); S()  # changes environment / associations
    if v >= V(6, 3, 0):
        raise Unsupported("Inno Setup %s header layout is not implemented" % vstr(v))
    if v >= V(5, 2, 5):
        r.a(); r.a(); r.a()  # license, info before, info after
    if V(5, 2, 1) <= v < V(5, 3, 10):
        S()  # uninstaller signature
    if v >= V(5, 2, 5):
        r.bstr()  # compiled code
    if not r.unicode:
        r.raw(32)  # lead bytes char set
    h["language_count"] = r.u32() if v >= V(4, 0, 0) else 1
    h["message_count"] = r.u32() if v >= V(4, 2, 1) else 0
    h["permission_count"] = r.u32() if v >= V(4, 1, 0) else 0
    h["type_count"] = r.u32()
    h["component_count"] = r.u32()
    h["task_count"] = r.u32()
    for k in ("directory_count", "file_count", "data_entry_count", "icon_count",
              "ini_entry_count", "registry_entry_count", "delete_entry_count",
              "uninstall_delete_entry_count", "run_entry_count",
              "uninstall_run_entry_count"):
        h[k] = r.u32()
    _winver(r, v)  # min version + only below version
    r.u32()  # back color
    r.u32()  # back color 2
    if v < V(5, 5, 7):
        r.u32()  # image back color
    if V(2, 0, 0) <= v < V(5, 0, 4):
        r.u32()  # small image back color
    if v >= V(6, 0, 0):
        r.u8(); r.u32(); r.u32()  # wizard style, resize percent x/y
    if v >= V(5, 5, 7):
        r.u8()  # image alpha format
    if v < V(4, 2, 0):
        r.u32()
    elif v < V(5, 3, 9):
        r.raw(16)
    else:
        r.raw(20)
    if v >= V(4, 2, 2):
        r.raw(8)  # password salt
    r.i64()  # extra disk space
    h["slices_per_disk"] = r.u32()
    if v < V(5, 0, 0):
        r.u8()  # install verbosity
    r.u8()  # uninstall log mode
    r.u8()  # dir exists warning
    r.u8()  # privileges required
    if v >= V(5, 7, 0):
        r.u8()  # privileges required override (set, 1 byte)
    r.u8()  # show language dialog
    r.u8()  # language detection
    h["compression"] = r.u8()
    r.u8(); r.u8()  # architectures allowed / installed in 64-bit mode
    if V(5, 2, 1) <= v < V(5, 3, 10):
        r.u32(); r.u32()
    if v >= V(5, 3, 3):
        r.u8(); r.u8()  # disable dir page / program group page
    if v >= V(5, 5, 0):
        r.u64()
    elif v >= V(5, 3, 6):
        r.u32()
    names = ["DisableStartupPrompt"]
    if v < V(5, 3, 10):
        names.append("Uninstallable")
    names.append("CreateAppDir")
    if v < V(5, 3, 3):
        names.append("DisableDirPage")
    if v < V(5, 3, 3):
        names.append("DisableProgramGroupPage")
    names += ["AllowNoIcons", "AlwaysRestart", "AlwaysUsePersonalGroup", "WindowVisible",
              "WindowShowCaption", "WindowResizable", "WindowStartMaximized",
              "EnableDirDoesntExistWarning"]
    if v < V(4, 1, 2):
        names.append("DisableAppendDir")
    names += ["Password", "AllowRootDirectory", "DisableFinishedPage"]
    if v < V(3, 0, 4):
        names.append("AdminPrivilegesRequired")
    if v < V(5, 6, 1):
        names.append("ChangesAssociations")
    if v < V(5, 3, 8):
        names.append("CreateUninstallRegKey")
    names += ["UsePreviousAppDir", "BackColorHorizontal", "UsePreviousGroup",
              "UpdateUninstallLogAppName", "UsePreviousSetupType", "DisableReadyMemo",
              "AlwaysShowComponentsList", "FlatComponentsList", "ShowComponentSizes",
              "UsePreviousTasks", "DisableReadyPage", "AlwaysShowDirOnReadyPage",
              "AlwaysShowGroupOnReadyPage"]
    if v < V(4, 1, 5):
        names.append("BzipUsed")
    names += ["AllowUNCPath", "UserInfoPage", "UsePreviousUserInfo",
              "UninstallRestartComputer", "RestartIfNeededByRun", "ShowTasksTreeLines"]
    if v < V(4, 0, 10):
        names += ["ShowLanguageDialog", "DetectLanguageUsingLocale"]
    if v >= V(4, 0, 9):
        names.append("AllowCancelDuringInstall")
    if v >= V(4, 1, 3):
        names.append("WizardImageStretch")
    if v >= V(4, 1, 8):
        names += ["AppendDefaultDirName", "AppendDefaultGroupName"]
    if v >= V(4, 2, 2):
        names.append("EncryptionUsed")
    if V(5, 0, 4) <= v < V(5, 6, 1):
        names.append("ChangesEnvironment")
    if v >= V(5, 1, 7) and not r.unicode:
        names.append("ShowUndisplayableLanguages")
    if v >= V(5, 1, 13):
        names.append("SetupLogging")
    if v >= V(5, 2, 1):
        names.append("SignedUninstaller")
    if v >= V(5, 3, 8):
        names.append("UsePreviousLanguage")
    if v >= V(5, 3, 9):
        names.append("DisableWelcomePage")
    if v >= V(5, 5, 0):
        names += ["CloseApplications", "RestartApplications", "AllowNetworkDrive"]
    if v >= V(5, 5, 7):
        names.append("ForceCloseApplications")
    if v >= V(6, 0, 0):
        names += ["AppNameHasConsts", "UsePreviousPrivileges", "WizardResizable"]
    h["options"] = r.flags(names)
    return h


def _parse_language(r, v):
    e = {}
    e["name"] = r.s() if v >= V(4, 0, 0) else "default"
    e["language_name"] = r.s()
    r.s(); r.s(); r.s(); r.s()  # fonts
    if v >= V(4, 0, 0):
        r.bstr()  # data
    if v >= V(4, 0, 1):
        r.a(); r.a(); r.a()
    e["language_id"] = r.u32()
    if v >= V(4, 2, 2) and not r.unicode:
        e["codepage"] = r.u32()
    elif r.unicode and v < V(5, 3, 0):
        r.u32()
    if v >= V(2, 0, 1):
        r.u32()  # dialog font size
    if v < V(4, 1, 0):
        r.u32()
    r.u32(); r.u32(); r.u32()  # title/welcome/copyright font size
    if v >= V(5, 2, 3):
        r.u8()  # right to left
    return e


def _parse_message(r, v):
    r.s(); r.bstr(); r.i32()


def _parse_permission(r, v):
    r.bstr()


def _parse_type(r, v):
    e = {"name": r.s(), "description": r.s()}
    if v >= V(4, 0, 1):
        e["languages"] = r.s()
    if v >= V(3, 0, 8):
        e["check"] = r.s()
    _winver(r, v)
    r.flags(["CustomSetupType"])
    if v >= V(4, 0, 3):
        r.u8()
    e["size"] = r.u64() if v >= V(4, 0, 0) else r.u32()
    return e


def _parse_component(r, v):
    e = {"name": r.s(), "description": r.s(), "types": r.s()}
    if v >= V(4, 0, 1):
        e["languages"] = r.s()
    if v >= V(3, 0, 8):
        e["check"] = r.s()
    r.u64() if v >= V(4, 0, 0) else r.u32()
    if v >= V(4, 0, 0):
        e["level"] = r.i32()
        r.u8()
    _winver(r, v)
    nm = ["Fixed", "Restart", "DisableNoUninstallWarning", "Exclusive"]
    if v >= V(4, 2, 3):
        nm.append("DontInheritCheck")
    e["options"] = r.flags(nm)
    e["size"] = r.u64() if v >= V(4, 0, 0) else r.u32()
    return e


def _parse_task(r, v):
    e = {"name": r.s(), "description": r.s(), "group_description": r.s(),
         "components": r.s()}
    if v >= V(4, 0, 1):
        e["languages"] = r.s()
    if v >= V(3, 0, 8):
        e["check"] = r.s()
    if v >= V(4, 0, 0):
        r.i32(); r.u8()
    _winver(r, v)
    nm = ["Exclusive", "Unchecked", "Restart", "CheckedOnce"]
    if v >= V(4, 2, 3):
        nm.append("DontInheritCheck")
    r.flags(nm)
    return e


def _parse_directory(r, v):
    e = {"name": r.s()}
    _conditions(r, v, e)
    if V(4, 0, 11) <= v < V(4, 1, 0):
        r.bstr()
    e["attributes"] = r.u32()
    _winver(r, v)
    if v >= V(4, 1, 0):
        r.i16()
    nm = ["NeverUninstall", "DeleteAfterInstall", "AlwaysUninstall"]
    if v >= V(5, 2, 0):
        nm += ["SetNtfsCompression", "UnsetNtfsCompression"]
    e["options"] = r.flags(nm)
    return e


FILE_FLAGS_CACHE = {}


def _file_flag_names(v):
    nm = ["ConfirmOverwrite", "NeverUninstall", "RestartReplace", "DeleteAfterInstall",
          "RegisterServer", "RegisterTypeLib", "SharedFile"]
    if v < V(2, 0, 0):
        nm.append("IsReadmeFile")
    nm += ["CompareTimeStamp", "FontIsNotTrueType", "SkipIfSourceDoesntExist",
           "OverwriteReadOnly", "OverwriteSameVersion", "CustomDestName",
           "OnlyIfDestFileExists", "NoRegError", "UninsRestartDelete",
           "OnlyIfDoesntExist", "IgnoreVersion", "PromptIfOlder", "DontCopy"]
    if v >= V(4, 0, 5):
        nm.append("UninsRemoveReadOnly")
    if v >= V(4, 1, 8):
        nm.append("RecurseSubDirsExternal")
    if v >= V(4, 2, 1):
        nm.append("ReplaceSameVersionIfContentsDiffer")
    if v >= V(4, 2, 5):
        nm.append("DontVerifyChecksum")
    if v >= V(5, 0, 3):
        nm.append("UninsNoSharedFilePrompt")
    if v >= V(5, 1, 0):
        nm.append("CreateAllSubDirs")
    if v >= V(5, 1, 2):
        nm += ["Bits32", "Bits64"]
    if v >= V(5, 2, 0):
        nm += ["ExternalSizePreset", "SetNtfsCompression", "UnsetNtfsCompression"]
    if v >= V(5, 2, 5):
        nm.append("GacInstall")
    return nm


def _parse_file(r, v):
    e = {"source": r.s(), "destination": r.s(), "install_font_name": r.s()}
    if v >= V(5, 2, 5):
        e["strong_assembly_name"] = r.s()
    _conditions(r, v, e)
    _winver(r, v)
    e["location"] = r.u32()
    e["attributes"] = r.u32()
    e["external_size"] = r.u64() if v >= V(4, 0, 0) else r.u32()
    if v >= V(4, 1, 0):
        r.i16()
    nm = FILE_FLAGS_CACHE.get(v)
    if nm is None:
        nm = FILE_FLAGS_CACHE[v] = _file_flag_names(v)
    e["options"] = r.flags(nm)
    e["file_type"] = r.u8()
    return e


def _parse_icon(r, v):
    e = {"name": r.s(), "filename": r.s()}
    r.s(); r.s(); r.s(); r.s()  # parameters, working dir, icon file, comment
    _conditions(r, v, e)
    if v >= V(5, 3, 5):
        r.s()  # app user model id
    if v >= V(6, 1, 0):
        r.raw(16)
    _winver(r, v)
    r.i32(); r.i32(); r.u8(); r.u16()  # icon index, show cmd, close on exit, hotkey
    nm = ["NeverUninstall", "CreateOnlyIfFileExists", "UseAppPaths"]
    if v >= V(5, 0, 3):
        nm.append("FolderShortcut")
    if v >= V(5, 4, 2):
        nm.append("ExcludeFromShowInNewInstall")
    if v >= V(5, 5, 0):
        nm.append("PreventPinning")
    if v >= V(6, 1, 0):
        nm.append("HasAppUserModelToastActivatorCLSID")
    r.flags(nm)
    return e


def _parse_ini(r, v):
    e = {"file": r.s(), "section": r.s(), "key": r.s(), "value": r.s()}
    _conditions(r, v, e)
    _winver(r, v)
    r.flags(["CreateKeyIfDoesntExist", "UninsDeleteEntry", "UninsDeleteEntireSection",
             "UninsDeleteSectionIfEmpty", "HasValue"])
    return e


def _parse_registry(r, v):
    e = {"key": r.s(), "name": r.s()}
    e["value_raw"] = r.bstr()
    _conditions(r, v, e)
    if V(4, 0, 11) <= v < V(4, 1, 0):
        r.bstr()
    _winver(r, v)
    e["hive"] = r.u32() & 0x7FFFFFFF
    if v >= V(4, 1, 0):
        r.i16()
    e["type"] = r.u8() if v >= V(5, 2, 5) else None
    nm = ["CreateValueIfDoesntExist", "UninsDeleteValue", "UninsClearValue",
          "UninsDeleteEntireKey", "UninsDeleteEntireKeyIfEmpty", "PreserveStringType",
          "DeleteKey", "DeleteValue", "NoError", "DontCreateKey"]
    if v >= V(5, 1, 0):
        nm += ["Bits32", "Bits64"]
    r.flags(nm)
    if e["type"] in (1, 2) and r.unicode:  # string / expandstring
        try:
            e["value"] = e["value_raw"].decode("utf-16-le")
        except UnicodeDecodeError:
            e["value"] = None
    elif e["type"] in (1, 2):
        e["value"] = e["value_raw"].decode(r.ansi_cp, "replace")
    return e


DATA_FLAGS = None


def _data_flag_names(v):
    nm = ["VersionInfoValid", "VersionInfoNotValid"]
    if V(2, 0, 17) <= v < V(4, 0, 1):
        nm.append("BZipped")
    if v >= V(4, 0, 10):
        nm.append("TimeStampInUTC")
    if v >= V(4, 1, 0):
        nm.append("IsUninstallerExe")
    if v >= V(4, 1, 8):
        nm.append("CallInstructionOptimized")
    if v >= V(4, 2, 0):
        nm.append("Touch")
    if v >= V(4, 2, 2):
        nm.append("ChunkEncrypted")
    if v >= V(4, 2, 5):
        nm.append("ChunkCompressed")
    if v >= V(5, 1, 13):
        nm.append("SolidBreak")
    if V(5, 5, 7) <= v < V(6, 3, 0):
        nm += ["Sign", "SignOnce"]
    return nm


COMPRESSION_NAMES = {0: "stored", 1: "zlib", 2: "bzip2", 3: "lzma1", 4: "lzma2"}


def _header_compression(v, c):
    if v >= V(5, 3, 9):
        return COMPRESSION_NAMES.get(c, "unknown%d" % c)
    if v >= V(4, 2, 6):  # stored, zlib, bzip2, lzma
        return {0: "stored", 1: "zlib", 2: "bzip2", 3: "lzma1"}.get(c, "unknown%d" % c)
    if v >= V(4, 2, 5):  # zlib, bzip2, lzma (stored is a separate flag)
        return {0: "zlib", 1: "bzip2", 2: "lzma1"}.get(c, "unknown%d" % c)
    if v >= V(4, 1, 5):
        return {0: "zlib", 1: "bzip2", 2: "lzma1"}.get(c, "unknown%d" % c)
    return "zlib"


def _parse_data(r, v, setup):
    d = {}
    d["first_slice"] = r.u32()
    d["last_slice"] = r.u32()
    if v < V(4, 0, 0):
        d["first_slice"] -= 1
        d["last_slice"] -= 1
    d["chunk_offset"] = r.u32()
    d["file_offset"] = r.u64() if v >= V(4, 0, 1) else 0
    if v >= V(4, 0, 0):
        d["size"] = r.u64()
        d["chunk_size"] = r.u64()
    else:
        d["size"] = r.u32()
        d["chunk_size"] = r.u32()
    if v >= V(5, 3, 9):
        d["checksum_type"], d["checksum"] = "sha1", r.raw(20)
    elif v >= V(4, 2, 0):
        d["checksum_type"], d["checksum"] = "md5", r.raw(16)
    elif v >= V(4, 0, 1):
        d["checksum_type"], d["checksum"] = "crc32", r.raw(4)
    else:
        d["checksum_type"], d["checksum"] = "adler32", r.raw(4)
    d["filetime"] = r.i64()
    d["version_ms"] = r.u32()
    d["version_ls"] = r.u32()
    global DATA_FLAGS
    if DATA_FLAGS is None or DATA_FLAGS[0] != v:
        DATA_FLAGS = (v, _data_flag_names(v))
    opts = r.flags(DATA_FLAGS[1])
    if v < V(4, 2, 5):
        opts.add("ChunkCompressed")
    d["options"] = opts
    if "BZipped" in opts:
        comp = "bzip2"
    elif "ChunkCompressed" in opts:
        comp = setup.compression
    else:
        comp = "stored"
    d["compression"] = comp
    d["encrypted"] = "ChunkEncrypted" in opts
    if "CallInstructionOptimized" in opts:
        if v < V(5, 2, 0):
            d["filter"] = "x86_4108"
        elif v < V(5, 3, 9):
            d["filter"] = "x86_5200"
        else:
            d["filter"] = "x86_5309"
    else:
        d["filter"] = None
    return d


def vstr(v):
    return ".".join(str(x) for x in (v if v[3] else v[:3]))


def _load_list(r, v, n, fn, what):
    out = []
    for i in range(n):
        try:
            out.append(fn(r, v))
        except InnoError as ex:
            raise InnoError("failed parsing %s entry %d/%d: %s" % (what, i, n, ex))
    return out


def open_setup(path):
    if not os.path.isfile(path):
        raise Unsupported("no such file: %s" % path)
    f = open(path, "rb")
    try:
        o = find_offsets(f)
        if o is None:
            raise Unsupported("%s: not an Inno Setup installer (no setup loader offset table)" % path)
        f.seek(o.header_offset)
        vs_raw = f.read(64)
        vs = vs_raw.split(b"\0", 1)[0].decode("latin-1")
        v, unicode = parse_version(vs)
        if v is None or "Setup Data" not in vs:
            raise Unsupported("%s: unrecognised setup data version string %r" % (path, vs))
        if v < V(4, 0, 0):
            raise Unsupported("Inno Setup %s (< 4.0.0) is not supported" % vstr(v))
        if v >= V(6, 3, 0):
            raise Unsupported("Inno Setup %s (6.3+) header layout is not implemented" % vstr(v))
        tested = v[:3] in TESTED_VERSIONS
        s = Setup()
        s.path = path
        s.offsets = o
        s.version = v
        s.version_string = vs
        s.unicode = unicode
        s.tested = tested
        try:
            blk = read_block(f, v)
            r = Reader(memoryview(blk), unicode)
            h = _parse_header(r, v)
            s.header = h
            s.compression = _header_compression(v, h["compression"])
            s.languages = _load_list(r, v, h["language_count"], _parse_language, "language")
            _load_list(r, v, h["message_count"], _parse_message, "message")
            _load_list(r, v, h["permission_count"], _parse_permission, "permission")
            s.types = _load_list(r, v, h["type_count"], _parse_type, "type")
            s.components = _load_list(r, v, h["component_count"], _parse_component, "component")
            s.tasks = _load_list(r, v, h["task_count"], _parse_task, "task")
            s.directories = _load_list(r, v, h["directory_count"], _parse_directory, "directory")
            s.files = _load_list(r, v, h["file_count"], _parse_file, "file")
            # Entries after [Files] are only needed for the GOG id; tolerate failures.
            s.registry = []
            s.tail_error = None
            try:
                _load_list(r, v, h["icon_count"], _parse_icon, "icon")
                _load_list(r, v, h["ini_entry_count"], _parse_ini, "ini")
                s.registry = _load_list(r, v, h["registry_entry_count"], _parse_registry, "registry")
            except (InnoError, struct.error) as ex:
                s.tail_error = str(ex)
            blk2 = read_block(f, v)
            r2 = Reader(memoryview(blk2), unicode)
            s.data = [_parse_data(r2, v, s) for _ in range(h["data_entry_count"])]
            if r2.p != len(blk2):
                raise InnoError("data entry block has %d trailing bytes (layout mismatch)"
                                % (len(blk2) - r2.p))
            for i, fe in enumerate(s.files):
                loc = fe["location"]
                if loc != 0xFFFFFFFF and loc >= len(s.data) and not fe["source"]:
                    raise InnoError("file entry %d points at data entry %d of %d"
                                    % (i, loc, len(s.data)))
        except (InnoError, struct.error, lzma.LZMAError, zlib.error, UnicodeDecodeError) as ex:
            if isinstance(ex, Unsupported):
                raise
            if "CRC32" in str(ex) or tested:
                raise InnoError("%s: %s" % (path, ex))
            raise Unsupported("%s: setup data %s could not be parsed (untested version): %s"
                              % (path, vstr(v), ex))
        return s
    finally:
        f.close()


# ---------------------------------------------------------------------------
# Expressions (Languages / Components / Tasks conditions), innoextract-style
# ---------------------------------------------------------------------------

_TOK = re.compile(r"\s*(\(|\)|[^\s()]+)")


def expression_match(test, expr):
    """True if identifier `test` satisfies Inno boolean expression `expr`.
    Space-separated identifiers are an implicit 'or'. Empty expr matches."""
    if not expr.strip():
        return True
    toks = _TOK.findall(expr)
    pos = 0
    test_l = test.lower()

    def peek():
        return toks[pos].lower() if pos < len(toks) else None

    def p_or():
        nonlocal pos
        val = p_and()
        while True:
            t = peek()
            if t == "or":
                pos += 1
                val = p_and() or val
            elif t is not None and t not in (")", "and"):
                val = p_and() or val  # implicit or
            else:
                return val

    def p_and():
        nonlocal pos
        val = p_not()
        while peek() == "and":
            pos += 1
            val = p_not() and val
        return val

    def p_not():
        nonlocal pos
        t = peek()
        if t == "not":
            pos += 1
            return not p_not()
        if t == "(":
            pos += 1
            val = p_or()
            if peek() == ")":
                pos += 1
            return val
        if t is None:
            return False
        pos += 1
        return t == test_l

    try:
        return p_or()
    except IndexError:
        return False


# ---------------------------------------------------------------------------
# Path mapping (innoextract filename_map::convert, default settings)
# ---------------------------------------------------------------------------

_UNSAFE = set('<>:"|?*')


def _safe(s):
    return "".join("$" if (c in _UNSAFE or ord(c) < 32) else c for c in s)


CONST_MAP = {}  # innoextract default: every {const} expands to its own name


def _expand(path, i, close):
    out = []
    n = len(path)
    while i < n:
        j = i
        while j < n and path[j] not in "{}":
            j += 1
        out.append(path[i:j])
        i = j
        if i >= n:
            break
        c = path[i]
        i += 1
        if close and c == "}":
            return "".join(out), i
        if c == "}":
            out.append("}")
            continue
        if i < n and path[i] == "{":
            out.append("{")
            i += 1
            continue
        key, i = _expand(path, i, True)
        out.append(CONST_MAP[key] if key in CONST_MAP else _safe(key))
    return "".join(out), i


class PathEscape(InnoError):
    pass


def convert_path(dest):
    """Inno destination -> relative POSIX output path ('' = not extracted)."""
    expanded, _ = _expand(dest, 0, False)
    res = []
    for seg in re.split(r"[\\/]", expanded):
        if seg in ("", "."):
            continue
        if seg == "..":
            if not res:
                raise PathEscape("destination %r escapes the output directory" % dest)
            res.pop()
            continue
        res.append(seg)
    return "/".join(res)


# ---------------------------------------------------------------------------
# Slices / chunk streams
# ---------------------------------------------------------------------------

SLICE_MAGICS = (b"idska16\x1a", b"idska32\x1a")


class SliceSet:
    def __init__(self, setup):
        self.setup = setup
        self.data_offset = setup.offsets.data_offset
        self.f = None
        self.cur = None
        self.slice_end = None
        self.dir = os.path.dirname(os.path.abspath(setup.path))
        stem = os.path.splitext(os.path.basename(setup.path))[0]
        self.bases = [stem]
        bf = setup.header.get("base_filename") or ""
        if bf and bf not in self.bases:
            self.bases.append(bf)
        self.spd = setup.header.get("slices_per_disk") or 1

    def slice_names(self, idx):
        names = []
        for b in self.bases:
            if self.spd == 1:
                names.append("%s-%d.bin" % (b, idx + 1))
            else:
                names.append("%s-%d%s.bin" % (b, idx // self.spd + 1, chr(97 + idx % self.spd)))
        return names

    def slice_path(self, idx):
        for nm in self.slice_names(idx):
            p = os.path.join(self.dir, nm)
            if os.path.isfile(p):
                return p
        raise InnoError("missing disk slice %s next to %s"
                        % (" / ".join(self.slice_names(idx)), self.setup.path))

    def open(self, idx):
        if self.cur == idx and self.f:
            return
        if self.f:
            self.f.close()
        self.f = None
        if self.data_offset:
            if idx != 0:
                raise InnoError("single-file setup references slice %d" % idx)
            self.f = open(self.setup.path, "rb")
            self.slice_end = None
        else:
            p = self.slice_path(idx)
            f = open(p, "rb")
            magic = f.read(8)
            if magic[:4] == b"Rar!":
                f.close()
                raise Unsupported(RAR_MSG % p)
            if magic not in SLICE_MAGICS:
                f.close()
                raise InnoError("%s: bad slice signature %r" % (p, magic))
            size = struct.unpack("<I", f.read(4))[0]
            if size > os.path.getsize(p) or size < 12:
                f.close()
                raise InnoError("%s: bad slice size %d" % (p, size))
            self.f = f
            self.slice_end = size
        self.cur = idx

    def seek(self, idx, offset):
        self.open(idx)
        self.f.seek(self.data_offset + offset)

    def read(self, n):
        out = []
        while n > 0:
            if self.slice_end is None:
                b = self.f.read(n)
                if not b:
                    break
                out.append(b)
                n -= len(b)
                continue
            left = self.slice_end - self.f.tell()
            if left <= 0:
                self.open(self.cur + 1)
                self.f.seek(12)
                continue
            b = self.f.read(min(n, left))
            if not b:
                raise InnoError("unexpected end of slice %d" % self.cur)
            out.append(b)
            n -= len(b)
        return b"".join(out)

    def close(self):
        if self.f:
            self.f.close()
            self.f = None


RAR_MSG = ("%s is an old GOG RAR-based data part ('Rar!' signature). These are not "
           "supported by inno.py: install the game (e.g. with Wine) and use the "
           "installed game folder instead.")

CHUNK_MAGIC = b"zlb\x1a"
IN_BLOCK = 1 << 20
OUT_BLOCK = 4 << 20


def chunk_pieces(slices, d):
    """Generator of decompressed byte pieces of the chunk holding data entry `d`."""
    slices.seek(d["first_slice"], d["chunk_offset"])
    magic = slices.read(4)
    if magic != CHUNK_MAGIC:
        raise InnoError("bad chunk magic %r at slice %d offset 0x%x"
                        % (magic, d["first_slice"], d["chunk_offset"]))
    if d["encrypted"]:
        raise Unsupported("encrypted chunks are not supported")
    remaining = d["chunk_size"]

    def src(n):
        nonlocal remaining
        n = min(n, remaining)
        if n <= 0:
            return b""
        b = slices.read(n)
        if len(b) != n:
            raise InnoError("chunk data truncated")
        remaining -= n
        return b

    comp = d["compression"]
    if comp == "stored":
        while True:
            b = src(IN_BLOCK)
            if not b:
                return
            yield b
    if comp == "zlib":
        dec = zlib.decompressobj()
        pending = b""
        while not dec.eof:
            if not pending:
                pending = src(IN_BLOCK)
                if not pending:
                    tail = dec.flush()
                    if tail:
                        yield tail
                    return
            out = dec.decompress(pending, OUT_BLOCK)
            pending = dec.unconsumed_tail
            if out:
                yield out
        return
    if comp == "lzma1":
        dec = lzma1_decompressor(src(5))
    elif comp == "lzma2":
        dec = lzma2_decompressor(src(1)[0])
    elif comp == "bzip2":
        dec = bz2.BZ2Decompressor()
    else:
        raise Unsupported("unknown chunk compression %s" % comp)
    while not dec.eof:
        if dec.needs_input:
            data = src(IN_BLOCK)
            if not data:
                return
        else:
            data = b""
        try:
            out = dec.decompress(data, OUT_BLOCK)
        except (lzma.LZMAError, OSError, EOFError) as ex:
            raise InnoError("chunk decompression failed: %s" % ex)
        if out:
            yield out


class Cursor:
    def __init__(self, gen):
        self.gen = gen
        self.buf = b""
        self.bp = 0
        self.pos = 0

    def _fill(self):
        try:
            self.buf = next(self.gen)
        except StopIteration:
            raise InnoError("chunk ended early at decompressed offset %d" % self.pos)
        self.bp = 0

    def pieces(self, n):
        while n > 0:
            if self.bp >= len(self.buf):
                self._fill()
            take = min(n, len(self.buf) - self.bp)
            piece = self.buf[self.bp:self.bp + take] if (self.bp or take != len(self.buf)) else self.buf
            self.bp += take
            self.pos += take
            n -= take
            yield piece

    def skip(self, n):
        for _ in self.pieces(n):
            pass


# ---------------------------------------------------------------------------
# x86 call/jmp filters
# ---------------------------------------------------------------------------

_E8E9 = re.compile(b"[\xe8\xe9]")


def _x86_block_5200(buf, addr_offset, flip):
    """Decode one <=64KiB block in place (Inno TransformCallInstructions, Encode=False)."""
    size = len(buf) - 4
    if size <= 0:
        return
    i = 0
    search = _E8E9.search
    while True:
        m = search(buf, i, size)
        if m is None:
            return
        i = m.start() + 1
        if buf[i + 3] in (0, 0xFF):
            addr = (addr_offset + i + 4) & 0xFFFFFF
            rel = (buf[i] | buf[i + 1] << 8 | buf[i + 2] << 16) - addr
            rel &= 0xFFFFFF
            if flip and rel & 0x800000:
                buf[i + 3] ^= 0xFF
            buf[i] = rel & 0xFF
            buf[i + 1] = rel >> 8 & 0xFF
            buf[i + 2] = rel >> 16
        i += 4


class X86Filter5200:
    BLOCK = 0x10000

    def __init__(self, flip):
        self.flip = flip
        self.pending = bytearray()
        self.offset = 0

    def feed(self, data):
        self.pending += data
        n = len(self.pending) - len(self.pending) % self.BLOCK
        if not n:
            return b""
        out = self.pending[:n]
        del self.pending[:n]
        for s in range(0, n, self.BLOCK):
            blk = out[s:s + self.BLOCK]
            _x86_block_5200(blk, self.offset, self.flip)
            out[s:s + self.BLOCK] = blk
            self.offset = (self.offset + self.BLOCK) & 0xFFFFFFFF
        return bytes(out)

    def flush(self):
        out = self.pending
        self.pending = bytearray()
        _x86_block_5200(out, self.offset, self.flip)
        return bytes(out)


class X86Filter4108:
    def __init__(self):
        self.addr_offset = 5
        self.addr = 0
        self.left = 0

    def feed(self, data):
        buf = bytearray(data)
        n = len(buf)
        i = 0
        addr, left, off = self.addr, self.left, self.addr_offset
        while i < n:
            if left == 0:
                m = _E8E9.search(buf, i)
                if m is None:
                    off += n - i
                    i = n
                    break
                j = m.start()
                off += j - i
                addr = (-off) & 0xFFFFFFFF
                left = 4
                i = j + 1
                off += 1
            else:
                addr += buf[i]
                buf[i] = addr & 0xFF
                addr >>= 8
                left -= 1
                i += 1
                off += 1
        self.addr, self.left, self.addr_offset = addr, left, off & 0xFFFFFFFF
        return bytes(buf)

    def flush(self):
        return b""


def make_filter(name):
    if name is None:
        return None
    if name == "x86_4108":
        return X86Filter4108()
    return X86Filter5200(flip=(name == "x86_5309"))


class Checker:
    def __init__(self, ctype):
        self.ctype = ctype
        if ctype == "sha1":
            self.h = hashlib.sha1()
        elif ctype == "md5":
            self.h = hashlib.md5()
        elif ctype == "crc32":
            self.v = 0
        else:
            self.a, self.b = 1, 0

    def update(self, data):
        t = self.ctype
        if t in ("sha1", "md5"):
            self.h.update(data)
        elif t == "crc32":
            self.v = zlib.crc32(data, self.v)
        else:
            self.v = zlib.adler32(data, getattr(self, "v", 1))

    def digest(self):
        t = self.ctype
        if t in ("sha1", "md5"):
            return self.h.digest()
        if t == "crc32":
            return struct.pack("<I", self.v & 0xFFFFFFFF)
        return struct.pack("<I", getattr(self, "v", 1) & 0xFFFFFFFF)


def checksum_hex(d):
    if d["checksum_type"] in ("crc32", "adler32"):
        return "%08x" % struct.unpack("<I", d["checksum"])[0]
    return d["checksum"].hex()


# ---------------------------------------------------------------------------
# GOG Galaxy split files (innoextract --gog-galaxy semantics)
# ---------------------------------------------------------------------------
#
# GOG Galaxy-era installers store every game file as one or more zlib-compressed
# parts, each an Inno file entry with destination {tmp}\xx\yy\<md5>. The script
# calls attached to the entries describe how to reassemble them:
#   BeforeInstall: before_install[_dependency]('<file md5>', '<relative path>', <parts>)
#   AfterInstall:  after_install[_dependency]('<part md5>', <stored size>, <size>)
#   Check:         check_if_install('<lang>#<lang>#', '32#64#', '<dlc>')
# The reassembled file lands at <relative path> (relative to the output root, NOT
# under app/), exactly as innoextract does it.

def parse_function_call(code, name):
    """Parse `name(arg, 'str', ...)`; return list of argument strings or None."""
    if not code:
        return None
    m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", code)
    if not m or m.group(1) != name:
        return None
    i = m.end()
    n = len(code)
    args = []
    while True:
        while i < n and code[i] in " \t\r\n":
            i += 1
        if i >= n:
            return None
        if code[i] == ")" and not args:
            return args
        if code[i] in "'\"":
            q = code[i]
            i += 1
            buf = []
            while True:
                if i >= n:
                    return None
                if code[i] == q:
                    if i + 1 < n and code[i + 1] == q:
                        buf.append(q)
                        i += 2
                        continue
                    i += 1
                    break
                buf.append(code[i])
                i += 1
            args.append("".join(buf))
        else:
            j = i
            while j < n and code[j] not in ",) \t\r\n":
                j += 1
            args.append(code[i:j])
            i = j
        while i < n and code[i] in " \t\r\n":
            i += 1
        if i >= n:
            return None
        if code[i] == ",":
            i += 1
            continue
        if code[i] == ")":
            return args
        return None


def is_gog(setup):
    h = setup.header
    return ("gog.com" in h.get("app_publisher", "").lower()
            or any("www.gog.com" in h.get(k, "").lower()
                   for k in ("app_publisher_url", "app_support_url", "app_updates_url")))


class Part:
    __slots__ = ("loc", "kind", "md5", "size", "stored_size")

    def __init__(self, loc, kind, md5, size, stored_size):
        self.loc, self.kind, self.md5, self.size, self.stored_size = loc, kind, md5, size, stored_size


def effective_files(setup):
    """File entries after GOG Galaxy reassembly. Each item is a dict with
    destination, languages, components, tasks, options, parts (list of Part),
    md5 (whole-file MD5 for Galaxy files, else None), galaxy, arch."""
    out = []
    galaxy = is_gog(setup)
    cur = None
    remaining = 0
    for idx, fe in enumerate(setup.files):
        e = {"index": idx, "destination": fe["destination"], "languages": fe["languages"],
             "components": fe["components"], "tasks": fe["tasks"], "options": fe["options"],
             "parts": None, "md5": None, "galaxy": False, "arch": ""}
        start = part = chk = None
        if galaxy:
            start = (parse_function_call(fe["before_install"], "before_install")
                     or parse_function_call(fe["before_install"], "before_install_dependency"))
            part = (parse_function_call(fe["after_install"], "after_install")
                    or parse_function_call(fe["after_install"], "after_install_dependency"))
            chk = parse_function_call(fe["check"], "check_if_install")
        if chk:
            langs = [x for x in chk[0].split("#") if x] if len(chk) > 0 else []
            e["languages"] = " or ".join(langs)
            e["arch"] = chk[1] if len(chk) > 1 else ""
        has_data = fe["location"] < len(setup.data)
        if start:
            if remaining:
                raise InnoError("incomplete GOG Galaxy file %r (%d part(s) missing)"
                                % (cur["destination"], remaining))
            if len(start) < 3 or not re.match(r"^[0-9a-fA-F]{32}$", start[0]):
                raise InnoError("bad GOG Galaxy before_install arguments: %r"
                                % fe["before_install"])
            try:
                remaining = int(start[2])
            except ValueError:
                raise InnoError("bad GOG Galaxy part count in %r" % fe["before_install"])
            e["destination"] = start[1]
            e["md5"] = bytes.fromhex(start[0])
            e["parts"] = []
            e["galaxy"] = True
            cur = e
            out.append(e)
        if part:
            if not remaining or cur is None:
                raise InnoError("GOG Galaxy file part without a start entry: %r"
                                % fe["after_install"])
            if len(part) < 3 or not has_data:
                raise InnoError("bad GOG Galaxy after_install entry: %r" % fe["after_install"])
            try:
                usize, csize = int(part[2]), int(part[1])
            except ValueError:
                raise InnoError("bad GOG Galaxy part sizes in %r" % fe["after_install"])
            cur["parts"].append(Part(fe["location"], "galaxy", bytes.fromhex(part[0]),
                                     usize, csize))
            remaining -= 1
            if not remaining:
                cur = None
            continue
        if start:
            continue
        if not has_data:
            continue  # external file / [Files] entry without stored data
        d = setup.data[fe["location"]]
        e["parts"] = [Part(fe["location"], "raw", None, d["size"], d["size"])]
        out.append(e)
    if remaining:
        raise InnoError("incomplete GOG Galaxy file %r (%d part(s) missing)"
                        % (cur["destination"], remaining))
    return out


def galaxy_languages(setup):
    langs = []
    for e in effective_files(setup):
        if e["galaxy"] or e["arch"]:
            for l in re.split(r"\s+or\s+", e["languages"]):
                if l and l not in langs:
                    langs.append(l)
    return langs


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

def gog_game_id(setup):
    pref = "software\\gog.com\\games\\"
    gid = ""
    for e in setup.registry:
        key = e["key"]
        if not key.lower().startswith(pref):
            continue
        if "\\" in key[len(pref):]:
            continue
        if e["name"].lower() == "gameid" and e.get("value"):
            return e["value"]
        if not gid:
            gid = key[len(pref):]
    if gid:
        return gid
    for fe in setup.files:
        for s in (fe["destination"], fe["before_install"]):
            m = re.search(r"goggame-(\d+)\.info\b", s, re.I)
            if m:
                return m.group(1)
    return ""


def rar_parts(setup):
    d = os.path.dirname(os.path.abspath(setup.path))
    stems = [os.path.splitext(os.path.basename(setup.path))[0]]
    bf = setup.header.get("base_filename")
    if bf and bf not in stems:
        stems.append(bf)
    out = []
    for stem in stems:
        i = 1
        while True:
            p = os.path.join(d, "%s-%d.bin" % (stem, i))
            if not os.path.isfile(p):
                break
            with open(p, "rb") as f:
                if f.read(4) == b"Rar!":
                    out.append(p)
            i += 1
    return out


class Target:
    """One output file (possibly several identical paths)."""

    def __init__(self, e, path):
        self.entries = [e]
        self.paths = [path]
        self.parts = e["parts"]
        self.md5 = e["md5"]
        self.size = sum(p.size for p in self.parts)
        self.offsets = []
        o = 0
        for p in self.parts:
            self.offsets.append(o)
            o += p.size
        self.fh = None
        self.tmp = None
        self.written = [0] * len(self.parts)
        self.done = set()
        self.next_part = 0
        self.pending = {}
        self.hasher = hashlib.md5() if self.md5 is not None else None
        self.mtime = None

    def key(self):
        return (tuple((p.loc, p.kind) for p in self.parts), self.md5)


def plan(setup, include_temp=False, language=None):
    """innoextract-style selection. Returns list of (effective entry, rel path)."""
    sel = []
    for e in effective_files(setup):
        if not include_temp and "DeleteAfterInstall" in e["options"]:
            continue
        if language and not expression_match(language, e["languages"]):
            continue
        path = convert_path(e["destination"])
        if not path:
            continue
        sel.append((e, path))
    return sel


def plan_dirs(setup, include_temp=False, language=None):
    out = []
    for de in setup.directories:
        if not include_temp and "DeleteAfterInstall" in de["options"]:
            continue
        if language and not expression_match(language, de["languages"]):
            continue
        p = convert_path(de["name"])
        if p:
            out.append(p)
    return out


def build_targets(entries, mode):
    """Group identical content into Targets and resolve path collisions
    (case-insensitive, as on Windows / default macOS volumes)."""
    by_path = {}
    order = []
    for e, path in entries:
        key = path.lower()
        if key in by_path:
            if mode == "error":
                raise InnoError("collision: %s (entries %r and %r)"
                                % (path, by_path[key][0]["destination"], e["destination"]))
            if mode == "rename":
                k = 1
                while ("%s$%d" % (path, k)).lower() in by_path:
                    k += 1
                path = "%s$%d" % (path, k)
                key = path.lower()
                order.append(key)
            # overwrite: the later entry wins (Inno installs entries in order)
        else:
            order.append(key)
        by_path[key] = (e, path)
    targets = {}
    tlist = []
    for key in order:
        e, path = by_path[key]
        t = Target(e, path)
        k = t.key()
        if k in targets:
            targets[k].paths.append(path)
            targets[k].entries.append(e)
        else:
            targets[k] = t
            tlist.append(t)
    return tlist


def filetime_to_unix(ft):
    return ft / 1e7 - 11644473600.0


# ---------------------------------------------------------------------------
# Extraction engine
# ---------------------------------------------------------------------------

def _safe_join(root, rel):
    full = os.path.normpath(os.path.join(root, *rel.split("/")))
    if os.path.commonpath([root, full]) != root or full == root:
        raise PathEscape("refusing path outside output dir: %s" % rel)
    cur = root
    for seg in rel.split("/")[:-1]:
        cur = os.path.join(cur, seg)
        if os.path.islink(cur):
            raise PathEscape("refusing to write through symlink %s" % cur)
    return full


_ZLIB_HDR_OK = lambda b: len(b) >= 2 and (b[0] & 0x0F) == 8 and (b[0] << 8 | b[1]) % 31 == 0


class Engine:
    def __init__(self, setup, targets, out_dir=None, set_mtime=True, verify_all=False,
                 progress=None):
        self.s = setup
        self.targets = targets
        self.out_dir = out_dir
        self.set_mtime = set_mtime
        self.verify_all = verify_all
        self.progress = progress
        self.uses = {}
        for t in targets:
            if out_dir is not None:
                t.full = [_safe_join(out_dir, p) for p in t.paths]
            if t.parts:  # innoextract leaves the timestamp of the last part written
                d = setup.data[t.parts[-1].loc]
                t.mtime = filetime_to_unix(d["filetime"])
            for k, p in enumerate(t.parts):
                self.uses.setdefault(p.loc, []).append((t, k))
        self.open_targets = set()
        self.stats = {"data_entries_verified": 0, "galaxy_parts_verified": 0,
                      "galaxy_files_verified": 0, "files_written": 0, "bytes_written": 0}

    # -- target output --------------------------------------------------
    def _write(self, t, k, data):
        if not data:
            return
        if self.out_dir is not None:
            if t.fh is None:
                t.tmp = t.full[0] + ".inno-partial"
                os.makedirs(os.path.dirname(t.tmp), exist_ok=True)
                t.fh = open(t.tmp, "wb")
                self.open_targets.add(t)
            t.fh.seek(t.offsets[k] + t.written[k])
            t.fh.write(data)
        t.written[k] += len(data)
        if t.hasher is not None:
            if k == t.next_part:
                t.hasher.update(data)
            else:
                t.pending.setdefault(k, []).append(bytes(data))

    def _part_done(self, t, k):
        if t.written[k] != t.parts[k].size:
            raise InnoError("%s: part %d produced %d bytes, expected %d"
                            % (t.paths[0], k, t.written[k], t.parts[k].size))
        t.done.add(k)
        while t.next_part in t.done:
            t.next_part += 1
            if t.hasher is not None:
                for b in t.pending.pop(t.next_part, ()):
                    t.hasher.update(b)
        if len(t.done) == len(t.parts):
            self._finish(t)

    def _finish(self, t):
        if t.hasher is not None:
            got = t.hasher.digest()
            if got != t.md5:
                raise InnoError("MD5 mismatch for reassembled GOG file %s: expected %s, got %s"
                                % (t.paths[0], t.md5.hex(), got.hex()))
            self.stats["galaxy_files_verified"] += 1
        if self.out_dir is None:
            return
        if t.fh is None:  # empty file
            t.tmp = t.full[0] + ".inno-partial"
            os.makedirs(os.path.dirname(t.tmp), exist_ok=True)
            t.fh = open(t.tmp, "wb")
            self.open_targets.add(t)
        t.fh.close()
        t.fh = None
        for p in t.full[1:]:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            shutil.copyfile(t.tmp, p + ".inno-partial")
            os.replace(p + ".inno-partial", p)
        os.replace(t.tmp, t.full[0])
        self.open_targets.discard(t)
        if self.set_mtime and t.mtime is not None:
            for p in t.full:
                try:
                    os.utime(p, (t.mtime, t.mtime))
                except (OSError, OverflowError, ValueError):
                    pass
        self.stats["files_written"] += len(t.full)
        self.stats["bytes_written"] += t.size * len(t.full)

    def abort(self):
        for t in list(self.open_targets):
            try:
                if t.fh:
                    t.fh.close()
                os.unlink(t.tmp)
            except OSError:
                pass
        self.open_targets.clear()

    # -- data entry processing ------------------------------------------
    def _process(self, idx, pieces):
        d = self.s.data[idx]
        uses = self.uses.get(idx, ())
        raw_uses = [u for u in uses if u[0].parts[u[1]].kind == "raw"]
        gal_uses = [u for u in uses if u[0].parts[u[1]].kind == "galaxy"]
        chk = Checker(d["checksum_type"])
        flt = make_filter(d["filter"])
        dec = None
        dmd5 = hashlib.md5() if gal_uses else None
        first = True
        gout = 0

        def emit(piece):
            nonlocal dec, first, gout
            chk.update(piece)
            for t, k in raw_uses:
                self._write(t, k, piece)
            if gal_uses:
                if first:
                    first = False
                    p0 = gal_uses[0][0].parts[gal_uses[0][1]]
                    if p0.stored_size == p0.size and not _ZLIB_HDR_OK(piece):
                        dec = False  # stored part
                    else:
                        dec = zlib.decompressobj()
                if dec is False:
                    out = piece
                else:
                    try:
                        out = dec.decompress(piece)
                    except zlib.error as ex:
                        raise InnoError("GOG part zlib error (data entry %d): %s" % (idx, ex))
                if out:
                    dmd5.update(out)
                    gout += len(out)
                    for t, k in gal_uses:
                        self._write(t, k, out)

        for piece in pieces:
            if flt:
                piece = flt.feed(piece)
            if piece:
                emit(piece)
        if flt:
            tail = flt.flush()
            if tail:
                emit(tail)
        got = chk.digest()
        if got != d["checksum"]:
            raise InnoError("%s checksum mismatch for data entry %d (%s): stored %s, computed %s"
                            % (d["checksum_type"].upper(), idx, describe_data(self.s, idx),
                               checksum_hex(d), got.hex()))
        self.stats["data_entries_verified"] += 1
        if gal_uses:
            if dec is None:  # empty stored data
                pass
            elif dec is not False:
                out = dec.flush()
                if out:
                    dmd5.update(out)
                    gout += len(out)
                    for t, k in gal_uses:
                        self._write(t, k, out)
                if not dec.eof:
                    raise InnoError("GOG part zlib stream truncated (data entry %d)" % idx)
            pm = dmd5.digest()
            for t, k in gal_uses:
                p = t.parts[k]
                if pm != p.md5 or gout != p.size:
                    raise InnoError("GOG part MD5/size mismatch for %s part %d: expected %s/%d, "
                                    "got %s/%d" % (t.paths[0], k, p.md5.hex(), p.size,
                                                   pm.hex(), gout))
            self.stats["galaxy_parts_verified"] += 1
        for t, k in uses:
            self._part_done(t, k)
        if self.progress:
            self.progress(idx, d)

    def run(self):
        s = self.s
        try:
            for t in self.targets:
                if not t.parts:
                    self._finish(t)
            wanted = set(range(len(s.data))) if self.verify_all else set(self.uses)
            chunks = {}
            for idx in wanted:
                d = s.data[idx]
                if d["size"] == 0 and d["chunk_size"] == 0:
                    self._process(idx, ())
                    continue
                chunks.setdefault((d["first_slice"], d["chunk_offset"]), []).append(idx)
            slices = SliceSet(s)
            try:
                for key in sorted(chunks):
                    idxs = sorted(chunks[key], key=lambda i: (s.data[i]["file_offset"], i))
                    d0 = s.data[idxs[0]]
                    if d0["encrypted"]:
                        raise Unsupported("data entry %d is in an encrypted chunk; encrypted "
                                          "installers are not supported" % idxs[0])
                    cur = None
                    for idx in idxs:
                        d = s.data[idx]
                        if d["size"] == 0:
                            self._process(idx, ())
                            continue
                        if cur is None or d["file_offset"] < cur.pos:
                            cur = Cursor(chunk_pieces(slices, d0))
                        cur.skip(d["file_offset"] - cur.pos)
                        self._process(idx, cur.pieces(d["size"]))
            finally:
                slices.close()
            left = [t for t in self.targets if len(t.done) != len(t.parts)]
            if left:
                raise InnoError("%d output files were not completed (e.g. %s)"
                                % (len(left), left[0].paths[0]))
        except BaseException:
            self.abort()
            raise
        return self.stats


def describe_data(setup, idx):
    for fe in setup.files:
        if fe["location"] == idx:
            return fe["destination"]
    return "?"


def preflight(setup):
    rars = rar_parts(setup)
    if rars:
        raise Unsupported(RAR_MSG % rars[0])
    if any(d["encrypted"] for d in setup.data):
        raise Unsupported("installer uses encrypted chunks (password protected); not supported")


def do_extract(setup, out_dir, language=None, include_temp=False, collisions="overwrite",
               set_mtime=True, quiet=False):
    preflight(setup)
    out_dir = os.path.realpath(out_dir)
    targets = build_targets(plan(setup, include_temp, language), collisions)
    dirs = plan_dirs(setup, include_temp, language)
    for p in dirs:
        _safe_join(out_dir, p + "/x")
    total = sum(t.size for t in targets)
    done = [0, 0]
    t0 = time.time()
    ndata = len({p.loc for t in targets for p in t.parts})

    def progress(idx, d):
        done[0] += d["size"]
        done[1] += 1
        if not quiet and done[1] % 1000 == 0:
            sys.stderr.write("  %d/%d data entries, %.0fs\n" % (done[1], ndata, time.time() - t0))

    eng = Engine(setup, targets, out_dir=out_dir, set_mtime=set_mtime, progress=progress)
    os.makedirs(out_dir, exist_ok=True)
    for p in dirs:
        os.makedirs(os.path.join(out_dir, *p.split("/")), exist_ok=True)
    st = eng.run()
    st["dirs_created"] = len(dirs)
    st["seconds"] = round(time.time() - t0, 2)
    return st


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def info_dict(setup):
    h = setup.header
    o = setup.offsets
    sl = 0
    if setup.data:
        sl = max(d["last_slice"] for d in setup.data) + 1
    ss = SliceSet(setup)
    if o.data_offset:
        parts = []
        layout = "embedded in exe (data offset 0x%x)" % o.data_offset
    else:
        parts = [ss.slice_names(i)[0] for i in range(sl)]
        layout = "external disk slices"
    comps = sorted({d["compression"] for d in setup.data})
    filters = sorted({d["filter"] for d in setup.data if d["filter"]})
    eff = effective_files(setup)
    sel = plan(setup)
    return {
        "inno_version": vstr(setup.version),
        "version_string": setup.version_string,
        "unicode": setup.unicode,
        "tested_version": setup.tested,
        "app_name": h["app_name"],
        "app_version": h["app_version"],
        "app_versioned_name": h["app_versioned_name"],
        "app_publisher": h["app_publisher"],
        "app_id": h["app_id"],
        "default_dir_name": h["default_dir_name"],
        "gog_game_id": gog_game_id(setup),
        "languages": [{"name": l["name"], "language_name": l["language_name"],
                       "id": l["language_id"]} for l in setup.languages],
        "gog_languages": galaxy_languages(setup),
        "components": [{"name": c["name"], "description": c["description"]}
                       for c in setup.components],
        "types": [t["name"] for t in setup.types],
        "tasks": [t["name"] for t in setup.tasks],
        "inno_file_entries": len(setup.files),
        "data_entries": len(setup.data),
        "gog_galaxy_files": sum(1 for e in eff if e["galaxy"]),
        "gog_galaxy_parts": sum(len(e["parts"]) for e in eff if e["galaxy"]),
        "files_to_extract": len(sel),
        "bytes_to_extract": sum(sum(p.size for p in e["parts"]) for e, _ in sel),
        "temp_files": sum(1 for e in eff if "DeleteAfterInstall" in e["options"]),
        "directories": len(setup.directories),
        "compression": comps,
        "x86_filters": filters,
        "encrypted": any(d["encrypted"] for d in setup.data),
        "data_layout": layout,
        "slices_needed": parts,
        "slices_per_disk": h["slices_per_disk"],
        "rar_parts": rar_parts(setup),
        "unparsed_tail": setup.tail_error,
    }


def cmd_info(a):
    s = open_setup(a.setup)
    d = info_dict(s)
    if a.json:
        print(json.dumps(d, indent=2, ensure_ascii=False))
        return EXIT_OK
    print("Inno Setup data %s (%s)%s" % (d["inno_version"], "unicode" if d["unicode"] else "ANSI",
                                         "" if d["tested_version"] else "  [UNTESTED version]"))
    print("App: %s  version %s  (%s)" % (d["app_name"], d["app_version"] or "?",
                                        d["app_versioned_name"]))
    if d["gog_game_id"]:
        print("GOG.com game ID: %s" % d["gog_game_id"])
    print("Inno languages: %s" % ", ".join("%s (%s)" % (l["name"], l["language_name"])
                                           for l in d["languages"]))
    if d["gog_languages"]:
        print("GOG file languages: %s" % ", ".join(d["gog_languages"]))
    if d["components"]:
        print("Components: %s" % ", ".join(c["name"] for c in d["components"]))
    print("Inno file entries: %d, data entries: %d, [Dirs] entries: %d"
          % (d["inno_file_entries"], d["data_entries"], d["directories"]))
    if d["gog_galaxy_files"]:
        print("GOG Galaxy split files: %d (from %d parts), reassembled on extraction"
              % (d["gog_galaxy_files"], d["gog_galaxy_parts"]))
    print("Files to extract: %d (%d bytes), temp files skipped: %d"
          % (d["files_to_extract"], d["bytes_to_extract"], d["temp_files"]))
    print("Compression: %s; x86 filter: %s; encrypted: %s" % (
        ",".join(d["compression"]) or "-", ",".join(d["x86_filters"]) or "none",
        d["encrypted"]))
    print("Data: %s" % d["data_layout"])
    if d["slices_needed"]:
        print("Slices needed: %s" % ", ".join(d["slices_needed"]))
    if d["rar_parts"]:
        print("UNSUPPORTED: GOG RAR data parts present: %s" % ", ".join(d["rar_parts"]))
    return EXIT_OK


def cmd_list(a):
    s = open_setup(a.setup)
    rows = []
    for e, path in plan(s, a.include_temp, a.language):
        if e["galaxy"]:
            ctype, csum = "md5", e["md5"].hex()
        else:
            d = s.data[e["parts"][0].loc]
            ctype, csum = d["checksum_type"], checksum_hex(d)
        rows.append({"path": path, "destination": e["destination"],
                     "size": sum(p.size for p in e["parts"]),
                     "checksum_type": ctype, "checksum": csum,
                     "languages": e["languages"], "components": e["components"],
                     "tasks": e["tasks"], "temp": "DeleteAfterInstall" in e["options"],
                     "gog_galaxy_parts": len(e["parts"]) if e["galaxy"] else 0,
                     "data_entries": [p.loc for p in e["parts"]]})
    if a.json:
        print(json.dumps(rows, indent=1, ensure_ascii=False))
        return EXIT_OK
    for r in rows:
        cond = []
        if r["languages"]:
            cond.append("lang=" + r["languages"])
        if r["components"]:
            cond.append("comp=" + r["components"])
        if r["tasks"]:
            cond.append("task=" + r["tasks"])
        if r["temp"]:
            cond.append("temp")
        if r["gog_galaxy_parts"]:
            cond.append("galaxy parts=%d" % r["gog_galaxy_parts"])
        print("%12d  %s:%s  %s%s" % (r["size"], r["checksum_type"], r["checksum"], r["path"],
                                     ("  [" + "; ".join(cond) + "]") if cond else ""))
    print("%d files, %d bytes" % (len(rows), sum(r["size"] for r in rows)), file=sys.stderr)
    return EXIT_OK


def cmd_extract(a):
    s = open_setup(a.setup)
    if not s.tested and not a.quiet:
        sys.stderr.write("warning: Inno Setup %s is not a tested version\n" % vstr(s.version))
    res = do_extract(s, a.out_dir, language=a.language, include_temp=a.include_temp,
                     collisions=a.collisions, set_mtime=not a.no_mtime, quiet=a.quiet)
    res["out_dir"] = os.path.realpath(a.out_dir)
    res["inno_version"] = vstr(s.version)
    res["app_name"] = s.header["app_name"]
    res["gog_game_id"] = gog_game_id(s)
    print(json.dumps(res, indent=2))
    return EXIT_OK


def cmd_verify(a):
    s = open_setup(a.setup)
    preflight(s)
    t0 = time.time()
    targets = build_targets(plan(s, include_temp=True), "rename")
    st = Engine(s, targets, out_dir=None, verify_all=True).run()
    st.pop("files_written")
    st.pop("bytes_written")
    st["data_entries"] = len(s.data)
    st["seconds"] = round(time.time() - t0, 2)
    print(json.dumps(st, indent=2))
    return EXIT_OK if st["data_entries_verified"] == len(s.data) else EXIT_FAIL


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write("inno.py: error: %s\n" % message)
        sys.exit(EXIT_UNSUPPORTED)


def main(argv=None):
    ap = _Parser(prog="inno.py", description="Pure-Python GOG Inno Setup extractor")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("info")
    p.add_argument("setup")
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("list")
    p.add_argument("setup")
    p.add_argument("--json", action="store_true")
    p.add_argument("--include-temp", action="store_true")
    p.add_argument("--exclude-temp", dest="include_temp", action="store_false")
    p.add_argument("--language")
    p = sub.add_parser("extract")
    p.add_argument("setup")
    p.add_argument("out_dir")
    p.add_argument("--language")
    p.add_argument("--include-temp", action="store_true")
    p.add_argument("--exclude-temp", dest="include_temp", action="store_false")
    p.add_argument("--collisions", choices=["overwrite", "error", "rename"], default="overwrite")
    p.add_argument("--no-mtime", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p = sub.add_parser("verify")
    p.add_argument("setup")
    for sp in sub.choices.values():
        sp.error = ap.error
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help(sys.stderr)
        return EXIT_UNSUPPORTED
    try:
        return {"info": cmd_info, "list": cmd_list, "extract": cmd_extract,
                "verify": cmd_verify}[a.cmd](a)
    except InnoError as ex:
        sys.stderr.write("inno.py: %s%s\n" % ("unsupported: " if ex.exit_code == EXIT_UNSUPPORTED
                                              else "error: ", ex))
        return ex.exit_code
    except OSError as ex:
        sys.stderr.write("inno.py: I/O error: %s\n" % ex)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())

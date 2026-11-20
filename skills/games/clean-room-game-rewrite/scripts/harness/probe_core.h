/* probe_core.h - the game-independent half of the PROBE: a proxy DLL that records the original game's
 * behaviour (scripted input in, per-frame trace out) without changing any of the game's files
 * (references/harness.md, "1. The oracle").
 *
 * How the probe is loaded: in the oracle's own copy of the game folder (never the user's install), a DLL the
 * game imports by name (SDL2.dll, d3d9.dll, dinput8.dll, winmm.dll, ...) is renamed to <name>_orig.dll and
 * the probe takes its place. `wintools.py proxy <dll> <name>_orig --hook A,B <out.def>` writes the probe's
 * .def: every export forwarded to the original, except the hooked ones, which the probe defines. Under Wine,
 * set WINEDLLOVERRIDES="<name>=n,b" so the probe in the game folder wins over a built-in DLL.
 *
 * Use, in the probe's single .c file (game-specific: hook choice, addresses, trace fields):
 *   #define PROBE_ORIG_DLL "SDL2_orig.dll"
 *   #define PROBE_IMAGE_BASE 0x00400000           (the exe's preferred base, as in the Ghidra project)
 *   #define HARNESS_... names, #include "harness_core.h", then #include "probe_core.h"
 *
 *   probe_orig(name)             export of the original DLL (loaded on first use; NULL when missing)
 *   probe_addr(va)               an address from the analysis (preferred base) -> address in this process
 *   probe_read(va, dst, n)       copy n bytes of game memory at va; 0 when the range is not readable
 *   probe_patch_call(va, fn)     the 5-byte `call rel32` at va now calls fn; returns the old target (to chain
 *                                to), NULL when va does not hold E8 rel32
 *   probe_patch_jmp(va, fn, n)   `jmp rel32` to fn at va, the rest of n bytes (n >= 5) filled with NOP; for a
 *                                detour of a whole function whose first n bytes are whole instructions
 *   probe_log(fmt, ...)          one line to the file named by PROBE_LOG_ENV (default GAME_PROBE_LOG), if set
 *
 * Rules (the reasons are in harness.md):
 *   - Patch only the oracle's process, in memory, from DllMain(DLL_PROCESS_ATTACH) or the first hooked call;
 *     never write the exe or a DLL on disk, and never touch a protected or packed executable (the intake gate
 *     refuses those).
 *   - Hook as little as possible: input polling, the present/flip call and the clocks are usually enough;
 *     read the trace fields at the addresses the analysts documented.
 *   - Without the replay variable the probe forwards everything and the game plays as it always does.
 * x86 (32-bit) only. Written against the Windows SDK headers; C89 so an old compiler builds it too.
 */
#ifndef PROBE_CORE_H
#define PROBE_CORE_H

#include <windows.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#ifndef PROBE_ORIG_DLL
#error "define PROBE_ORIG_DLL (the renamed original DLL, e.g. \"SDL2_orig.dll\") before including probe_core.h"
#endif
#ifndef PROBE_IMAGE_BASE
#define PROBE_IMAGE_BASE 0x00400000u
#endif
#ifndef PROBE_LOG_ENV
#define PROBE_LOG_ENV "GAME_PROBE_LOG"
#endif

static HMODULE probe_orig_module;

static FARPROC probe_orig(const char *name)
{
    if (!probe_orig_module)
        probe_orig_module = LoadLibraryA(PROBE_ORIG_DLL);
    return probe_orig_module ? GetProcAddress(probe_orig_module, name) : NULL;
}

static unsigned char *probe_addr(unsigned int va)
{
    unsigned char *base = (unsigned char *)GetModuleHandleA(NULL);
    return base + (va - (unsigned int)PROBE_IMAGE_BASE);
}

static int probe_readable(const void *p, size_t n)
{
    MEMORY_BASIC_INFORMATION mbi;
    const unsigned char *q = (const unsigned char *)p;
    const unsigned char *end = q + n;
    while (q < end) {
        if (VirtualQuery(q, &mbi, sizeof mbi) == 0 || mbi.State != MEM_COMMIT ||
            (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
            return 0;
        q = (const unsigned char *)mbi.BaseAddress + mbi.RegionSize;
    }
    return 1;
}

static int probe_read(unsigned int va, void *dst, size_t n)
{
    const unsigned char *src = probe_addr(va);
    if (!probe_readable(src, n))
        return 0;
    memcpy(dst, src, n);
    return 1;
}

static int probe_write_code(unsigned char *at, const unsigned char *bytes, size_t n)
{
    DWORD old, tmp;
    if (!VirtualProtect(at, n, PAGE_EXECUTE_READWRITE, &old))
        return 0;
    memcpy(at, bytes, n);
    VirtualProtect(at, n, old, &tmp);
    FlushInstructionCache(GetCurrentProcess(), at, n);
    return 1;
}

static void *probe_patch_call(unsigned int va, void *fn)
{
    unsigned char *at = probe_addr(va);
    unsigned char code[5];
    int rel;
    void *old;
    if (!probe_readable(at, 5) || at[0] != 0xE8)
        return NULL;
    memcpy(&rel, at + 1, 4);
    old = at + 5 + rel;
    rel = (int)((unsigned char *)fn - (at + 5));
    code[0] = 0xE8;
    memcpy(code + 1, &rel, 4);
    return probe_write_code(at, code, 5) ? old : NULL;
}

static int probe_patch_jmp(unsigned int va, void *fn, size_t n)
{
    unsigned char *at = probe_addr(va);
    unsigned char code[32];
    int rel;
    if (n < 5 || n > sizeof code || !probe_readable(at, n))
        return 0;
    memset(code, 0x90, n);
    rel = (int)((unsigned char *)fn - (at + 5));
    code[0] = 0xE9;
    memcpy(code + 1, &rel, 4);
    return probe_write_code(at, code, n);
}

static void probe_log(const char *fmt, ...)
{
    static FILE *f;
    static int tried;
    va_list ap;
    if (!tried) {
        const char *p = getenv(PROBE_LOG_ENV);
        tried = 1;
        f = (p && *p) ? fopen(p, "a") : NULL;
    }
    if (!f)
        return;
    va_start(ap, fmt);
    vfprintf(f, fmt, ap);
    va_end(ap);
    fputc('\n', f);
    fflush(f);
}

#endif /* PROBE_CORE_H */

/* crt_shim.c - minimal stand-in for the MinGW startup/runtime pieces the i686-pc-windows-gnu Rust target
 * expects (we have no MinGW: no crt2.o runtime, libmingw32, libmingwex, libgcc, libgcc_eh).
 *
 * Built by build_libs.py with Apple clang (--target=i686-w64-windows-gnu, freestanding, no headers) into
 * libmingw32.a, which rustc already passes to the linker (-lmingw32), so nothing extra is needed on the
 * Rust command line. Provides:
 *   - mainCRTStartup / WinMainCRTStartup: run the .CRT$XI* and .CRT$XC* initialisers (std registers some
 *     there), call the C `main` that rustc generates (Rust's std reads the command line itself through
 *     GetCommandLineW, so argc/argv are passed as 0/NULL), run atexit handlers, ExitProcess.
 *   - the TLS directory (_tls_used, .tls, .CRT$XLA/.CRT$XLZ) so std's .CRT$XLB TLS callback
 *     (thread-local destructors) is called by the loader.
 *   - __main (no-op: no GCC constructors are used), atexit.
 *   - libgcc_eh stand-ins: __register_frame_info/__deregister_frame_info (no-ops, called by rsbegin.o)
 *     and the _Unwind_* entry points referenced by the prebuilt std. They abort: Rust code must be built
 *     with -C panic=abort, which never unwinds, so they are unreachable in practice.
 */

typedef unsigned int u32;
typedef void (*initfn)(void);
typedef void (__attribute__((stdcall)) *tlscb)(void *, u32, void *);

__attribute__((stdcall, dllimport)) void ExitProcess(u32 code);
extern int main(int argc, char **argv);

/* ---- C/C++-style initialiser tables; the linker sorts .CRT$X?? sections alphabetically ---------------- */
__attribute__((section(".CRT$XIA"), used)) static initfn xi_a = 0;
__attribute__((section(".CRT$XIZ"), used)) static initfn xi_z = 0;
__attribute__((section(".CRT$XCA"), used)) static initfn xc_a = 0;
__attribute__((section(".CRT$XCZ"), used)) static initfn xc_z = 0;

static void run_table(initfn *begin, initfn *end)
{
    /* hide the pointers' origin: begin/end are distinct objects as far as C is concerned */
    __asm__("" : "+r"(begin));
    __asm__("" : "+r"(end));
    for (initfn *p = begin + 1; p < end; ++p) {
        if (*p) (*p)();
    }
}

/* ---- TLS directory (same layout as MinGW's tlssup.c) -------------------------------------------------- */
u32 _tls_index = 0;
__attribute__((section(".tls"), used)) char _tls_start = 0;
__attribute__((section(".tls$ZZZ"), used)) char _tls_end = 0;
__attribute__((section(".CRT$XLA"), used)) tlscb __xl_a = 0;
__attribute__((section(".CRT$XLZ"), used)) tlscb __xl_z = 0;

typedef struct {
    u32 StartAddressOfRawData, EndAddressOfRawData, AddressOfIndex, AddressOfCallBacks;
    u32 SizeOfZeroFill, Characteristics;
} tls_directory;

__attribute__((section(".rdata$T"), used)) const tls_directory _tls_used = {
    (u32)&_tls_start, (u32)&_tls_end, (u32)&_tls_index, (u32)(&__xl_a + 1), 0, 0
};

/* ---- atexit -------------------------------------------------------------------------------------------- */
#define MAX_ATEXIT 64
static initfn atexit_fns[MAX_ATEXIT];
static int atexit_count;

int atexit(initfn fn)
{
    if (atexit_count >= MAX_ATEXIT) return -1;
    atexit_fns[atexit_count++] = fn;
    return 0;
}

void __main(void) {}

static void start(void)
{
    run_table(&xi_a, &xi_z);
    run_table(&xc_a, &xc_z);
    int rc = main(0, 0);
    while (atexit_count > 0) atexit_fns[--atexit_count]();
    ExitProcess((u32)rc);
}

void mainCRTStartup(void) { start(); }
void WinMainCRTStartup(void) { start(); }

/* ---- libgcc_eh stand-ins ------------------------------------------------------------------------------- */
void __register_frame_info(const void *eh_frame, void *object) { (void)eh_frame; (void)object; }
void *__deregister_frame_info(const void *eh_frame) { (void)eh_frame; return 0; }

#define UNWIND_STUB(name) void name(void) { __builtin_trap(); }
UNWIND_STUB(_Unwind_Resume)
UNWIND_STUB(_Unwind_RaiseException)
UNWIND_STUB(_Unwind_DeleteException)
UNWIND_STUB(_Unwind_Backtrace)
UNWIND_STUB(_Unwind_GetIP)
UNWIND_STUB(_Unwind_GetIPInfo)
UNWIND_STUB(_Unwind_GetCFA)
UNWIND_STUB(_Unwind_GetGR)
UNWIND_STUB(_Unwind_SetGR)
UNWIND_STUB(_Unwind_SetIP)
UNWIND_STUB(_Unwind_GetLanguageSpecificData)
UNWIND_STUB(_Unwind_GetRegionStart)
UNWIND_STUB(_Unwind_GetDataRelBase)
UNWIND_STUB(_Unwind_GetTextRelBase)
UNWIND_STUB(_Unwind_FindEnclosingFunction)

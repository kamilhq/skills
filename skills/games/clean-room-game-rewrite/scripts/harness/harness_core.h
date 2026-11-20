/* harness_core.h - the game-independent half of the differential-test hooks (references/harness.md).
 *
 * Include it in ONE translation unit of the probe (with probe_core.h) or of a C/C++ rewrite, after defining
 * the game's names (all optional, defaults below):
 *   HARNESS_ENV_REPLAY "GAME_REPLAY"   HARNESS_ENV_TRACE "GAME_TRACE"
 *   HARNESS_ENV_EXIT   "GAME_EXIT_FRAME"   HARNESS_ENV_FB "GAME_TRACE_FB"
 *   HARNESS_REPLAY_HEADER "GAME-REPLAY 1"   HARNESS_TRACE_HEADER "GAME-TRACE 1"
 *   HARNESS_KEYS_VK      key names map to Windows virtual-key codes (default: SDL2 keycodes)
 *   HARNESS_IO_CUSTOM    the unit provides harness_io_open/read/write/close and harness_getenv itself (e.g.
 *                        a probe that must not depend on the CRT can use the game's own library calls)
 * The game-specific half (which fields, where the hooks are called, how held keys reach the game's input
 * state) stays in the game's own hook file. The calls, in the order of one logic frame:
 *   after every input poll:  n = harness_held(codes, HARNESS_MAX_HELD); overwrite the game's key state
 *   end of logic frame:      if (harness_tracing()) { harness_line_begin(); harness_put("f=%d ...", ...);
 *                            ... } harness_frame_done();
 *   after the frame's render/present: if (harness_end_of_render(rgb_hash_or_minus)) <quit like the game>
 * harness_replay_on() tells the main loop to run one fixed step per render, without interpolation.
 * Every entry point is HARNESS_NOINLINE, so a hook patched into the original's code stays one call.
 */
#ifndef HARNESS_CORE_H
#define HARNESS_CORE_H

#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#ifndef HARNESS_ENV_REPLAY
#define HARNESS_ENV_REPLAY "GAME_REPLAY"
#endif
#ifndef HARNESS_ENV_TRACE
#define HARNESS_ENV_TRACE "GAME_TRACE"
#endif
#ifndef HARNESS_ENV_EXIT
#define HARNESS_ENV_EXIT "GAME_EXIT_FRAME"
#endif
#ifndef HARNESS_ENV_FB
#define HARNESS_ENV_FB "GAME_TRACE_FB"
#endif
#ifndef HARNESS_REPLAY_HEADER
#define HARNESS_REPLAY_HEADER "GAME-REPLAY 1"
#endif
#ifndef HARNESS_TRACE_HEADER
#define HARNESS_TRACE_HEADER "GAME-TRACE 1"
#endif
#define HARNESS_MAX_HELD 16
#define HARNESS_LINE 8192

#if defined(_MSC_VER)
#define HARNESS_NOINLINE __declspec(noinline)
#else
#define HARNESS_NOINLINE __attribute__((noinline))
#endif

#if defined(_MSC_VER) && _MSC_VER < 1900
#define HARNESS_VSNPRINTF _vsnprintf          /* VS2010: no C99 vsnprintf; terminated by hand below */
#else
#include <stdio.h>
#define HARNESS_VSNPRINTF vsnprintf
#endif

/* ------------------------------------------------------------------------------------------------ I/O */
#ifndef HARNESS_IO_CUSTOM
#include <stdio.h>
typedef FILE harness_file;
static harness_file *harness_io_open(const char *path, const char *mode) { return fopen(path, mode); }
static size_t harness_io_read(harness_file *f, void *buf, size_t n) { return fread(buf, 1, n, f); }
static size_t harness_io_write(harness_file *f, const void *buf, size_t n) { return fwrite(buf, 1, n, f); }
static void harness_io_close(harness_file *f) { fclose(f); }
static const char *harness_getenv(const char *name) { return getenv(name); }
#endif

/* ------------------------------------------------------------------------------------- FNV-1a 32 bit */
static unsigned int harness_fnv(unsigned int h, const void *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    size_t i;
    for (i = 0; i < len; i++) {
        h ^= p[i];
        h *= 16777619u;
    }
    return h;
}
#define HARNESS_FNV_INIT 2166136261u

static unsigned int harness_fnv_i32(unsigned int h, int v)    /* 4 bytes, little-endian */
{
    unsigned char b[4];
    b[0] = (unsigned char)(v & 0xff);
    b[1] = (unsigned char)((v >> 8) & 0xff);
    b[2] = (unsigned char)((v >> 16) & 0xff);
    b[3] = (unsigned char)((v >> 24) & 0xff);
    return harness_fnv(h, b, 4);
}

static unsigned int harness_float_bits(float f)               /* print with %08x: exact, no rounding */
{
    union { float f; unsigned int u; } x;
    x.f = f;
    return x.u;
}

/* Hash of a framebuffer: bytes R, G, B of every pixel, row by row (alpha never). bgra = 1 for 32-bit
 * little-endian ARGB8888 / D3DFMT_X8R8G8B8 (bytes B G R A), 0 for bytes R G B A. */
static unsigned int harness_fb_hash(const unsigned char *pixels, int w, int h, int pitch, int bgra)
{
    unsigned int fh = HARNESS_FNV_INIT;
    int x, y;
    for (y = 0; y < h; y++) {
        const unsigned char *row = pixels + (size_t)y * (size_t)pitch;
        for (x = 0; x < w; x++) {
            unsigned char rgb[3];
            const unsigned char *px = row + x * 4;
            rgb[0] = bgra ? px[2] : px[0];
            rgb[1] = px[1];
            rgb[2] = bgra ? px[0] : px[2];
            fh = harness_fnv(fh, rgb, 3);
        }
    }
    return fh;
}

/* ------------------------------------------------------------------------------------------ key names */
struct harness_keyname { const char *name; int code; };

#ifdef HARNESS_KEYS_VK
static const struct harness_keyname harness_keynames[] = {
    {"left", 0x25}, {"up", 0x26}, {"right", 0x27}, {"down", 0x28}, {"enter", 0x0d}, {"escape", 0x1b},
    {"space", 0x20}, {"tab", 0x09}, {"backspace", 0x08}, {"delete", 0x2e}, {"kpenter", 0x0d},
    {"lshift", 0xa0}, {"rshift", 0xa1}, {"lctrl", 0xa2}, {"rctrl", 0xa3}, {"lalt", 0xa4}, {"ralt", 0xa5},
    {"f1", 0x70}, {"f2", 0x71}, {"f3", 0x72}, {"f4", 0x73}, {"f5", 0x74}, {"f6", 0x75}, {"f7", 0x76},
    {"f8", 0x77}, {"f9", 0x78}, {"f10", 0x79}, {"f11", 0x7a}, {"f12", 0x7b},
    {"comma", 0xbc}, {"period", 0xbe}, {"slash", 0xbf}, {"minus", 0xbd}, {"equals", 0xbb},
};
#define HARNESS_LETTER(c) ((c) - 'a' + 'A')       /* VK_A.. = 'A'.., VK_0.. = '0'.. */
#else
static const struct harness_keyname harness_keynames[] = {
    {"left", 0x40000050}, {"right", 0x4000004f}, {"up", 0x40000052}, {"down", 0x40000051},
    {"enter", 13}, {"escape", 27}, {"space", 32}, {"tab", 9}, {"backspace", 8}, {"delete", 127},
    {"kpenter", 0x40000058}, {"lshift", 0x400000e1}, {"rshift", 0x400000e5}, {"lctrl", 0x400000e0},
    {"rctrl", 0x400000e4}, {"lalt", 0x400000e2}, {"ralt", 0x400000e6},
    {"f1", 0x4000003a}, {"f2", 0x4000003b}, {"f3", 0x4000003c}, {"f4", 0x4000003d}, {"f5", 0x4000003e},
    {"f6", 0x4000003f}, {"f7", 0x40000040}, {"f8", 0x40000041}, {"f9", 0x40000042}, {"f10", 0x40000043},
    {"f11", 0x40000044}, {"f12", 0x40000045},
    {"comma", 44}, {"period", 46}, {"slash", 47}, {"minus", 45}, {"equals", 61},
};
#define HARNESS_LETTER(c) (c)                      /* SDLK_a.. = 'a'.. */
#endif

static int harness_keycode(const char *s, int len)   /* 0 = unknown name */
{
    size_t i;
    if (len == 1 && s[0] >= 'a' && s[0] <= 'z') return HARNESS_LETTER(s[0]);
    if (len == 1 && s[0] >= '0' && s[0] <= '9') return s[0];
    for (i = 0; i < sizeof(harness_keynames) / sizeof(harness_keynames[0]); i++) {
        const char *n = harness_keynames[i].name;
        if ((int)strlen(n) == len && memcmp(n, s, (size_t)len) == 0) return harness_keynames[i].code;
    }
    return 0;
}

/* ------------------------------------------------------------------------------------------- state */
struct harness_event { int frame; int n; int codes[HARNESS_MAX_HELD]; };

static struct {
    int inited, replay, fb, exit_frame, frame, nevents, cursor, pending, pending_frame, linelen;
    struct harness_event *events;
    harness_file *trace;
    char line[HARNESS_LINE];
} harness;

static void harness_fail(void) { exit(3); }       /* a broken replay must never run as a free game */

/* Replay file: header line, then "<frame> <keys>" lines; keys "-" or names joined by "+"; '#' comments. */
static int harness_parse_replay(char *text, size_t len)
{
    int maxlines = 1, header = 0, last = -1;
    size_t i;
    char *p = text, *end_all = text + len;
    for (i = 0; i < len; i++) if (text[i] == '\n') maxlines++;
    harness.events = (struct harness_event *)malloc(sizeof(struct harness_event) * (size_t)maxlines);
    if (!harness.events) return 0;
    harness.nevents = 0;
    while (p < end_all) {
        char *eol = p, *end;
        while (eol < end_all && *eol != '\n') eol++;
        end = eol;
        if (end > p && end[-1] == '\r') end--;
        while (p < end && (*p == ' ' || *p == '\t')) p++;
        if (p < end && *p != '#') {
            if (!header) {
                size_t hl = strlen(HARNESS_REPLAY_HEADER);
                if ((size_t)(end - p) < hl || memcmp(p, HARNESS_REPLAY_HEADER, hl) != 0) return 0;
                header = 1;
            } else {
                struct harness_event *ev = &harness.events[harness.nevents];
                int frame = 0;
                char *q = p, *kend;
                if (*q < '0' || *q > '9') return 0;
                while (q < end && *q >= '0' && *q <= '9') frame = frame * 10 + (*q++ - '0');
                if (frame <= last) return 0;
                while (q < end && (*q == ' ' || *q == '\t')) q++;
                kend = q;
                while (kend < end && *kend != ' ' && *kend != '\t' && *kend != '#') kend++;
                if (kend == q) return 0;
                ev->frame = frame;
                ev->n = 0;
                if (!(kend - q == 1 && *q == '-')) {
                    char *k = q;
                    while (k < kend) {
                        char *ke = k;
                        int code;
                        while (ke < kend && *ke != '+') ke++;
                        code = harness_keycode(k, (int)(ke - k));
                        if (code == 0 || ev->n >= HARNESS_MAX_HELD) return 0;
                        ev->codes[ev->n++] = code;
                        k = ke < kend ? ke + 1 : ke;
                    }
                }
                last = frame;
                harness.nevents++;
            }
        }
        p = eol < end_all ? eol + 1 : eol;
    }
    return header;
}

static HARNESS_NOINLINE void harness_init(void)
{
    const char *v;
    if (harness.inited) return;
    harness.inited = 1;
    harness.exit_frame = -1;
    harness.cursor = -1;
    harness.fb = 1;
    v = harness_getenv(HARNESS_ENV_FB);
    if (v && v[0] == '0') harness.fb = 0;
    v = harness_getenv(HARNESS_ENV_EXIT);
    if (v && v[0]) harness.exit_frame = atoi(v);
    v = harness_getenv(HARNESS_ENV_REPLAY);
    if (v && v[0]) {
        harness_file *f = harness_io_open(v, "rb");
        size_t cap = 1 << 16, got = 0, r;
        char *text = (char *)malloc(cap);
        if (!f || !text) harness_fail();
        while ((r = harness_io_read(f, text + got, cap - got)) > 0) {
            got += r;
            if (got == cap) {
                char *t2 = (char *)realloc(text, cap * 2);
                if (!t2) harness_fail();
                text = t2;
                cap *= 2;
            }
        }
        harness_io_close(f);
        if (!harness_parse_replay(text, got)) harness_fail();
        free(text);
        harness.replay = 1;
    }
    v = harness_getenv(HARNESS_ENV_TRACE);
    if (v && v[0]) {
        static const char head[] = HARNESS_TRACE_HEADER "\n";
        harness.trace = harness_io_open(v, "wb");
        if (!harness.trace) harness_fail();
        harness_io_write(harness.trace, head, sizeof(head) - 1);
    }
}

/* 1 when input comes from the replay file (and the loop must run one fixed step per render). */
static HARNESS_NOINLINE int harness_replay_on(void) { harness_init(); return harness.replay; }

/* 1 when a trace is written (the game then builds the frame's line). */
static HARNESS_NOINLINE int harness_tracing(void) { harness_init(); return harness.trace != NULL; }

/* Keys held in the current logic frame (call after every input poll, then overwrite the game's state).
 * Returns -1 when replay is off (leave the real input alone). */
static HARNESS_NOINLINE int harness_held(int *codes, int max)
{
    int i, n = 0;
    harness_init();
    if (!harness.replay) return -1;
    while (harness.cursor + 1 < harness.nevents && harness.events[harness.cursor + 1].frame <= harness.frame)
        harness.cursor++;
    if (harness.cursor >= 0) {
        const struct harness_event *ev = &harness.events[harness.cursor];
        for (i = 0; i < ev->n && n < max; i++) codes[n++] = ev->codes[i];
    }
    return n;
}

static int harness_frame(void) { return harness.frame; }

/* ---------------------------------------------------------------------------------- the trace line */
static void harness_line_begin(void) { harness.linelen = 0; }

static void harness_put(const char *fmt, ...)
{
    va_list ap;
    int room = HARNESS_LINE - 1 - harness.linelen, n;
    if (room <= 0) return;
    va_start(ap, fmt);
    n = HARNESS_VSNPRINTF(harness.line + harness.linelen, (size_t)room, fmt, ap);
    va_end(ap);
    harness.linelen += (n < 0 || n > room) ? room : n;
    harness.line[harness.linelen] = '\0';
}

/* " name=i,j,k" for the set entries of a bool/byte array, "-" when none */
static void harness_put_set(const char *name, const unsigned char *arr, int n, size_t stride)
{
    int i, any = 0;
    harness_put(" %s=", name);
    for (i = 0; i < n; i++) {
        if (arr[(size_t)i * stride]) {
            harness_put(any ? ",%d" : "%d", i);
            any = 1;
        }
    }
    if (!any) harness_put("-");
}

/* End of a logic frame: the line built since harness_line_begin() waits for the frame's render. */
static HARNESS_NOINLINE void harness_frame_done(void)
{
    harness_init();
    if (harness.trace || harness.exit_frame >= 0) {
        harness.pending = 1;
        harness.pending_frame = harness.frame;
    }
    harness.frame++;
}

/* After the frame's render. fb: the framebuffer hash, or -1 for "-" (no render, or GAME_TRACE_FB=0).
 * Writes the pending line; returns 1 when the exit frame is reached (the game then quits its usual way, so
 * that settings and saves are written as in a real quit). */
static HARNESS_NOINLINE int harness_end_of_render(long long fb)
{
    harness_init();
    if (!harness.pending) return 0;
    harness.pending = 0;
    if (harness.trace) {
        if (fb >= 0 && harness.fb) harness_put(" fb=%08x\n", (unsigned int)fb);
        else harness_put(" fb=-\n");
        harness_io_write(harness.trace, harness.line, (size_t)harness.linelen);
    }
    if (harness.exit_frame >= 0 && harness.pending_frame >= harness.exit_frame) {
        if (harness.trace) {
            harness_io_close(harness.trace);
            harness.trace = NULL;
        }
        return 1;
    }
    return 0;
}

/* Whether the fb field is wanted at all (skip the read-back when not). */
static int harness_fb_wanted(void) { return harness.trace != NULL && harness.fb; }

#endif /* HARNESS_CORE_H */

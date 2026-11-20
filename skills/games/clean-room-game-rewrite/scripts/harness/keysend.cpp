// keysend.cpp - post scripted key presses to a window found by its title (a Win32 test tool for rewrites).
//
// Real keyboard input for a game under test, without a hook in the game: the messages are posted to the
// window (WM_KEYDOWN / WM_KEYUP with the scan code in lParam, as Windows sends them; WM_SYSKEYDOWN/UP for
// Alt), so the game reads them through its normal window procedure (SDL, DirectInput's window, ...).
// It complements the harness replay (scripted input inside the game, references/harness.md): use it to
// check that the rewrite's real input path works, e.g. title screen -> menu -> new game.
//
// Build (C++03, any MSVC from VS2010 on; Wine works):
//   cl /nologo /O2 /MT keysend.cpp user32.lib
//   python3 -I <skill>/scripts/cpp_build.py --no-default-libs --lib user32.lib --out keysend.exe keysend.cpp
//
// Usage: keysend.exe [--timeout S] [--contains] [--no-focus] [--quiet] TITLE STEP...
//   TITLE        exact window title (--contains: a part of it); waited for up to --timeout seconds (30)
//   STEP         run in order; several steps may share one argument, separated by spaces:
//     wait:MS          sleep MS milliseconds
//     tap:KEY[:MS]     key down, hold MS milliseconds (default 80), key up
//     down:KEY         key down (held until up:KEY)
//     up:KEY           key up
//     char:TEXT        WM_CHAR for each character of TEXT (text input; '_' is sent as a space)
//     focus            SetForegroundWindow again
//   KEY: a-z 0-9 f1-f12 left right up down space enter escape tab backspace delete insert home end pageup
//        pagedown lshift rshift lctrl rctrl lalt ralt comma period slash minus equals kp0-kp9 kpenter,
//        or vk:HH (a virtual-key code in hex)
// Example: keysend.exe "My Game" "wait:3000 tap:z:150 wait:500 down:right wait:1000 up:right"
// Prints one line per key event. Exit 0 done, 2 window not found, 3 bad step or key.

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static int g_quiet = 0;

struct FindCtx
{
    const char* title;
    HWND found;
};

static BOOL CALLBACK find_part(HWND h, LPARAM lp)
{
    FindCtx* ctx = (FindCtx*) lp;
    char buf[512];
    if (GetWindowTextA(h, buf, sizeof(buf)) > 0 && strstr(buf, ctx->title) != NULL && IsWindowVisible(h))
    {
        ctx->found = h;
        return FALSE;
    }
    return TRUE;
}

static HWND find_window(const char* title, int contains, int timeout_s)
{
    for (int i = 0; i < timeout_s * 10; i++)
    {
        HWND h = NULL;
        if (contains)
        {
            FindCtx ctx;
            ctx.title = title;
            ctx.found = NULL;
            EnumWindows(find_part, (LPARAM) &ctx);
            h = ctx.found;
        }
        else
        {
            h = FindWindowA(NULL, title);
        }
        if (h != NULL)
        {
            return h;
        }
        Sleep(100);
    }
    return NULL;
}

struct KeyName
{
    const char* name;
    UINT vk;
    int extended;
};

static const KeyName KEYS[] = {
    {"left", VK_LEFT, 1}, {"right", VK_RIGHT, 1}, {"up", VK_UP, 1}, {"down", VK_DOWN, 1},
    {"space", VK_SPACE, 0}, {"enter", VK_RETURN, 0}, {"escape", VK_ESCAPE, 0}, {"tab", VK_TAB, 0},
    {"backspace", VK_BACK, 0}, {"delete", VK_DELETE, 1}, {"insert", VK_INSERT, 1}, {"home", VK_HOME, 1},
    {"end", VK_END, 1}, {"pageup", VK_PRIOR, 1}, {"pagedown", VK_NEXT, 1},
    {"lshift", VK_LSHIFT, 0}, {"rshift", VK_RSHIFT, 0}, {"lctrl", VK_LCONTROL, 0}, {"rctrl", VK_RCONTROL, 1},
    {"lalt", VK_LMENU, 0}, {"ralt", VK_RMENU, 1}, {"comma", VK_OEM_COMMA, 0}, {"period", VK_OEM_PERIOD, 0},
    {"slash", VK_OEM_2, 0}, {"minus", VK_OEM_MINUS, 0}, {"equals", VK_OEM_PLUS, 0},
    {"kpenter", VK_RETURN, 1},
};

// vk: the code posted in wParam; scan: the scan code for lParam
static int key_codes(const char* name, UINT* vk, UINT* scan, int* extended)
{
    *extended = 0;
    size_t n = strlen(name);
    if (n == 1 && (islower((unsigned char) name[0]) || isdigit((unsigned char) name[0])))
    {
        *vk = (UINT) toupper((unsigned char) name[0]);
    }
    else if ((name[0] == 'f') && n >= 2 && n <= 3 && isdigit((unsigned char) name[1]) && atoi(name + 1) >= 1 &&
             atoi(name + 1) <= 12)
    {
        *vk = VK_F1 + (UINT) (atoi(name + 1) - 1);
    }
    else if (strncmp(name, "kp", 2) == 0 && n == 3 && isdigit((unsigned char) name[2]))
    {
        *vk = VK_NUMPAD0 + (UINT) (name[2] - '0');
    }
    else if (strncmp(name, "vk:", 3) == 0 && n > 3)
    {
        *vk = (UINT) strtoul(name + 3, NULL, 16);
    }
    else
    {
        size_t i;
        for (i = 0; i < sizeof(KEYS) / sizeof(KEYS[0]); i++)
        {
            if (strcmp(name, KEYS[i].name) == 0)
            {
                break;
            }
        }
        if (i == sizeof(KEYS) / sizeof(KEYS[0]))
        {
            return 0;
        }
        *vk = KEYS[i].vk;
        *extended = KEYS[i].extended;
    }
    *scan = MapVirtualKeyA(*vk, MAPVK_VK_TO_VSC);
    // the messages carry the generic modifier codes; the scan code tells left from right
    if (*vk == VK_LSHIFT || *vk == VK_RSHIFT)
    {
        *vk = VK_SHIFT;
    }
    else if (*vk == VK_LCONTROL || *vk == VK_RCONTROL)
    {
        *vk = VK_CONTROL;
    }
    else if (*vk == VK_LMENU || *vk == VK_RMENU)
    {
        *vk = VK_MENU;
    }
    return 1;
}

static int send_key(HWND h, const char* name, int down)
{
    UINT vk, scan;
    int ext;
    if (!key_codes(name, &vk, &scan, &ext))
    {
        printf("unknown key %s\n", name);
        return 0;
    }
    LPARAM lp = (LPARAM) (1 | (scan << 16) | (ext ? (1u << 24) : 0));
    if (!down)
    {
        lp |= (LPARAM) ((1u << 30) | (1u << 31));
    }
    UINT msg = vk == VK_MENU ? (down ? WM_SYSKEYDOWN : WM_SYSKEYUP) : (down ? WM_KEYDOWN : WM_KEYUP);
    PostMessageA(h, msg, vk, lp);
    if (!g_quiet)
    {
        printf("%s %s\n", down ? "down" : "up", name);
        fflush(stdout);
    }
    return 1;
}

// one step "verb:arg[:arg2]"; returns 0 on a bad step
static int run_step(HWND h, char* step)
{
    char* a = step;
    char* b = strchr(a, ':');
    char* c = NULL;
    if (b != NULL)
    {
        *b++ = '\0';
        if (strcmp(a, "char") != 0 && strncmp(b, "vk:", 3) != 0)
        {
            c = strchr(b, ':');
        }
        else if (strncmp(b, "vk:", 3) == 0)
        {
            c = strchr(b + 3, ':');
        }
        if (c != NULL)
        {
            *c++ = '\0';
        }
    }
    if (strcmp(a, "focus") == 0)
    {
        SetForegroundWindow(h);
        return 1;
    }
    if (b == NULL)
    {
        return 0;
    }
    if (strcmp(a, "wait") == 0)
    {
        Sleep((DWORD) atoi(b));
        return 1;
    }
    if (strcmp(a, "tap") == 0)
    {
        if (!send_key(h, b, 1))
        {
            return 0;
        }
        Sleep((DWORD) (c != NULL ? atoi(c) : 80));
        return send_key(h, b, 0);
    }
    if (strcmp(a, "down") == 0)
    {
        return send_key(h, b, 1);
    }
    if (strcmp(a, "up") == 0)
    {
        return send_key(h, b, 0);
    }
    if (strcmp(a, "char") == 0)
    {
        for (const char* p = b; *p != '\0'; p++)
        {
            PostMessageA(h, WM_CHAR, (WPARAM) (unsigned char) (*p == '_' ? ' ' : *p), 1);
        }
        if (!g_quiet)
        {
            printf("char %s\n", b);
            fflush(stdout);
        }
        return 1;
    }
    return 0;
}

int main(int argc, char** argv)
{
    int timeout_s = 30;
    int contains = 0;
    int focus = 1;
    int i = 1;
    for (; i < argc && strncmp(argv[i], "--", 2) == 0; i++)
    {
        if (strcmp(argv[i], "--timeout") == 0 && i + 1 < argc)
        {
            timeout_s = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "--contains") == 0)
        {
            contains = 1;
        }
        else if (strcmp(argv[i], "--no-focus") == 0)
        {
            focus = 0;
        }
        else if (strcmp(argv[i], "--quiet") == 0)
        {
            g_quiet = 1;
        }
        else
        {
            printf("unknown option %s\n", argv[i]);
            return 3;
        }
    }
    if (i >= argc)
    {
        printf("usage: keysend.exe [--timeout S] [--contains] [--no-focus] [--quiet] TITLE STEP...\n");
        return 3;
    }
    const char* title = argv[i++];
    HWND h = find_window(title, contains, timeout_s);
    if (h == NULL)
    {
        printf("no window \"%s\"\n", title);
        return 2;
    }
    if (focus)
    {
        SetForegroundWindow(h);
    }
    for (; i < argc; i++)
    {
        // one argument may hold several space-separated steps
        size_t len = strlen(argv[i]);
        char* buf = (char*) malloc(len + 1);
        memcpy(buf, argv[i], len + 1);
        char* ctx = NULL;
        for (char* step = strtok_s(buf, " \t", &ctx); step != NULL; step = strtok_s(NULL, " \t", &ctx))
        {
            if (!run_step(h, step))
            {
                printf("bad step %s\n", step);
                free(buf);
                return 3;
            }
        }
        free(buf);
    }
    return 0;
}

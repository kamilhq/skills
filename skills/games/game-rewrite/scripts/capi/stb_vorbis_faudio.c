/* stb_vorbis_faudio.c - compiles FAudio's src/stb_vorbis.h (FAudio 24.02: stb_vorbis v1.20 from
 * nothings/stb 314d0a6f plus FAudio's patches) as a library of its own. Example of building a library from
 * the patched copy that a game really contains instead of the plain upstream file. Signs of FAudio's copy in
 * an exe: stb_vorbis_open_memory returns NULL for NULL data without setting *error (v1.20; v1.21+ set it) and
 * get8 reads with fread(&c, 1, 1, f) != 1 (an FAudio change; upstream uses fgetc). FAudio's patch also
 * makes a 0-byte setup_malloc return a valid pointer: unpatched v1.20 fails with VORBIS_outofmem (3) on
 * Ogg streams that carry no comments (in one game: every music track).
 *
 * FAudio's copy expects its includer to provide the C headers, FAUDIOAPI and FAudio_alloca/dealloca.
 * Here FILE is the C runtime's FILE and memory comes from malloc (a game may map them to its own I/O and
 * allocator, e.g. SDL_RWops and SDL_malloc in an SDL game). FAUDIOAPI is __declspec(dllexport): the
 * functions are exported from the DLL, and from an exe that links the static library (as the original did).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <malloc.h>

#define FAUDIOAPI __declspec(dllexport)
#define FAudio_alloca(x) alloca(x)
#define FAudio_dealloca(x) ((void)(x))

#define STB_VORBIS_NO_PUSHDATA_API 1
#define STB_VORBIS_NO_INTEGER_CONVERSION 1
#include "stb_vorbis.h"

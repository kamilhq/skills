/* lodepng_alloc.c - the three allocator hooks lodepng calls when it is built with
 * LODEPNG_NO_COMPILE_ALLOCATORS. A game that builds lodepng this way defines them itself (an SDL game
 * typically forwards them to SDL_malloc/SDL_realloc/SDL_free); this file is the stand-in for a DLL build.
 *
 * Linked into lodepng.dll (build_libs.py, flavour "dll") so the DLL is self-contained and exports them:
 * buffers that lodepng returns (lodepng_decode32 etc.) come from the DLL's own static CRT heap, so callers
 * outside the DLL must release them with the exported lodepng_free, never with their own free().
 * The static flavour leaves this file out: the C++ rewrite defines the three functions, as the game did.
 */
#include <stdlib.h>

#ifdef LODEPNG_ALLOC_EXPORT
#define LODEPNG_ALLOC_API __declspec(dllexport)
#else
#define LODEPNG_ALLOC_API
#endif

LODEPNG_ALLOC_API void *lodepng_malloc(size_t size) { return malloc(size); }
LODEPNG_ALLOC_API void *lodepng_realloc(void *ptr, size_t new_size) { return realloc(ptr, new_size); }
LODEPNG_ALLOC_API void lodepng_free(void *ptr) { free(ptr); }

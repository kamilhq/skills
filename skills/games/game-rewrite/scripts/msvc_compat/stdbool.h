/* Stand-in for C99 <stdbool.h>, which VS2010 lacks (c-hashmap's map.h includes it). In C++ bool is built in
   (1 byte, returned in AL - the same as the C99 _Bool of the clang-compiled c-hashmap); in C (VS2010 is C89)
   it maps bool to unsigned char. */
#pragma once
#ifndef __cplusplus
#define bool unsigned char
#define true 1
#define false 0
#endif
#define __bool_true_false_are_defined 1

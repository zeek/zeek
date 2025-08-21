// See the file "COPYING" in the main distribution directory for copyright.

#ifndef pac_dbg_h
#define pac_dbg_h

#include <assert.h>
#include <stdio.h>

extern bool FLAGS_pac_debug;

constexpr void ASSERT(bool flag) { assert(flag); }
constexpr void ASSERT(int flag) { assert(flag); }
#define DEBUG_MSG(...)                                                                                                 \
    if ( FLAGS_pac_debug )                                                                                             \
    fprintf(stderr, __VA_ARGS__)

#endif /* pac_dbg_h */

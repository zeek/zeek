#ifndef pac_dbg_h
#define pac_dbg_h

#include <assert.h>
#include <stdio.h>

extern bool FLAGS_pac_debug;

#define ASSERT(x) assert(x)
#define DEBUG_MSG(...)                                                                                                 \
    if ( FLAGS_pac_debug )                                                                                             \
    fprintf(stderr, __VA_ARGS__)

#endif /* pac_dbg_h */

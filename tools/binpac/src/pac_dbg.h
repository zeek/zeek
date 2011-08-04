#ifndef pac_dbg_h
#define pac_dbg_h

#include <assert.h>
#include <stdio.h>

extern bool FLAGS_pac_debug;

#define ASSERT(x)	assert(x)
#define DEBUG_MSG(x...)	if ( FLAGS_pac_debug ) fprintf(stderr, x)

#endif /* pac_dbg_h */

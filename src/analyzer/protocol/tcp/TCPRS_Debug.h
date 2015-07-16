/*
 * Copyright (c) 2011-2015 James Swaro
 * Copyright (c) 2011-2015 Internetworking Research Group, Ohio University
 */


#ifndef TCPRS_DEBUG_H
#define TCPRS_DEBUG_H

#include <cstdio>

#ifndef STRINGIFY_HELPER
#define STRINGIFY_HELPER(something)		#something
#endif
#ifndef STRINGIFY
#define STRINGIFY(something)			STRINGIFY_HELPER(something)
#endif

extern FILE* tcprs_debug_file;

#define MAX_DEBUG_STRINGS 4

#define TCPRS_DEBUG 0
#define TCPRS_DBG_LVL 0

#if DEBUG && TCPRS_DEBUG
#  define TCPRS_DEBUG_MSG(level, category, message, args...)                           \
        do {                                                                          \
        if (tcprs_debug_file != NULL &&                                                \
                level <= TCPRS_DBG_LVL)                                                \
                                tcprs_fprintf(__func__, STRINGIFY(__LINE__),           \
                                                category, (char*) message, ##args);   \
        } while (0)
#else
#  define TCPRS_DEBUG_MSG(level, message, args...)
#endif

typedef enum {
	CAT_TESTING = 0, CAT_RTT = 1, CAT_RETRANSMIT = 2, CAT_MISC = 3, CAT_RECOVERY, MAX_TCPRS_CATEGORIES
} TCPRS_DEBUG_CATEGORY_LABEL;

#define MAX_DEBUG_LEVEL 8
typedef enum {
	VERBOSE = 0,
	LVL_1 = 1,
	LVL_2 = 2,
	LVL_3 = 3,
	LVL_4 = 4,
	LVL_5 = 5,
	LVL_6 = 6,
	LVL_7 = 7,
	PEDANTIC = MAX_DEBUG_LEVEL
} TCPRS_DEBUG_LEVEL;

typedef enum {
	TCPS_DEBUG_UNKNOWN = 0,
	TCPS_DEBUG_NOTICE = 1,
	TCPS_DEBUG_WARNING = 2,
	TCPS_DEBUG_ERROR = 3
} TCPRS_ERROR_TYPES;

/* Custom version of fprintf which adds which adds identifying info. */
void tcprs_fprintf(const char *func, const char *line, int category, char *fmt,
		...);


#endif

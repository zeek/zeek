/*
 * Copyright (c) 2011-2015 James Swaro
 * Copyright (c) 2011-2015 Internetworking Research Group, Ohio University
 */


#include "TCPRS_Debug.h"
#include <cstdio>
#include <ctime>
#include <cstdarg>
#include <sys/time.h>
#include <cassert>

using namespace std;

FILE* tcprs_debug_file;

#if DEBUG && TCPRS_DEBUG

__attribute__ ((constructor))
static void setup_tcp_state_debug() {
	tcprs_debug_file = fopen("tcpstate.debug", "w");
	assert(tcprs_debug_file);
}

__attribute__ ((destructor))
static void finalize_tcp_state_debug() {
	fclose(tcprs_debug_file);
}
#endif

const char* TCPRS_DEBUG_STRINGS[MAX_DEBUG_STRINGS] = { "UNKNOWN", "NOTICE",
		"WARNING", "ERROR" };

const char* TCPRS_DEBUG_CATEGORY[MAX_TCPRS_CATEGORIES] = {
		[CAT_TESTING] = "TST", //Testing
		[CAT_RTT] = "RTT", //RTT measurement debug info
		[CAT_RETRANSMIT] = "RTX", //Retransmission debug info
		[CAT_MISC] = "MSC", //Miscellaneous debug info
		[CAT_RECOVERY] = "REC" //Recovery related debug infos
		};

/* Custom version of fprintf which adds which adds identifying info. */
void tcprs_fprintf(const char *func, const char *line, int category, char *fmt,
                ...) {
        char buf[1024];
        char *buf_ptr;
        int bc = 0;
        va_list ap;

        struct timeval now;

        (void) gettimeofday(&now, NULL);
        fprintf(tcprs_debug_file, "%03ld.%06ld: %.6s ",
                        ((long) now.tv_sec) % 1000, (long) now.tv_usec,
                        TCPRS_DEBUG_CATEGORY[category]);

        buf_ptr = buf;
        buf_ptr += bc;
        va_start(ap, fmt);
        buf_ptr += vsprintf(buf_ptr, fmt, ap);
        va_end(ap);

        fprintf(tcprs_debug_file, "%s - %s():%s\n", buf, func, line);

        fflush(tcprs_debug_file);
}



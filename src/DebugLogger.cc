// $Id: DebugLogger.cc 4771 2007-08-11 05:50:24Z vern $

#ifdef DEBUG

#include <stdlib.h>
#include <unistd.h>

#include "DebugLogger.h"
#include "Net.h"

DebugLogger debug_logger("debug");

// Same order here as in DebugStream.
DebugLogger::Stream DebugLogger::streams[NUM_DBGS] = {
	{ "serial", 0, false }, { "rules", 0, false }, { "comm", 0, false },
	{ "state", 0, false }, { "chunkedio", 0, false },
	{ "compressor", 0, false }, {"string", 0, false },
	{ "notifiers", 0, false },  { "main-loop", 0, false },
	{ "dpd", 0, false }, { "tm", 0, false },
};

DebugLogger::DebugLogger(const char* filename)
	{
	if ( filename )
		{
		filename = log_file_name(filename);
		
		file = fopen(filename, "w");
		if ( ! file )
			{
			fprintf(stderr, "Can't open '%s' for debugging output.", filename);
			exit(1);
			}

		setvbuf(file, NULL, _IOLBF, 0);
		}
	else
		file = stderr;

	verbose = false;
	}

DebugLogger::~DebugLogger()
	{
	if ( file != stderr )
		fclose(file);
	}

void DebugLogger::EnableStreams(const char* s)
	{
	char* tmp = copy_string(s);
	char* brkt;
	char* tok = strtok(tmp, ",");

	while ( tok )
		{
		int i;
		for ( i = 0; i < NUM_DBGS; ++i )
			if ( strcasecmp(streams[i].prefix, tok) == 0 )
				{
				streams[i].enabled = true;
				break;
				}

		if ( i == NUM_DBGS )
			{
			if ( strcasecmp("verbose", tok) == 0 )
				verbose = true;
			else
				internal_error("unknown debug stream %s\n", tok);
			}

		tok = strtok(0, ",");
		}
	}

void DebugLogger::Log(DebugStream stream, const char* fmt, ...)
	{
	Stream* g = &streams[int(stream)];

	if ( ! g->enabled )
		return;

	fprintf(file, "%17.06f/%17.06f [%s] ",
			network_time, current_time(true), g->prefix);

	for ( int i = g->indent; i > 0; --i )
		fputs("   ", file);

	va_list ap;
	va_start(ap, fmt);
	vfprintf(file, fmt, ap);
	va_end(ap);

	fputc('\n', file);
	fflush(file);
	}

#endif

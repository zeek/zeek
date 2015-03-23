#ifdef DEBUG

#include <stdlib.h>
#include <unistd.h>

#include "DebugLogger.h"
#include "Net.h"
#include "plugin/Plugin.h"

DebugLogger debug_logger("debug");

// Same order here as in DebugStream.
DebugLogger::Stream DebugLogger::streams[NUM_DBGS] = {
	{ "serial", 0, false }, { "rules", 0, false }, { "comm", 0, false },
	{ "state", 0, false }, { "chunkedio", 0, false },
	{ "compressor", 0, false }, {"string", 0, false },
	{ "notifiers", 0, false },  { "main-loop", 0, false },
	{ "dpd", 0, false }, { "tm", 0, false },
	{ "logging", 0, false }, {"input", 0, false },
	{ "threading", 0, false }, { "file_analysis", 0, false },
	{ "plugins", 0, false }, { "broxygen", 0, false },
	{ "pktio", 0, false }, { "broker", 0, false }
};

DebugLogger::DebugLogger(const char* filename)
	{
	if ( filename )
		{
		filename = log_file_name(filename);

		file = fopen(filename, "w");
		if ( ! file )
			{
			// The reporter may not be initialized here yet.
			if ( reporter )
				reporter->FatalError("can't open '%s' for debugging output", filename);
			else
				{
				fprintf(stderr, "can't open '%s' for debugging output\n", filename);
				exit(1);
				}
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

void DebugLogger::ShowStreamsHelp()
	{
	fprintf(stderr, "\n");
	fprintf(stderr, "Enable debug output into debug.log with -B <streams>.\n");
	fprintf(stderr, "<streams> is a comma-separated list of streams to enable.\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Available streams:\n");

	for ( int i = 0; i < NUM_DBGS; ++i )
		fprintf(stderr,"  %s\n", streams[i].prefix);

	fprintf(stderr, "\n");
	fprintf(stderr, "  plugin-<plugin-name>   (replace '::' in name with '-'; e.g., '-B plugin-Bro-Netmap')\n");
	fprintf(stderr, "\n");
	fprintf(stderr, "Pseudo streams\n");
	fprintf(stderr, "  verbose  Increase verbosity.\n");
	fprintf(stderr, "  all      Enable all streams at maximum verbosity.\n");
	fprintf(stderr, "\n");
	}

void DebugLogger::EnableStreams(const char* s)
	{
	char* brkt;
	char* tmp = copy_string(s);
	char* tok = strtok(tmp, ",");

	while ( tok )
		{
		if ( strcasecmp("all", tok) == 0 )
			{
			for ( int i = 0; i < NUM_DBGS; ++i )
				{
				streams[i].enabled = true;
				enabled_streams.insert(streams[i].prefix);
				}

			verbose = true;
			goto next;
			}

		if ( strcasecmp("verbose", tok) == 0 )
			{
			verbose = true;
			goto next;
			}

		if ( strcasecmp("help", tok) == 0 )
			{
			ShowStreamsHelp();
			exit(0);
			}

		if ( strncmp(tok, "plugin-", strlen("plugin-")) == 0 )
			{
			// Cannot verify this at this time, plugins may not
			// have been loaded.
			enabled_streams.insert(tok);
			goto next;
			}

		int i;

		for ( i = 0; i < NUM_DBGS; ++i )
			{
			if ( strcasecmp(streams[i].prefix, tok) == 0 )
				{
				streams[i].enabled = true;
				enabled_streams.insert(tok);
				goto next;
				}
			}

		reporter->FatalError("unknown debug stream '%s', try -B help.\n", tok);

next:
		tok = strtok(0, ",");
		}

	delete [] tmp;
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

void DebugLogger::Log(const plugin::Plugin& plugin, const char* fmt, ...)
	{
	string tok = string("plugin-") + plugin.Name();
	tok = strreplace(tok, "::", "-");

	if ( enabled_streams.find(tok) == enabled_streams.end() )
		return;

	fprintf(file, "%17.06f/%17.06f [plugin %s] ",
			network_time, current_time(true), plugin.Name().c_str());

	va_list ap;
	va_start(ap, fmt);
	vfprintf(file, fmt, ap);
	va_end(ap);

	fputc('\n', file);
	fflush(file);
	}

#endif

// A logger for (selective) debugging output. Only compiled in if DEBUG is
// defined.

#ifndef debug_logger_h
#define debug_logger_h

#ifdef DEBUG

#include <stdio.h>

// To add a new debugging stream, add a constant here as well as
// an entry to DebugLogger::streams in DebugLogger.cc.

enum DebugStream {
	DBG_SERIAL,	// Serialization
	DBG_RULES,	// Signature matching
	DBG_COMM,	// Remote communication
	DBG_STATE,	// StateAccess logging
	DBG_CHUNKEDIO,	// ChunkedIO logging
	DBG_COMPRESSOR,	// Connection compressor
	DBG_STRING,	// String code
	DBG_NOTIFIERS,	// Notifiers (see StateAccess.h)
	DBG_MAINLOOP,	// Main IOSource loop
	DBG_ANALYZER,	// Analyzer framework
	DBG_TM,		// Time-machine packet input via Brocolli
	DBG_LOGGING,	// Logging streams
	DBG_INPUT,	// Input streams
	DBG_THREADING,	// Threading system
	DBG_FILE_ANALYSIS,	// File analysis
	DBG_PLUGINS,
	DBG_BROXYGEN,

	NUM_DBGS // Has to be last
};

#define DBG_LOG(stream, args...) \
	if ( debug_logger.IsEnabled(stream) ) \
		debug_logger.Log(stream, args)
#define DBG_LOG_VERBOSE(stream, args...) \
	if ( debug_logger.IsVerbose() && debug_logger.IsEnabled(stream) ) \
		debug_logger.Log(stream, args)
#define DBG_PUSH(stream) debug_logger.PushIndent(stream)
#define DBG_POP(stream) debug_logger.PopIndent(stream)

class DebugLogger {
public:
	// Output goes to stderr per default.
	DebugLogger(const char* filename = 0);
	~DebugLogger();

	void Log(DebugStream stream, const char* fmt, ...);

	void PushIndent(DebugStream stream)
		{ ++streams[int(stream)].indent; }
	void PopIndent(DebugStream stream)
		{ --streams[int(stream)].indent; }

	void EnableStream(DebugStream stream)
		{ streams[int(stream)].enabled = true; }
	void DisableStream(DebugStream stream)
		{ streams[int(stream)].enabled = false; }

	// Takes comma-seperated list of stream prefixes.
	void EnableStreams(const char* streams);

	bool IsEnabled(DebugStream stream) const
		{ return streams[int(stream)].enabled; }

	void SetVerbose(bool arg_verbose)	{ verbose = arg_verbose; }
	bool IsVerbose() const			{ return verbose; }

private:
	FILE* file;
	bool verbose;

	struct Stream {
		const char* prefix;
		int indent;
		bool enabled;
	};

	static Stream streams[NUM_DBGS];
};

extern DebugLogger debug_logger;

#else
#define DBG_LOG(args...)
#define DBG_LOG_VERBOSE(args...)
#define DBG_PUSH(stream)
#define DBG_POP(stream)
#endif

#endif

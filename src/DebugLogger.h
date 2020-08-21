// A logger for (selective) debugging output. Only compiled in if DEBUG is
// defined.

#pragma once

#ifdef DEBUG

#include "zeek-config.h"

#include <stdio.h>
#include <string>
#include <set>

#define DBG_LOG(stream, args...) \
	if ( zeek::detail::debug_logger.IsEnabled(stream) ) \
		zeek::detail::debug_logger.Log(stream, args)
#define DBG_LOG_VERBOSE(stream, args...) \
	if ( zeek::detail::debug_logger.IsVerbose() && zeek::detail::debug_logger.IsEnabled(stream) ) \
		zeek::detail::debug_logger.Log(stream, args)
#define DBG_PUSH(stream) zeek::detail::debug_logger.PushIndent(stream)
#define DBG_POP(stream) zeek::detail::debug_logger.PopIndent(stream)

#define PLUGIN_DBG_LOG(plugin, args...) zeek::detail::debug_logger.Log(plugin, args)

ZEEK_FORWARD_DECLARE_NAMESPACED(Plugin, zeek, plugin);

namespace zeek {

// To add a new debugging stream, add a constant here as well as
// an entry to DebugLogger::streams in DebugLogger.cc.

enum DebugStream {
	DBG_SERIAL, // Serialization
	DBG_RULES,	// Signature matching
	DBG_STRING,	// String code
	DBG_NOTIFIERS,	// Notifiers
	DBG_MAINLOOP,	// Main IOSource loop
	DBG_ANALYZER,	// Analyzer framework
	DBG_TM,		// Time-machine packet input via Brocolli
	DBG_LOGGING,	// Logging streams
	DBG_INPUT,	// Input streams
	DBG_THREADING,	// Threading system
	DBG_FILE_ANALYSIS,	// File analysis
	DBG_PLUGINS,	// Plugin system
	DBG_ZEEKYGEN,	// Zeekygen
	DBG_PKTIO,	// Packet sources and dumpers.
	DBG_BROKER,	// Broker communication
	DBG_SCRIPTS,	// Script initialization
	DBG_SUPERVISOR,	// Process supervisor

	NUM_DBGS // Has to be last
};

namespace detail {

class DebugLogger {
public:
	// Output goes to stderr per default.
	DebugLogger();
	~DebugLogger();

	void OpenDebugLog(const char* filename = 0);

	void Log(DebugStream stream, const char* fmt, ...) __attribute__((format(printf, 3, 4)));
	void Log(const plugin::Plugin& plugin, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

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

	void ShowStreamsHelp();

private:
	FILE* file;
	bool verbose;

	struct Stream {
		const char* prefix;
		int indent;
		bool enabled;
	};

	std::set<std::string> enabled_streams;

	static Stream streams[NUM_DBGS];
};

extern DebugLogger debug_logger;

} // namespace detail
} // namespace zeek

using DebugLogger [[deprecated("Remove in v4.1. Use zeek::detail::DebugLogger.")]] = zeek::detail::DebugLogger;

using DebugStream [[deprecated("Remove in v4.1. Use zeek::DebugStream.")]] = zeek::DebugStream;
constexpr auto DBG_SERIAL [[deprecated("Remove in v4.1. Use zeek::DBG_SERIAL.")]] = zeek::DBG_SERIAL;
constexpr auto DBG_RULES [[deprecated("Remove in v4.1. Use zeek::DBG_RULES.")]] = zeek::DBG_RULES;
constexpr auto DBG_STRING [[deprecated("Remove in v4.1. Use zeek::DBG_STRING.")]] = zeek::DBG_STRING;
constexpr auto DBG_NOTIFIERS [[deprecated("Remove in v4.1. Use zeek::DBG_NOTIFIERS.")]] = zeek::DBG_NOTIFIERS;
constexpr auto DBG_MAINLOOP [[deprecated("Remove in v4.1. Use zeek::DBG_MAINLOOP.")]] = zeek::DBG_MAINLOOP;
constexpr auto DBG_ANALYZER [[deprecated("Remove in v4.1. Use zeek::DBG_ANALYZER.")]] = zeek::DBG_ANALYZER;
constexpr auto DBG_TM [[deprecated("Remove in v4.1. Use zeek::DBG_TM.")]] = zeek::DBG_TM;
constexpr auto DBG_LOGGING [[deprecated("Remove in v4.1. Use zeek::DBG_LOGGING.")]] = zeek::DBG_LOGGING;
constexpr auto DBG_INPUT [[deprecated("Remove in v4.1. Use zeek::DBG_INPUT.")]] = zeek::DBG_INPUT;
constexpr auto DBG_THREADING [[deprecated("Remove in v4.1. Use zeek::DBG_THREADING.")]] = zeek::DBG_THREADING;
constexpr auto DBG_FILE_ANALYSIS [[deprecated("Remove in v4.1. Use zeek::DBG_FILE_ANALYSIS.")]] = zeek::DBG_FILE_ANALYSIS;
constexpr auto DBG_PLUGINS [[deprecated("Remove in v4.1. Use zeek::DBG_PLUGINS.")]] = zeek::DBG_PLUGINS;
constexpr auto DBG_ZEEKYGEN [[deprecated("Remove in v4.1. Use zeek::DBG_ZEEKYGEN.")]] = zeek::DBG_ZEEKYGEN;
constexpr auto DBG_PKTIO [[deprecated("Remove in v4.1. Use zeek::DBG_PKTIO.")]] = zeek::DBG_PKTIO;
constexpr auto DBG_BROKER [[deprecated("Remove in v4.1. Use zeek::DBG_BROKER.")]] = zeek::DBG_BROKER;
constexpr auto DBG_SCRIPTS [[deprecated("Remove in v4.1. Use zeek::DBG_SCRIPTS.")]] = zeek::DBG_SCRIPTS;
constexpr auto DBG_SUPERVISOR [[deprecated("Remove in v4.1. Use zeek::DBG_SUPERVISOR.")]] = zeek::DBG_SUPERVISOR;

extern zeek::detail::DebugLogger& debug_logger;

#else
#define DBG_LOG(args...)
#define DBG_LOG_VERBOSE(args...)
#define DBG_PUSH(stream)
#define DBG_POP(stream)
#define PLUGIN_DBG_LOG(plugin, args...)
#endif

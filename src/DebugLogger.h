// A logger for (selective) debugging output. Only compiled in if DEBUG is
// defined.

#pragma once

#ifdef DEBUG

#include "zeek/zeek-config.h"

#include <stdio.h>
#include <set>
#include <string>

#include "zeek/util.h"

#define DBG_LOG(stream, args...)                                                                   \
	if ( ::zeek::detail::debug_logger.IsEnabled(stream) )                                          \
	::zeek::detail::debug_logger.Log(stream, args)
#define DBG_LOG_VERBOSE(stream, args...)                                                           \
	if ( ::zeek::detail::debug_logger.IsVerbose() &&                                               \
	     ::zeek::detail::debug_logger.IsEnabled(stream) )                                          \
	::zeek::detail::debug_logger.Log(stream, args)
#define DBG_PUSH(stream) ::zeek::detail::debug_logger.PushIndent(stream)
#define DBG_POP(stream) ::zeek::detail::debug_logger.PopIndent(stream)

#define PLUGIN_DBG_LOG(plugin, args...) ::zeek::detail::debug_logger.Log(plugin, args)

namespace zeek
	{

namespace plugin
	{
class Plugin;
	}

// To add a new debugging stream, add a constant here as well as
// an entry to DebugLogger::streams in DebugLogger.cc.

enum DebugStream
	{
	DBG_SERIAL, // Serialization
	DBG_RULES, // Signature matching
	DBG_STRING, // String code
	DBG_NOTIFIERS, // Notifiers
	DBG_MAINLOOP, // Main IOSource loop
	DBG_ANALYZER, // Analyzer framework
	DBG_PACKET_ANALYSIS, // Packet analysis
	DBG_FILE_ANALYSIS, // File analysis
	DBG_TM, // Time-machine packet input via Broccoli
	DBG_LOGGING, // Logging streams
	DBG_INPUT, // Input streams
	DBG_THREADING, // Threading system
	DBG_PLUGINS, // Plugin system
	DBG_ZEEKYGEN, // Zeekygen
	DBG_PKTIO, // Packet sources and dumpers.
	DBG_BROKER, // Broker communication
	DBG_SCRIPTS, // Script initialization
	DBG_SUPERVISOR, // Process supervisor
	DBG_HASHKEY, // HashKey buffers

	NUM_DBGS // Has to be last
	};

namespace detail
	{

class DebugLogger
	{
public:
	// Output goes to stderr per default.
	DebugLogger();
	~DebugLogger();

	void OpenDebugLog(const char* filename = 0);

	void Log(DebugStream stream, const char* fmt, ...) __attribute__((format(printf, 3, 4)));
	void Log(const plugin::Plugin& plugin, const char* fmt, ...)
		__attribute__((format(printf, 3, 4)));

	void PushIndent(DebugStream stream) { ++streams[int(stream)].indent; }
	void PopIndent(DebugStream stream) { --streams[int(stream)].indent; }

	void EnableStream(DebugStream stream) { streams[int(stream)].enabled = true; }
	void DisableStream(DebugStream stream) { streams[int(stream)].enabled = false; }

	// Takes comma-seperated list of stream prefixes.
	void EnableStreams(const char* streams);

	// Check the enabled streams for invalid ones.
	bool CheckStreams(const std::set<std::string>& plugin_names);

	bool IsEnabled(DebugStream stream) const { return streams[int(stream)].enabled; }

	void SetVerbose(bool arg_verbose) { verbose = arg_verbose; }
	bool IsVerbose() const { return verbose; }

	void ShowStreamsHelp();

private:
	FILE* file;
	bool verbose;

	struct Stream
		{
		const char* prefix;
		int indent;
		bool enabled;
		};

	std::set<std::string> enabled_streams;

	static Stream streams[NUM_DBGS];

	const std::string PluginStreamName(const std::string& plugin_name)
		{
		return "plugin-" + util::strreplace(plugin_name, "::", "-");
		}
	};

extern DebugLogger debug_logger;

	} // namespace detail
	} // namespace zeek

#else
#define DBG_LOG(args...)
#define DBG_LOG_VERBOSE(args...)
#define DBG_PUSH(stream)
#define DBG_POP(stream)
#define PLUGIN_DBG_LOG(plugin, args...)
#endif

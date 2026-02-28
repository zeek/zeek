// See the file "COPYING" in the main distribution directory for copyright.

// A logger for (selective) debugging output. Only compiled in if DEBUG is
// defined.

#pragma once

#include <cstdint>
#include <cstdio>
#include <set>
#include <string>

#ifdef _MSC_VER
#include <unistd.h> // Needed to ignore __attribute__((format(printf))) on MSVC
#endif

#ifdef DEBUG

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define DBG_LOG(stream, ...)                                                                                           \
    if ( ::zeek::detail::debug_logger.IsEnabled(stream) )                                                              \
    ::zeek::detail::debug_logger.Log(stream, __VA_ARGS__)
#define DBG_LOG_VERBOSE(stream, ...)                                                                                   \
    if ( ::zeek::detail::debug_logger.IsVerbose() && ::zeek::detail::debug_logger.IsEnabled(stream) )                  \
    ::zeek::detail::debug_logger.Log(stream, __VA_ARGS__)
#define DBG_PUSH(stream) ::zeek::detail::debug_logger.PushIndent(stream)
#define DBG_POP(stream) ::zeek::detail::debug_logger.PopIndent(stream)

#define PLUGIN_DBG_LOG(plugin, ...) ::zeek::detail::debug_logger.Log(plugin, __VA_ARGS__)
// NOLINTEND(cppcoreguidelines-macro-usage)

#else
// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define DBG_LOG(...)
#define DBG_LOG_VERBOSE(...)
#define DBG_PUSH(stream)
#define DBG_POP(stream)
#define PLUGIN_DBG_LOG(plugin, ...)
// NOLINTEND(cppcoreguidelines-macro-usage)

#endif

namespace zeek {

namespace plugin {
class Plugin;
}

// To add a new debugging stream, add a constant here as well as
// an entry to DebugLogger::streams in DebugLogger.cc.

enum DebugStream : uint8_t {
    DBG_SERIAL,          // Serialization
    DBG_RULES,           // Signature matching
    DBG_STRING,          // String code
    DBG_NOTIFIERS,       // Notifiers
    DBG_MAINLOOP,        // Main IOSource loop
    DBG_ANALYZER,        // Analyzer framework
    DBG_PACKET_ANALYSIS, // Packet analysis
    DBG_FILE_ANALYSIS,   // File analysis
    DBG_TM,              // Time-machine packet input via Broccoli
    DBG_LOGGING,         // Logging streams
    DBG_INPUT,           // Input streams
    DBG_THREADING,       // Threading system
    DBG_PLUGINS,         // Plugin system
    DBG_ZEEKYGEN,        // Zeekygen
    DBG_PKTIO,           // Packet sources and dumpers.
    DBG_BROKER,          // Broker communication
    DBG_SCRIPTS,         // Script initialization
    DBG_SUPERVISOR,      // Process supervisor
    DBG_HASHKEY,         // HashKey buffers
    DBG_SPICY,           // Spicy functionality
    DBG_CLUSTER,         // Cluster functionality
    DBG_STORAGE,         // Storage framework

    NUM_DBGS // Has to be last
};

namespace detail {

class DebugLogger {
public:
    // Output goes to stderr per default.
    DebugLogger() = default;
    ~DebugLogger();

    void OpenDebugLog(const char* filename = nullptr);

    void Log(DebugStream stream, const char* fmt, ...) __attribute__((format(printf, 3, 4)));
    void Log(const plugin::Plugin& plugin, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

    void PushIndent(DebugStream stream) { ++streams[static_cast<int>(stream)].indent; }
    void PopIndent(DebugStream stream) { --streams[static_cast<int>(stream)].indent; }

    void EnableStream(DebugStream stream) { streams[static_cast<int>(stream)].enabled = true; }
    void DisableStream(DebugStream stream) { streams[static_cast<int>(stream)].enabled = false; }

    // Takes comma-separated list of stream prefixes.
    void EnableStreams(const char* streams);

    // Check the enabled streams for invalid ones.
    bool CheckStreams(const std::set<std::string>& plugin_names);

    bool IsEnabled(DebugStream stream) const { return streams[static_cast<int>(stream)].enabled; }

    // Are any streams enabled?
    bool HasEnabledStreams() const { return ! enabled_streams.empty(); }

    void SetVerbose(bool arg_verbose) { verbose = arg_verbose; }
    bool IsVerbose() const { return verbose; }

    void ShowStreamsHelp();

private:
    FILE* file = nullptr;
    bool all = false;
    bool verbose = false;

    struct Stream {
        const char* prefix = nullptr;
        int indent = 0;
        bool enabled = false;
    };

    std::set<std::string> enabled_streams;

    static Stream streams[NUM_DBGS];

    // Canonical rendering of a plugin's name. This is lower-cased,
    // with "::" and "_" both becoming "-".
    std::string PluginStreamName(const std::string& plugin_name) const;
};

extern DebugLogger debug_logger;

} // namespace detail

} // namespace zeek

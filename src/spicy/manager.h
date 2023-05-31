// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <hilti/rt/library.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/types/port.h>

#include "zeek/Scope.h"
#include "zeek/Tag.h"
#include "zeek/plugin/Component.h"
#include "zeek/plugin/Plugin.h"
#include "zeek/spicy/port-range.h"
#include "zeek/spicy/spicyz/config.h" // include for Spicy version

// Macro helper to report Spicy debug messages. This forwards to
// to both the Zeek logger and the Spicy runtime logger.
#define SPICY_DEBUG(msg) ::zeek::spicy::log(msg);

namespace hilti::rt {
class Port;
struct Protocol;
} // namespace hilti::rt

namespace spicy::rt {
struct Parser;
}

namespace zeek {

namespace analyzer {
class Analyzer;
}

namespace file_analysis {
class Analyzer;
}

namespace packet_analysis {
class Analyzer;
}

namespace spicy {

// Backend to log debug messages.
inline void log(const std::string& msg) {
    DBG_LOG(DBG_SPICY, "%s", msg.c_str());

    if ( hilti::rt::isInitialized() )
        HILTI_RT_DEBUG("zeek", msg);
}


/* Top-level entry point for Spicy functionality. */
class Manager : public zeek::plugin::Plugin {
public:
    Manager() {}
    virtual ~Manager();

    /**
     * Runtime method to register a protocol analyzer with its Zeek-side
     * configuration. This is called at startup by generated Spicy code for
     * each protocol analyzer defined in an EVT file.
     *
     * @param name name of the analyzer as defined in its EVT file
     * @param proto analyzer's transport-layer protocol
     * @param prts well-known ports for the analyzer; it'll be activated automatically for these
     * @param parser_orig name of the Spicy parser for the originator side; must match the name that
     * Spicy registers the unit's parser with
     * @param parser_resp name of the Spicy parser for the originator side; must match the name that
     * Spicy registers the unit's parser with
     * @param replaces optional name of existing Zeek analyzer that this one replaces; the Zeek
     * analyzer will automatically be disabled
     * @param linker_scope scope of current HLTO file, which will restrict visibility of the
     * registration
     */
    void registerProtocolAnalyzer(const std::string& name, hilti::rt::Protocol proto,
                                  const hilti::rt::Vector<::zeek::spicy::rt::PortRange>& ports,
                                  const std::string& parser_orig, const std::string& parser_resp,
                                  const std::string& replaces, const std::string& linker_scope);

    /**
     * Runtime method to register a file analyzer with its Zeek-side
     * configuration. This is called at startup by generated Spicy code for
     * each file analyzer defined in an EVT file
     *
     * @param name name of the analyzer as defined in its EVT file
     * @param mime_types list of MIME types the analyzer handles; it'll be automatically used for
     * all files of matching types
     * @param parser name of the Spicy parser for parsing the file; must match the name that Spicy
     * registers the unit's parser with
     * @param replaces optional name of existing Zeek analyzer that this one replaces; the Zeek
     * analyzer will automatically be disabled
     * @param linker_scope scope of current HLTO file, which will restrict visibility of the
     * registration
     */
    void registerFileAnalyzer(const std::string& name, const hilti::rt::Vector<std::string>& mime_types,
                              const std::string& parser, const std::string& replaces, const std::string& linker_scope);

    /**
     * Runtime method to register a packet analyzer with its Zeek-side
     * configuration. This is called at startup by generated Spicy code for
     * each packet analyzer defined in an EVT file.
     *
     * @param name name of the analyzer as defined in its EVT file
     * @param parser name of the Spicy parser for parsing the packet; must
     * match the name that Spicy registers the unit's
     * parser with.
     * @param replaces optional name of existing Zeek analyzer that this one
     * replaces; the Zeek analyzer will automatically be disabled
     * @param linker_scope scope of current HLTO file, which will restrict visibility of the
     * registration
     */
    void registerPacketAnalyzer(const std::string& name, const std::string& parser, const std::string& replaces,
                                const std::string& linker_scope);

    /**
     * Runtime method to register a Spicy-generated type with Zeek. The type
     * must have been encountered during AST traversal already, so that its ID
     * is known. The corresponding Zeek type will be created and registered with Zeek.
     *
     * @param id fully-qualified ID of the type
     * @return error if the type could not be registered
     */
    hilti::rt::Result<hilti::rt::Nothing> registerType(const std::string& id);

    /**
     * Runtime method to register an already converted Spicy-generated type
     * with Zeek.
     *
     * @param id fully-qualified ID of the type
     * @param type Zeek-side type to register
     */
    void registerType(const std::string& id, const TypePtr& type);

    /**
     * Looks up a global type by its ID with Zeek.
     *
     * @param id fully-qualified Zeek-side ID of the type
     * @return Zeek-side type, or null if not found
     */
    TypePtr findType(const std::string& id) const;

    /**
     * Runtime method to register a Spicy-generated event. The installs the ID
     * Zeek-side and is called at startup by generated Spicy code for each
     * event defined in an EVT file.
     *
     * @param name fully scoped name of the event
     */
    void registerEvent(const std::string& name);

    /**
     * Runtime method to retrieve the Spicy parser for a given Zeek protocol analyzer tag.
     *
     * @param analyzer requested protocol analyzer
     * @param is_orig true if requesting the parser parser for a sessions' originator side, false
     * for the responder
     * @return parser, or null if we don't have one for this tag. The pointer will remain valid for
     * the life-time of the process.
     */
    const ::spicy::rt::Parser* parserForProtocolAnalyzer(const Tag& tag, bool is_orig);

    /**
     * Runtime method to retrieve the Spicy parser for a given Zeek file analyzer tag.
     *
     * @param analyzer requested file analyzer.
     * @return parser, or null if we don't have one for this tag. The pointer will remain valid for
     * the life-time of the process.
     */
    const ::spicy::rt::Parser* parserForFileAnalyzer(const Tag& tag);

    /**
     * Runtime method to retrieve the Spicy parser for a given Zeek packet analyzer tag.
     *
     * @param analyzer requested packet analyzer.
     * @return parser, or null if we don't have one for this tag. The pointer will remain
     * valid for the life-time of the process.
     */
    const ::spicy::rt::Parser* parserForPacketAnalyzer(const Tag& tag);

    /**
     * Runtime method to retrieve the analyzer tag that should be passed to
     * script-land when talking about a protocol analyzer. This is normally
     * the analyzer's standard tag, but may be replaced with something else
     * if the analyzer substitutes for an existing one.
     *
     * @param tag original tag we query for how to pass it to script-land.
     * @return desired tag for passing to script-land.
     */
    Tag tagForProtocolAnalyzer(const Tag& tag);

    /**
     * Runtime method to retrieve the analyzer tag that should be passed to
     * script-land when talking about a file analyzer. This is normally the
     * analyzer's standard tag, but may be replaced with something else if
     * the analyzer substitutes for an existing one.
     *
     * @param tag original tag we query for how to pass it to script-land.
     * @return desired tag for passing to script-land.
     */
    Tag tagForFileAnalyzer(const Tag& tag);

    /**
     * Runtime method to retrieve the analyzer tag that should be passed to
     * script-land when talking about a packet analyzer. This is normally the
     * analyzer's standard tag, but may be replaced with something else if
     * the analyzer substitutes for an existing one.
     *
     * @param tag original tag we query for how to pass it to script-land.
     * @return desired tag for passing to script-land.
     */
    Tag tagForPacketAnalyzer(const Tag& tag);

    /**
     * Explicitly enable/disable a protocol analyzer. By default, all analyzers
     * loaded will also be activated. By calling this method, an analyzer can
     * toggled.
     *
     * @param analyzer tag of analyzer
     * @param enable true to enable, false to disable
     */
    bool toggleProtocolAnalyzer(const Tag& tag, bool enable);

    /**
     * Explicitly enable/disable a file analyzer. By default, all analyzers
     * loaded will also be activated. By calling this method, an analyzer can
     * toggled.
     *
     * @param analyzer tag of analyzer
     * @param enable true to enable, false to disable
     */
    bool toggleFileAnalyzer(const Tag& tag, bool enable);

    /**
     * Explicitly enable/disable a packet analyzer. By default, all analyzers
     * loaded will also be activated. By calling this method, an analyzer can
     * toggled.
     *
     * @note This is currently not supported because Zeek does not provide the
     * necessary API.
     *
     * @param analyzer tag of analyzer
     * @param enable true to enable, false to disable
     */
    bool togglePacketAnalyzer(const Tag& tag, bool enable);

    /**
     * Explicitly enable/disable an analyzer. By default, all analyzers
     * loaded will also be activated. By calling this method, an analyzer can
     * toggled.
     *
     * This method is frontend for the versions specific to
     * protocol/file/packet analyzers. It takes an enum corresponding to either
     * kind and branches out accordingly.
     *
     * @param analyzer tag of analyzer
     * @param enable true to enable, false to disable
     */
    bool toggleAnalyzer(EnumVal* tag, bool enable);

    /** Report an error and disable a protocol analyzer's input processing */
    void analyzerError(analyzer::Analyzer* a, const std::string& msg, const std::string& location);

    /** Report an error and disable a file analyzer's input processing */
    void analyzerError(file_analysis::Analyzer* a, const std::string& msg, const std::string& location);

    /** Report an error and disable a packet analyzer's input processing. */
    void analyzerError(packet_analysis::Analyzer* a, const std::string& msg, const std::string& location);

    /** Returns the number of errors recorded by the Zeek reporter. */
    int numberErrors();

protected:
    // Overriding method from Zeek's plugin API.
    zeek::plugin::Configuration Configure() override;

    // Overriding method from Zeek's plugin API.
    void InitPreScript() override;

    // Overriding method from Zeek's plugin API.
    void InitPostScript() override;

    // Overriding method from Zeek's plugin API.
    void Done() override;

    // Overriding method from Zeek's plugin API.
    int HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved) override;

private:
    // Load one *.hlto module.
    void loadModule(const hilti::rt::filesystem::path& path);

    // Search ZEEK_SPICY_MODULE_PATH for pre-compiled *.hlto modules and load them.
    void autoDiscoverModules();

    // Recursively search pre-compiled *.hlto in colon-separated paths.
    void searchModules(const std::string& paths);

    // Return a Zeek location object for the given file name that will stay valid.
    detail::Location makeLocation(const std::string& fname);

    // Disable any Zeek-side analyzers that are replaced by one of ours.
    void disableReplacedAnalyzers();

    /**
     * Internal callback that records the component-to-tag-type mapping for plugin's analyzer.
     *
     * @param c component to track
     * @param tag_type tag type to associate with component
     */
    void trackComponent(plugin::Component* c, int32_t tag_type);

    /** Captures a registered protocol analyzer. */
    struct ProtocolAnalyzerInfo {
        // Provided when registering the analyzer.
        std::string name_analyzer;
        std::string name_parser_orig;
        std::string name_parser_resp;
        std::string name_replaces;
        hilti::rt::Protocol protocol = hilti::rt::Protocol::Undef;
        hilti::rt::Vector<::zeek::spicy::rt::PortRange> ports;
        std::string linker_scope;

        // Computed and available once the analyzer has been registered.
        std::string name_zeek;
        std::string name_zeekygen;
        Tag::type_t type;
        const ::spicy::rt::Parser* parser_orig;
        const ::spicy::rt::Parser* parser_resp;
        Tag replaces;

        bool operator==(const ProtocolAnalyzerInfo& other) const {
            return name_analyzer == other.name_analyzer && name_parser_orig == other.name_parser_orig &&
                   name_parser_resp == other.name_parser_resp && name_replaces == other.name_replaces &&
                   protocol == other.protocol && ports == other.ports && linker_scope == other.linker_scope;
        }

        bool operator!=(const ProtocolAnalyzerInfo& other) const { return ! (*this == other); }
    };

    /** Captures a registered file analyzer. */
    struct FileAnalyzerInfo {
        // Provided when registering the analyzer.
        std::string name_analyzer;
        std::string name_parser;
        std::string name_replaces;
        hilti::rt::Vector<std::string> mime_types;
        std::string linker_scope;

        // Computed and available once the analyzer has been registered.
        std::string name_zeek;
        std::string name_zeekygen;
        Tag::type_t type;
        const ::spicy::rt::Parser* parser;
        Tag replaces;

        bool operator==(const FileAnalyzerInfo& other) const {
            return name_analyzer == other.name_analyzer && name_parser == other.name_parser &&
                   name_replaces == other.name_replaces && mime_types == other.mime_types &&
                   linker_scope == other.linker_scope;
        }

        bool operator!=(const FileAnalyzerInfo& other) const { return ! (*this == other); }
    };

    /** Captures a registered file analyzer. */
    struct PacketAnalyzerInfo {
        // Provided when registering the analyzer.
        std::string name_analyzer;
        std::string name_parser;
        std::string name_replaces;
        std::string linker_scope;

        // Computed and available once the analyzer has been registered.
        std::string name_zeek;
        std::string name_zeekygen;
        Tag::type_t type;
        const ::spicy::rt::Parser* parser;
        Tag replaces;

        // Compares only the provided attributes, as that's what defines us.
        bool operator==(const PacketAnalyzerInfo& other) const {
            return name_analyzer == other.name_analyzer && name_parser == other.name_parser &&
                   name_replaces == other.name_replaces && linker_scope == other.linker_scope;
        }

        bool operator!=(const PacketAnalyzerInfo& other) const { return ! (*this == other); }
    };

    std::string _spicy_version;

    std::vector<ProtocolAnalyzerInfo> _protocol_analyzers_by_type;
    std::vector<FileAnalyzerInfo> _file_analyzers_by_type;
    std::vector<PacketAnalyzerInfo> _packet_analyzers_by_type;
    std::unordered_map<std::string, hilti::rt::Library> _libraries;
    std::set<std::string> _locations;
    std::unordered_map<std::string, detail::IDPtr> _events;

    // Mapping of component names to tag types. We use this to ensure analyzer uniqueness.
    std::unordered_map<std::string, int32_t> _analyzer_name_to_tag_type;
};

} // namespace spicy

extern spicy::Manager* spicy_mgr;

} // namespace zeek

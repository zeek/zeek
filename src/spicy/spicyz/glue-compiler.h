// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>
#include <hilti/rt/types/port.h>
#include <hilti/rt/util.h>

#include <spicy/rt/mime.h>

#include <hilti/ast/builder/builder.h>
#include <hilti/ast/declarations/function.h>
#include <hilti/ast/declarations/module.h>
#include <hilti/ast/expression.h>
#include <hilti/ast/type.h>
#include <hilti/compiler/context.h>
#include <hilti/compiler/driver.h>

#include <spicy/ast/builder/builder.h>
#include <spicy/ast/declarations/unit-hook.h>
#include <spicy/ast/types/unit.h>

#include "driver.h"
#include "zeek/spicy/port-range.h"

namespace spicy::rt {
struct Parser;
}

namespace zeek::spicy {

namespace glue {

/** Representation of a Spicy protocol analyzer, parsed from an EVT file. */
struct ProtocolAnalyzer {
    // Information parsed directly from the *.evt file.
    hilti::Location location;                                  /**< Location where the analyzer was defined. */
    hilti::ID name;                                            /**< Name of the analyzer. */
    hilti::rt::Protocol protocol = hilti::rt::Protocol::Undef; /**< The transport layer the analyzer uses. */
    std::vector<::zeek::spicy::rt::PortRange> ports;           /**< The ports associated with the analyzer. */
    hilti::ID unit_name_orig; /**< The fully-qualified name of the unit type to parse the originator
                                 side. */
    hilti::ID unit_name_resp; /**< The fully-qualified name of the unit type to parse the originator
                                 side. */
    std::string replaces;     /**< Name of another analyzer this one replaces. */

    // Computed information.
    std::optional<TypeInfo> unit_orig; /**< The type of the unit to parse the originator side. */
    std::optional<TypeInfo> unit_resp; /**< The type of the unit to parse the originator side. */
};

/** Representation of a Spicy file analyzer, parsed from an EVT file. */
struct FileAnalyzer {
    // Information parsed directly from the *.evt file.
    hilti::Location location;            /**< Location where the analyzer was defined. */
    hilti::ID name;                      /**< Name of the analyzer. */
    std::vector<std::string> mime_types; /**< The mime_types associated with the analyzer. */
    hilti::ID unit_name;                 /**< The fully-qualified name of the unit type to parse with. */
    std::string replaces;                /**< Name of another analyzer this one replaces. */

    // Computed information.
    std::optional<TypeInfo> unit; /**< The type of the unit to parse the originator side. */
};

/** Representation of a Spicy packet analyzer, parsed from an EVT file. */
struct PacketAnalyzer {
    // Information parsed directly from the *.evt file.
    hilti::Location location; /**< Location where the analyzer was defined. */
    hilti::ID name;           /**< Name of the analyzer. */
    hilti::ID unit_name;      /**< The fully-qualified name of the unit type to parse with. */
    std::string replaces;     /**< Name of another analyzer this one replaces. */

    // Computed information.
    std::optional<TypeInfo> unit; /**< The type of the unit to parse the originator side. */
};

/**
 * Representation of an expression computing the value of a parameter passed
 * to Spicy-generated events.
 */
struct ExpressionAccessor {
    // Information parsed directly from the *.evt file.
    int nr;                   /**< Position of this expression in argument list. */
    std::string expression;   /**< The original string representation of the expression. */
    hilti::Location location; /**< Location where the expression was defined. */
};

/** Representation of a compiled Spicy module. */
struct SpicyModule {
    // Provided.
    hilti::ID id;                               /**< Name of the module */
    hilti::rt::filesystem::path file;           /**< The path the module was read from. */
    std::set<hilti::rt::filesystem::path> evts; /**< EVT files that refer to this module. */

    // Generated code.
    hilti::node::RetainedPtr<hilti::declaration::Module> spicy_module =
        nullptr; /**< the ``BroHooks_*.spicy`` module. */
};

/** Representation of an event parsed from an EVT file. */
struct Event {
    // Information parsed directly from the *.evt file.
    hilti::rt::filesystem::path file; /**< The path of the *.evt file we parsed this from. */
    hilti::ID name;                   /**< The name of the event. */
    hilti::ID path;                   /**< The hook path as specified in the evt file. */
    std::vector<hilti::node::RetainedPtr<hilti::declaration::Parameter>>
        parameters;                 /**< Event parameters specified in the evt file. */
    std::string condition;          /**< Condition that must be true for the event to trigger. */
    std::vector<std::string> exprs; /**< The argument expressions. */
    int priority;                   /**< Event/hook priority. */
    hilti::Location location;       /**< Location where event is defined. */

    // Computed information.
    hilti::ID hook; /**< The name of the hook triggering the event. */
    hilti::ID unit; /**< The fully qualified name of the unit type. */
    hilti::node::RetainedPtr<::spicy::type::Unit> unit_type = nullptr; /**< The Spicy type of referenced unit. */
    hilti::ID unit_module_id;                     /**< The name of the module the referenced unit is defined in. */
    hilti::rt::filesystem::path unit_module_path; /**< The path of the module that the referenced unit is defined in. */
    std::shared_ptr<glue::SpicyModule>
        spicy_module; /**< State for the Spichy module the referenced unit is defined in. */

    // Code generation.
    std::vector<ExpressionAccessor> expression_accessors; /**< One HILTI function per expression to access the value. */
};

/** Representation of an "export" statement parsed from an EVT file. */
struct Export {
    hilti::ID spicy_id;
    hilti::ID zeek_id;
    hilti::Location location;

    // Additional information for exported record types.
    bool log_all = false;        /**< mark all fields for logging in exported record */
    std::set<hilti::ID> with;    /**< fields to include in exported record */
    std::set<hilti::ID> without; /**<  fields to exclude from exported record */
    std::set<hilti::ID> logs;    /**< fields to mark for logging in exported record */

    /**
     * Checks that the information is semantically correct given the provided
     * type information. Logs any errors and returns false on failure.
     **/
    bool validate(const TypeInfo& ti) const;
};

} // namespace glue

/** Generates the glue code between Zeek and Spicy based on *.evt files. */
class GlueCompiler {
public:
    /** Constructor. */
    GlueCompiler() {}

    /** Destructor. */
    virtual ~GlueCompiler();

    /**
     * Returns the AST context in use. Only available once the driver has
     * initialized the glue compiler.
     */
    auto* context() { return _driver->context()->astContext(); }

    /**
     * Returns the AST builder in use. Only available once the driver has
     * initialized the glue compiler.
     */
    auto* builder() { return static_cast<::spicy::Builder*>(_driver->builder()); }

    /** Parses an `*.evt` file, without generating any code yet. */
    bool loadEvtFile(hilti::rt::filesystem::path& path);

    /**
     * Registers a Spicy file to generate glue code for, without generating
     * any code yet.
     *
     * @param id ID of the module
     * @param file path the module is loaded from
     */
    void addSpicyModule(const hilti::ID& id, const hilti::rt::filesystem::path& file);

    /**
     * Generates all glue code based on previously registered `*.evt` and
     * Spicy files.
     */
    bool compile();

    /** Returns all IDs that have been exported so far. */
    const auto& exportedIDs() const { return _exports; }

    /** Returns the `export` declaration for a specific type given by the Zeek-side ID, if available. */
    std::optional<glue::Export> exportForZeekID(const hilti::ID& id) const;

    /** Provides `export` details for a given record field. */
    struct ExportedField {
        bool skip = false; /**< True if field is not to be included in the exported type. */
        bool log = false;  /**< True if field is logged. */
    };

    /**
     * Retrieves the  `export` details for a given record field. If our EVT
     * file doesn't mention the field explicitly, the method returns the
     * default behavior.
     */
    ExportedField exportForField(const hilti::ID& zeek_id, const hilti::ID& field_id) const;

    using ZeekTypeCache = std::map<hilti::ID, hilti::Expression*>;

    /**
     * Generates code to convert a HILTI type to a corresponding Zeek type at
     * runtime. The code is added to the given body.
     */
    hilti::Result<hilti::Nothing> createZeekType(hilti::QualifiedType* t, const hilti::ID& id,
                                                 ::spicy::Builder* builder, ZeekTypeCache* cache) const;

    /** Return type for `recordField()`. */
    struct RecordField {
        hilti::ID id;                         /**< name of record field */
        hilti::QualifiedType* type = nullptr; /**< Spicy-side type object */
        bool is_optional;                     /**< true if field is optional */
        bool is_anonymous;                    /**< true if field is annymous */
    };

    /**
     * Helper to retrieve a list of Zeek-side record fields that converting a
     * Spicy unit to a Zeek record will yield.
     *
     * @param unit the unit type to retrieve fields for
     * @return list of fields
     */
    static std::vector<RecordField> recordFields(const ::spicy::type::Unit* unit);

protected:
    friend class Driver;

    /** Called by driver to initialized a provided glue compiler. */
    void init(Driver* driver, int zeek_version);

private:
    /**
     * Filters input EVT file by applying preprocessor directives.
     */
    void preprocessEvtFile(hilti::rt::filesystem::path& path, std::istream& in, std::ostream& out);

    /**
     * Extracts the next semicolon-terminated block from an input stream,
     * accounting for special EVT constructs like strings and comments.
     *
     * @param in stream to read from
     * @param lineno pointer to integer that will be increased with line breaks
     * @return the read block of data, with comments removed, and empty if end of
     * data has been reached; error will be set if parsing failed
     */
    hilti::Result<std::string> getNextEvtBlock(std::istream& in, int* lineno) const;

    // Parsers for parts from EVT files.
    glue::ProtocolAnalyzer parseProtocolAnalyzer(const std::string& chunk);
    glue::FileAnalyzer parseFileAnalyzer(const std::string& chunk);
    glue::PacketAnalyzer parsePacketAnalyzer(const std::string& chunk);
    glue::Event parseEvent(const std::string& chunk);
    glue::Export parseExport(const std::string& chunk);

    /** Computes the missing pieces for all `Event` instances.  */
    bool PopulateEvents();

    /**
     * Create the Spicy hook for an event that triggers a corresponding Zeek
     * event.
     */
    bool CreateSpicyHook(glue::Event* ev);

    Driver* _driver = nullptr;        /**< driver provided to Init() */
    std::optional<int> _zeek_version; /**< Zeek version provided to Init() */

    std::map<hilti::ID, std::shared_ptr<glue::SpicyModule>> _spicy_modules;

    std::vector<std::pair<hilti::ID, hilti::ID>>
        _imports; /**< imports from EVT files, with ID and scope; latter is optional and can be empty */
    std::map<hilti::ID, glue::Export> _exports;              /**< exports from EVT files */
    std::vector<glue::Event> _events;                        /**< events parsed from EVT files */
    std::vector<glue::ProtocolAnalyzer> _protocol_analyzers; /**< protocol analyzers parsed from EVT files */
    std::vector<glue::FileAnalyzer> _file_analyzers;         /**< file analyzers parsed from EVT files */
    std::vector<glue::PacketAnalyzer> _packet_analyzers;     /**< file analyzers parsed from EVT files */
    std::vector<hilti::Location> _locations;                 /**< location stack during parsing EVT files */

    std::string _doc_id;          /**< name/ID associated with the current EVT module inside Zeekygen documentation */
    std::string _doc_description; /**< textual description to be included for the current EVT module inside Zeekygen
                                     documentation */
};
} // namespace zeek::spicy

namespace std {
template<>
struct hash<zeek::spicy::glue::Event> {
    std::size_t operator()(const zeek::spicy::glue::Event& e) {
        // We only hash enough information here to unique identify the event.
        return hilti::rt::hashCombine(std::hash<std::string>()(e.file), std::hash<std::string>()(e.name),
                                      std::hash<std::string>()(e.path), std::hash<std::string>()(e.location));
    }
};
} // namespace std

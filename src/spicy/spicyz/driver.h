// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include <hilti/rt/filesystem.h>

#include <spicy/rt/driver.h>

#include <hilti/ast/declaration.h>
#include <hilti/ast/id.h>
#include <hilti/ast/type.h>
#include <hilti/base/logger.h>
#include <hilti/compiler/driver.h>

#include <spicy/compiler/driver.h>

// Debug stream for compiler messages.
static const ::hilti::logging::DebugStream ZeekPlugin("zeek");

// Macro helper to report debug messages.
#define SPICY_DEBUG(msg) HILTI_DEBUG(ZeekPlugin, std::string(msg));

namespace zeek::spicy {

class GlueCompiler;

struct TypeInfo {
    hilti::ID id;                        /**< fully-qualified name of the type */
    hilti::Type type;                    /**< the type itself */
    hilti::declaration::Linkage linkage; /**< linkage of of the type's declaration */
    bool is_resolved = false; /**< true if we are far enough in processing that the type has been fully resolved */
    hilti::ID module_id;      /**< name of module type is defined in */
    hilti::rt::filesystem::path module_path; /**< path of module that type is defined in */
    hilti::Location location;                /**< location of type's declaration */
};

/** Spicy compilation driver. */
class Driver : public ::spicy::Driver {
public:
    /**
     * Constructor.
     *
     * @param argv0 path to current executable, or empty to determine automatically
     * @param lib_path Path to library files the Spicy support needs
     * @param zeek_version Version number of Zeek we're working with
     */
    Driver(std::unique_ptr<GlueCompiler> glue, const char* argv0, hilti::rt::filesystem::path lib_path,
           int zeek_version);

    /** Destructor. */
    ~Driver();

    /**
     * Schedules an *.spicy, *.evt, or *.hlt file for loading. Note that it
     * won't necessarily load them all immediately, but may queue some for
     * later processing.
     *
     * @param file file to load, which will be searched across all current search paths
     * @param relative_to if given, relative paths will be interpreted as relative to this directory
     */
    hilti::Result<hilti::Nothing> loadFile(hilti::rt::filesystem::path file,
                                           const hilti::rt::filesystem::path& relative_to = {});

    /**
     * After user scripts have been read, compiles and links all resulting
     * Spicy code. Note that compiler and driver options must have been set
     * before calling this.
     *
     * Must be called before any packet processing starts.
     *
     * @return False if an error occurred. It will have been reported already.
     */
    hilti::Result<hilti::Nothing> compile();

    /**
     * Returns meta information for a type. The Spicy module defining the type
     * must have been compiled already for it to be found.
     *
     * @param id fully qualified name of type to look up
     * @return meta data, or an error if the type is not (yet) known
     */
    hilti::Result<TypeInfo> lookupType(const hilti::ID& id);

    /**
     * Returns meta information for a type, enforcing it to be a of a certain
     * kind. The Spicy module defining the type must have been compiled already
     * for it to be found.
     *
     * @tparam T type to enforce; method will return an error if type is not of this class
     * @param id fully qualified name of type to look up
     * @return meta data, or an error if the type is not (yet) known
     */
    template<typename T>
    hilti::Result<TypeInfo> lookupType(const hilti::ID& id) {
        auto ti = lookupType(id);
        if ( ! ti )
            return ti.error();

        if ( ! ti->type.isA<T>() )
            return hilti::result::Error(hilti::util::fmt("'%s' is not of expected type", id));

        return ti;
    }

    /**
     * Returns all types seen so far during processing of Spicy files.
     * Depending on where we are at with processing, these may or may not be
     * resolved yet (as indicated by their `is_resolved` field).

     * @return list of types
     */
    std::vector<TypeInfo> types() const;

    /**
     * Returns all *exported* types seen so far during processing of Spicy
     * files, including their desired Zeek-side names. Depending on where we
     * are at with processing, these may or may not be resolved yet (as
     * indicated by their `is_resolved` field).
     *
     * @return list of pairs of type and Zeek-side name
     */
    std::vector<std::pair<TypeInfo, hilti::ID>> exportedTypes() const;

    /** Returns true if we're running out of the plugin's build directory. */
    bool usingBuildDirectory() const { return _using_build_directory; }

    /** Returns the glue compiler in use by the driver. */
    const auto* glueCompiler() const { return _glue.get(); }

    /**
     * Parses some options command-line style *before* Zeek-side scripts have
     * been processed. Most of the option processing happens in
     * `parseOptionsPostScript()` instead, except for things that must be in
     * place already before script processing.
     *
     * @param options space-separated string of command line argument to parse
     * @return success if all argument could be parsed, or a suitable error message
     */
    static hilti::Result<hilti::Nothing> parseOptionsPreScript(const std::string& options);

    /**
     * Parses options command-line style after Zeek-side scripts have been
     * fully procssed. Most of the option processing happens here (vs. in
     * `parseOptionsPreScript()`) except for things that must be in place
     * already before script processing.
     *
     * @param options space-separated string of command line argument to parse
     * @param driver_options instance of options to update per parsed arguments
     * @param compiler_options instance of options to update per parsed arguments
     * @return success if all argument could be parsed, or a suitable error message
     */
    static hilti::Result<hilti::Nothing> parseOptionsPostScript(const std::string& options,
                                                                hilti::driver::Options* driver_options,
                                                                hilti::Options* compiler_options);

    /** Prints a usage message for options supported by `parseOptions{Pre,Post}Script()`. */
    static void usage(std::ostream& out);

protected:
    /**
     * Hook executed for all type declarations encountered in a Spicy module.
     * Derived classes may override this to add custom processing. This hooks
     * executes twices for each declaration: once before we compile the AST
     * (meaning types have not been resolved yet), and once after. The type
     * info's `is_resolved` field indicates which of the two we're in.
     *
     * @param t type's meta information
     */
    virtual void hookNewType(const TypeInfo& ti) {}

    /** Overridden from HILTI driver. */
    void hookNewASTPreCompilation(std::shared_ptr<hilti::Unit> unit) override;

    /** Overridden from HILTI driver. */
    void hookNewASTPostCompilation(std::shared_ptr<hilti::Unit> unit) override;

    /** Overridden from HILTI driver. */
    hilti::Result<hilti::Nothing> hookCompilationFinished(const hilti::Plugin& plugin) override;

    /** Overridden from HILTI driver. */
    void hookInitRuntime() override;

    /** Overridden from HILTI driver. */
    void hookFinishRuntime() override;

    std::unique_ptr<GlueCompiler> _glue;            // glue compiler in use
    std::unordered_map<hilti::ID, TypeInfo> _types; // map of Spicy type declarations encountered so far
    std::vector<TypeInfo> _public_enums;            // tracks Spicy enum types declared public, for automatic export
    bool _using_build_directory = false;            // true if we're running out of the plugin's build directory
    bool _need_glue = true;                         // true if glue code has not yet been generated
};

} // namespace zeek::spicy

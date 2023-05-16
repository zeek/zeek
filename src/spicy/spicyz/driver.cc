// See the file "COPYING" in the main distribution directory for copyright.

#include "driver.h"

#include <getopt.h>

#include <algorithm>
#include <memory>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include <spicy/rt/libspicy.h>

#include <hilti/ast/declarations/type.h>
#include <hilti/compiler/init.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/ast/types/unit.h>
#include <spicy/autogen/config.h>
#include <spicy/compiler/init.h>

#include "config.h"
#include "glue-compiler.h"

using namespace zeek::spicy;
using Driver = ::zeek::spicy::Driver;

/**
 * Visitor to type information from a HILTI AST. This extracts user-visible
 * types only, we skip any internal ones.
 */
struct VisitorTypes : public hilti::visitor::PreOrder<void, VisitorTypes> {
    explicit VisitorTypes(Driver* driver, hilti::ID module, hilti::rt::filesystem::path path, bool is_resolved)
        : driver(driver), module(std::move(module)), path(std::move(path)), is_resolved(is_resolved) {}

    void operator()(const hilti::declaration::Type& t) {
        assert(! t.type().typeID() || *t.type().typeID() == hilti::ID(module, t.id())); // ensure consistent IDs

        if ( module == hilti::ID("hilti") || module == hilti::ID("spicy_rt") || module == hilti::ID("zeek_rt") )
            return;

        types.emplace_back(TypeInfo{
            .id = hilti::ID(module, t.id()),
            .type = t.type()._clone().as<hilti::Type>(),
            .linkage = t.linkage(),
            .is_resolved = is_resolved,
            .module_id = module,
            .module_path = path,
            .location = t.meta().location(),
        });
    }

    Driver* driver;
    hilti::ID module;
    hilti::rt::filesystem::path path;
    bool is_resolved;
    std::vector<TypeInfo> types;
};

Driver::Driver(std::unique_ptr<GlueCompiler> glue, const char* argv0, hilti::rt::filesystem::path lib_path,
               int zeek_version)
    : ::spicy::Driver("<Spicy Plugin for Zeek>"), _glue(std::move(glue)) {
    _glue->Init(this, zeek_version);

    ::spicy::Configuration::extendHiltiConfiguration();
    auto options = hiltiOptions();

    // Note that, different from Spicy's own SPICY_PATH, this extends the
    // search path, it doesn't replace it.
    if ( auto path = hilti::rt::getenv("ZEEK_SPICY_PATH") ) {
        for ( const auto& dir : hilti::rt::split(*path, ":") ) {
            if ( dir.size() )
                options.library_paths.emplace_back(dir);
        }
    }

    try {
        lib_path = hilti::rt::filesystem::weakly_canonical(lib_path);

        // We make our search paths relative to the plugin library, so that the
        // plugin installation can move around.
        options.library_paths.push_back(lib_path);
    } catch ( const hilti::rt::filesystem::filesystem_error& e ) {
        ::hilti::logger().warning(
            hilti::util::fmt("invalid plugin base directory %s: %s", lib_path.native(), e.what()));
    }

    for ( const auto& i : hilti::util::split(configuration::CxxZeekIncludesDirectories(), ":") ) {
        if ( i.size() )
            options.cxx_include_paths.emplace_back(i);
    }

#ifdef DEBUG
    SPICY_DEBUG("Search paths:");

    auto hilti_options = hiltiOptions();
    for ( const auto& x : hilti_options.library_paths ) {
        SPICY_DEBUG(hilti::rt::fmt("  %s", x.native()));
    }
#endif

    setCompilerOptions(std::move(options));

    auto& config = ::spicy::configuration();
    config.preprocessor_constants["HAVE_ZEEK"] = 1;
    config.preprocessor_constants["ZEEK_VERSION"] = zeek_version;

#if SPICY_VERSION_NUMBER >= 10500
    ::hilti::init();
    ::spicy::init();
#endif
}

Driver::~Driver() {}

hilti::Result<hilti::Nothing> Driver::loadFile(hilti::rt::filesystem::path file,
                                               const hilti::rt::filesystem::path& relative_to) {
    std::error_code ec;
    if ( ! relative_to.empty() && file.is_relative() ) {
        auto p = relative_to / file;
        auto exists = hilti::rt::filesystem::exists(p, ec);

        if ( ec )
            return hilti::rt::result::Error(
                hilti::util::fmt("error computing path of %s relative to %s: %s", file, relative_to, ec.message()));

        if ( exists )
            file = p;
    }

    auto exists = hilti::rt::filesystem::exists(file, ec);

    if ( ec )
        return hilti::rt::result::Error(
            hilti::util::fmt("cannot check whether file %s exists: %s", file, ec.message()));

    if ( ! exists ) {
        if ( auto path = hilti::util::findInPaths(file, hiltiOptions().library_paths) )
            file = *path;
        else
            return hilti::result::Error(hilti::util::fmt("Spicy plugin cannot find file %s", file));
    }

    auto rpath = hilti::util::normalizePath(file);
    auto ext = rpath.extension();

    if ( ext == ".evt" ) {
        SPICY_DEBUG(hilti::util::fmt("Loading EVT file %s", rpath));
        if ( _glue->loadEvtFile(rpath) )
            return hilti::Nothing();
        else
            return hilti::result::Error(hilti::util::fmt("error loading EVT file %s", rpath));
    }

    if ( ext == ".spicy" ) {
        SPICY_DEBUG(hilti::util::fmt("Loading Spicy file %s", rpath));
        if ( auto rc = addInput(rpath); ! rc )
            return rc.error();

        return hilti::Nothing();
    }

    if ( ext == ".hlt" ) {
        SPICY_DEBUG(hilti::util::fmt("Loading HILTI file %s", rpath));
        if ( auto rc = addInput(rpath) )
            return hilti::Nothing();
        else
            return rc.error();
    }

    if ( ext == ".hlto" ) {
        SPICY_DEBUG(hilti::util::fmt("Loading precompiled HILTI code %s", rpath));
        if ( auto rc = addInput(rpath) )
            return hilti::Nothing();
        else
            return rc.error();
    }

    if ( ext == ".cc" || ext == ".cxx" ) {
        SPICY_DEBUG(hilti::util::fmt("Loading C++ code %s", rpath));
        if ( auto rc = addInput(rpath) )
            return hilti::Nothing();
        else
            return rc.error();
    }

    return hilti::result::Error(hilti::util::fmt("unknown file type passed to Spicy loader: %s", rpath));
}

hilti::Result<hilti::Nothing> Driver::compile() {
    if ( ! hasInputs() )
        return hilti::Nothing();

    SPICY_DEBUG("Running Spicy driver");

    if ( auto x = ::spicy::Driver::compile(); ! x )
        return x.error();

    SPICY_DEBUG("Done with Spicy driver");
    return hilti::Nothing();
}

hilti::Result<TypeInfo> Driver::lookupType(const hilti::ID& id) {
    if ( auto x = _types.find(id); x != _types.end() )
        return x->second;
    else
        return hilti::result::Error(hilti::util::fmt("unknown type '%s'", id));
}

std::vector<TypeInfo> Driver::types() const {
    std::vector<TypeInfo> result;
    result.reserve(_types.size());

    for ( const auto& t : _types )
        result.push_back(t.second);

    return result;
}

std::vector<std::pair<TypeInfo, hilti::ID>> Driver::exportedTypes() const {
    std::vector<std::pair<TypeInfo, hilti::ID>> result;

    for ( const auto& [spicy_id, zeek_id, _] : _glue->exportedIDs() ) {
        if ( auto t = _types.find(spicy_id); t != _types.end() )
            result.emplace_back(t->second, zeek_id);
        else {
            hilti::logger().error(hilti::rt::fmt("unknown type '%s' exported", spicy_id));
            continue;
        }
    }

    // Automatically export public enums for backwards compatibility.
    for ( const auto& t : _public_enums )
        result.emplace_back(t, t.id);

    return result;
}

void Driver::hookNewASTPreCompilation(std::shared_ptr<hilti::Unit> unit) {
    if ( unit->extension() != ".spicy" )
        return;

    if ( unit->path().empty() )
        // Ignore modules constructed in memory.
        return;

    auto v = VisitorTypes(this, unit->id(), unit->path(), false);
    for ( auto i : v.walk(unit->module()) )
        v.dispatch(i);

    for ( const auto& ti : v.types ) {
        SPICY_DEBUG(hilti::util::fmt("  Got type '%s' (pre-compile)", ti.id));
        _types[ti.id] = ti;

        if ( auto et = ti.type.tryAs<hilti::type::Enum>(); et && ti.linkage == hilti::declaration::Linkage::Public ) {
            SPICY_DEBUG("    Automatically exporting public enum for backwards compatibility");
            _public_enums.push_back(ti);
        }

        hookNewType(ti);
    }
}

void Driver::hookNewASTPostCompilation(std::shared_ptr<hilti::Unit> unit) {
    if ( unit->extension() != ".spicy" )
        return;

    if ( unit->path().empty() )
        // Ignore modules constructed in memory.
        return;

    auto v = VisitorTypes(this, unit->id(), unit->path(), true);
    for ( auto i : v.walk(unit->module()) )
        v.dispatch(i);

    for ( auto&& t : v.types ) {
        SPICY_DEBUG(hilti::util::fmt("  Got type '%s' (post-compile)", t.id));
        _types[t.id] = t;
        hookNewType(t);
    }

    _glue->addSpicyModule(unit->id(), unit->path());
}

hilti::Result<hilti::Nothing> Driver::hookCompilationFinished(const hilti::Plugin& plugin) {
    if ( ! _need_glue )
        return hilti::Nothing();

    _need_glue = false;

    if ( _glue->compile() )
        return hilti::Nothing();
    else
        return hilti::result::Error("glue compilation failed");
}

void Driver::hookInitRuntime() { ::spicy::rt::init(); }

void Driver::hookFinishRuntime() { ::spicy::rt::done(); }

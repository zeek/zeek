// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/spicy/manager.h"

#include <dlfcn.h>
#include <glob.h>

#include <exception>
#include <limits>
#include <utility>

#include <hilti/rt/configuration.h>
#include <hilti/rt/filesystem.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/init.h>
#include <hilti/rt/library.h>
#include <hilti/rt/logging.h>
#include <hilti/rt/types/vector.h>
#include <hilti/rt/util.h>

#include <spicy/rt/configuration.h>
#include <spicy/rt/init.h>
#include <spicy/rt/parser.h>

#include <hilti/autogen/config.h>

#include <zeek/analyzer/Manager.h>
#include <zeek/file_analysis/Manager.h>
#include <zeek/packet_analysis/Manager.h>

#include "zeek/DebugLogger.h"
#include "zeek/spicy/file-analyzer.h"
#include "zeek/spicy/packet-analyzer.h"
#include "zeek/spicy/protocol-analyzer.h"
#include "zeek/zeek-config-paths.h"

using namespace zeek;
using namespace zeek::spicy;

// Split an potentially scoped ID into namespace and local part.
static std::pair<std::string, std::string> parseID(const std::string& s) {
    if ( auto i = s.rfind("::"); i != std::string::npos )
        return std::make_pair(s.substr(0, i), s.substr(i + 2));
    else
        return std::make_pair("", s);
}

Manager::~Manager() {}

void Manager::registerProtocolAnalyzer(const std::string& name, hilti::rt::Protocol proto,
                                       const hilti::rt::Vector<::zeek::spicy::rt::PortRange>& ports,
                                       const std::string& parser_orig, const std::string& parser_resp,
                                       const std::string& replaces, const std::string& linker_scope) {
    SPICY_DEBUG(hilti::rt::fmt("Have Spicy protocol analyzer %s", name));

    ProtocolAnalyzerInfo info;
    info.name_analyzer = name;
    info.name_parser_orig = parser_orig;
    info.name_parser_resp = parser_resp;
    info.name_replaces = replaces;
    info.name_zeek = hilti::rt::replace(name, "::", "_");
    info.name_zeekygen = hilti::rt::fmt("<Spicy-%s>", name);
    info.protocol = proto;
    info.ports = ports;
    info.linker_scope = linker_scope;

    // We may have that analyzer already iff it was previously pre-registered
    // without a linker scope. We'll then only set the scope now.
    if ( auto t = _analyzer_name_to_tag_type.find(info.name_zeek); t != _analyzer_name_to_tag_type.end() ) {
        SPICY_DEBUG(hilti::rt::fmt("Updating already registered protocol analyzer %s", name));

        auto& existing = _protocol_analyzers_by_type.at(t->second);
        assert(existing.name_analyzer == name);
        existing.linker_scope = info.linker_scope;

        // If the infos don't match now, we have two separate definitions.
        if ( info != existing )
            reporter->FatalError("redefinition of protocol analyzer %s", info.name_analyzer.c_str());

        return;
    }

    analyzer::Component::factory_callback factory = nullptr;

#if SPICY_VERSION_NUMBER >= 10700
    auto proto_ = proto.value();
#else
    auto proto_ = proto;
#endif

    switch ( proto_ ) {
        case hilti::rt::Protocol::TCP: factory = spicy::rt::TCP_Analyzer::InstantiateAnalyzer; break;
        case hilti::rt::Protocol::UDP: factory = spicy::rt::UDP_Analyzer::InstantiateAnalyzer; break;
        default: reporter->Error("unsupported protocol in analyzer"); return;
    }

    auto c = new ::zeek::analyzer::Component(info.name_zeek, factory, 0);
    AddComponent(c);

    // Hack to prevent Zeekygen from reporting the ID as not having a
    // location during the following initialization step.
    ::zeek::detail::zeekygen_mgr->Script(info.name_zeekygen);
    ::zeek::detail::set_location(makeLocation(info.name_zeekygen));

    // TODO: Should Zeek do this? It has run component intiialization at
    // this point already, so ours won't get initialized anymore.
    c->Initialize();

    trackComponent(c, c->Tag().Type()); // Must come after Initialize().

    info.type = c->Tag().Type();
    _protocol_analyzers_by_type.resize(info.type + 1);
    _protocol_analyzers_by_type[info.type] = info;
}

void Manager::registerFileAnalyzer(const std::string& name, const hilti::rt::Vector<std::string>& mime_types,
                                   const std::string& parser, const std::string& replaces,
                                   const std::string& linker_scope) {
    SPICY_DEBUG(hilti::rt::fmt("Have Spicy file analyzer %s", name));

    FileAnalyzerInfo info;
    info.name_analyzer = name;
    info.name_parser = parser;
    info.name_replaces = replaces;
    info.name_zeek = hilti::rt::replace(name, "::", "_");
    info.name_zeekygen = hilti::rt::fmt("<Spicy-%s>", name);
    info.mime_types = mime_types;
    info.linker_scope = linker_scope;

    // We may have that analyzer already iff it was previously pre-registered
    // without a linker scope. We'll then only set the scope now.
    if ( auto t = _analyzer_name_to_tag_type.find(info.name_zeek); t != _analyzer_name_to_tag_type.end() ) {
        SPICY_DEBUG(hilti::rt::fmt("Updating already registered packet analyzer %s", name));

        auto& existing = _file_analyzers_by_type.at(t->second);
        existing.linker_scope = info.linker_scope;

        // If the infos don't match now, we have two separate definitions.
        if ( info != existing )
            reporter->FatalError("redefinition of file analyzer %s", info.name_analyzer.c_str());

        return;
    }

    auto c = new ::zeek::file_analysis::Component(info.name_zeek, spicy::rt::FileAnalyzer::InstantiateAnalyzer, 0);
    AddComponent(c);

    // Hack to prevent Zeekygen from reporting the ID as not having a
    // location during the following initialization step.
    ::zeek::detail::zeekygen_mgr->Script(info.name_zeekygen);
    ::zeek::detail::set_location(makeLocation(info.name_zeekygen));

    // TODO: Should Zeek do this? It has run component intiialization at
    // this point already, so ours won't get initialized anymore.
    c->Initialize();

    trackComponent(c, c->Tag().Type()); // Must come after Initialize().

    info.type = c->Tag().Type();
    _file_analyzers_by_type.resize(info.type + 1);
    _file_analyzers_by_type[info.type] = info;
}

void Manager::registerPacketAnalyzer(const std::string& name, const std::string& parser, const std::string& replaces,
                                     const std::string& linker_scope) {
    SPICY_DEBUG(hilti::rt::fmt("Have Spicy packet analyzer %s", name));

    PacketAnalyzerInfo info;
    info.name_analyzer = name;
    info.name_replaces = replaces;
    info.name_parser = parser;
    info.name_zeek = hilti::rt::replace(name, "::", "_");
    info.name_zeekygen = hilti::rt::fmt("<Spicy-%s>", info.name_zeek);
    info.linker_scope = linker_scope;

    // We may have that analyzer already iff it was previously pre-registered
    // without a linker scope. We'll then set the scope now.
    if ( auto t = _analyzer_name_to_tag_type.find(info.name_zeek); t != _analyzer_name_to_tag_type.end() ) {
        SPICY_DEBUG(hilti::rt::fmt("Updating already registered packet analyzer %s", name));

        auto& existing = _packet_analyzers_by_type.at(t->second);
        assert(existing.name_analyzer == name);
        existing.linker_scope = info.linker_scope;

        // If the infos don't match now, we have two separate definitions.
        if ( info != existing )
            reporter->FatalError("redefinition of packet analyzer %s", info.name_analyzer.c_str());

        return;
    }

    auto instantiate = [info]() -> packet_analysis::AnalyzerPtr {
        return spicy::rt::PacketAnalyzer::Instantiate(info.name_zeek);
    };

    auto c = new ::zeek::packet_analysis::Component(info.name_zeek, instantiate, 0);
    AddComponent(c);

    // Hack to prevent Zeekygen from reporting the ID as not having a
    // location during the following initialization step.
    ::zeek::detail::zeekygen_mgr->Script(info.name_zeekygen);
    ::zeek::detail::set_location(makeLocation(info.name_zeekygen));

    // TODO: Should Zeek do this? It has run component intialization at
    // this point already, so ours won't get initialized anymore.
    c->Initialize();

    trackComponent(c, c->Tag().Type()); // Must come after Initialize().

    info.type = c->Tag().Type();
    _packet_analyzers_by_type.resize(info.type + 1);
    _packet_analyzers_by_type[info.type] = info;
}

void Manager::registerType(const std::string& id, const TypePtr& type) {
    auto [ns, local] = parseID(id);

    if ( const auto& old = detail::lookup_ID(local.c_str(), ns.c_str(), true) ) {
        // This is most likely to trigger for IDs that other Spicy modules
        // register. If we two Spicy modules need the same type, that's ok as
        // long as they match.
        if ( ! old->IsType() ) {
            reporter->Error("Zeek type registration failed for '%s': ID already exists, but is not a type", id.c_str());
            return;
        }

        if ( ! zeek::same_type(type, old->GetType()) ) {
            reporter->Error("Zeek type registration failed for '%s': Type already exists, but differs", id.c_str());
        }

        SPICY_DEBUG(hilti::rt::fmt("Not re-registering Zeek type %s: identical type already exists", id));
        return;
    }

    SPICY_DEBUG(hilti::rt::fmt("Registering Zeek type %s", id));
    auto zeek_id = detail::install_ID(local.c_str(), ns.c_str(), true, true);
    zeek_id->SetType(type);
    zeek_id->MakeType();
    AddBifItem(id, ::zeek::plugin::BifItem::TYPE);
}

TypePtr Manager::findType(const std::string& id) const {
    auto [ns, local] = parseID(id);

    auto zid = detail::lookup_ID(local.c_str(), ns.c_str());
    if ( ! zid )
        return nullptr;

    if ( ! zid->IsType() )
        return nullptr;

    return zid->GetType();
}

void Manager::registerEvent(const std::string& name) {
    // Create a Zeek handler for the event.
    event_registry->Register(name);

    // Install the ID into the corresponding namespace and export it.
    auto n = ::hilti::rt::split(name, "::");
    std::string mod;

    if ( n.size() > 1 )
        mod = n.front();
    else
        mod = detail::GLOBAL_MODULE_NAME;

    if ( auto id = detail::lookup_ID(name.c_str(), mod.c_str(), false, false, false) ) {
        // Auto-export IDs that already exist.
        id->SetExport();
        _events[name] = id;
    }
    else
        // This installs & exports the ID, but it doesn't set its type yet.
        // That will happen as handlers get defined. If there are no handlers,
        // we set a dummy type in the plugin's InitPostScript
        _events[name] = detail::install_ID(name.c_str(), mod.c_str(), false, true);
}

const ::spicy::rt::Parser* Manager::parserForProtocolAnalyzer(const Tag& tag, bool is_orig) {
    if ( is_orig )
        return _protocol_analyzers_by_type[tag.Type()].parser_orig;
    else
        return _protocol_analyzers_by_type[tag.Type()].parser_resp;
}

const ::spicy::rt::Parser* Manager::parserForFileAnalyzer(const Tag& tag) {
    return _file_analyzers_by_type[tag.Type()].parser;
}

const ::spicy::rt::Parser* Manager::parserForPacketAnalyzer(const Tag& tag) {
    return _packet_analyzers_by_type[tag.Type()].parser;
}

Tag Manager::tagForProtocolAnalyzer(const Tag& tag) {
    if ( auto r = _protocol_analyzers_by_type[tag.Type()].replaces )
        return r;
    else
        return tag;
}

Tag Manager::tagForFileAnalyzer(const Tag& tag) {
    if ( auto r = _file_analyzers_by_type[tag.Type()].replaces )
        return r;
    else
        return tag;
}

Tag Manager::tagForPacketAnalyzer(const Tag& tag) {
    if ( auto r = _packet_analyzers_by_type[tag.Type()].replaces )
        return r;
    else
        return tag;
}

bool Manager::toggleProtocolAnalyzer(const Tag& tag, bool enable) {
    auto type = tag.Type();

    if ( type >= _protocol_analyzers_by_type.size() )
        return false;

    const auto& analyzer = _protocol_analyzers_by_type[type];

    if ( ! analyzer.type )
        // not set -> not ours
        return false;

    if ( enable ) {
        SPICY_DEBUG(hilti::rt::fmt("Enabling Spicy protocol analyzer %s", analyzer.name_analyzer));
        analyzer_mgr->EnableAnalyzer(tag);

        if ( analyzer.replaces ) {
            SPICY_DEBUG(hilti::rt::fmt("Disabling standard protocol analyzer %s", analyzer.name_analyzer));
            analyzer_mgr->DisableAnalyzer(analyzer.replaces);
        }
    }
    else {
        SPICY_DEBUG(hilti::rt::fmt("Disabling Spicy protocol analyzer %s", analyzer.name_analyzer));
        analyzer_mgr->DisableAnalyzer(tag);

        if ( analyzer.replaces ) {
            SPICY_DEBUG(hilti::rt::fmt("Re-enabling standard protocol analyzer %s", analyzer.name_analyzer));
            analyzer_mgr->EnableAnalyzer(analyzer.replaces);
        }
    }

    return true;
}

bool Manager::toggleFileAnalyzer(const Tag& tag, bool enable) {
    auto type = tag.Type();

    if ( type >= _file_analyzers_by_type.size() )
        return false;

    const auto& analyzer = _file_analyzers_by_type[type];

    if ( ! analyzer.type )
        // not set -> not ours
        return false;

    file_analysis::Component* component = file_mgr->Lookup(tag);
    file_analysis::Component* component_replaces = analyzer.replaces ? file_mgr->Lookup(analyzer.replaces) : nullptr;

    if ( ! component ) {
        // Shouldn't really happen.
        reporter->InternalError("failed to lookup file analyzer component");
        return false;
    }

    if ( enable ) {
        SPICY_DEBUG(hilti::rt::fmt("Enabling Spicy file analyzer %s", analyzer.name_analyzer));
        component->SetEnabled(true);

        if ( component_replaces ) {
            SPICY_DEBUG(hilti::rt::fmt("Disabling standard file analyzer %s", analyzer.name_analyzer));
            component_replaces->SetEnabled(false);
        }
    }
    else {
        SPICY_DEBUG(hilti::rt::fmt("Disabling Spicy file analyzer %s", analyzer.name_analyzer));
        component->SetEnabled(false);

        if ( component_replaces ) {
            SPICY_DEBUG(hilti::rt::fmt("Enabling standard file analyzer %s", analyzer.name_analyzer));
            component_replaces->SetEnabled(true);
        }
    }

    return true;
}

bool Manager::togglePacketAnalyzer(const Tag& tag, bool enable) {
    auto type = tag.Type();

    if ( type >= _packet_analyzers_by_type.size() )
        return false;

    const auto& analyzer = _packet_analyzers_by_type[type];

    if ( ! analyzer.type )
        // not set -> not ours
        return false;

    packet_analysis::Component* component = packet_mgr->Lookup(tag);
    packet_analysis::Component* component_replaces =
        analyzer.replaces ? packet_mgr->Lookup(analyzer.replaces) : nullptr;

    if ( ! component ) {
        // Shouldn't really happen.
        reporter->InternalError("failed to lookup packet analyzer component");
        return false;
    }

    if ( enable ) {
        SPICY_DEBUG(hilti::rt::fmt("Enabling Spicy packet analyzer %s", analyzer.name_analyzer));
        component->SetEnabled(true);

        if ( component_replaces ) {
            SPICY_DEBUG(hilti::rt::fmt("Disabling standard packet analyzer %s", analyzer.name_analyzer));
            component_replaces->SetEnabled(false);
        }
    }
    else {
        SPICY_DEBUG(hilti::rt::fmt("Disabling Spicy packet analyzer %s", analyzer.name_analyzer));
        component->SetEnabled(false);

        if ( component_replaces ) {
            SPICY_DEBUG(hilti::rt::fmt("Enabling standard packet analyzer %s", analyzer.name_analyzer));
            component_replaces->SetEnabled(true);
        }
    }

    return true;
}

bool Manager::toggleAnalyzer(EnumVal* tag, bool enable) {
    if ( tag->GetType() == analyzer_mgr->GetTagType() ) {
        if ( auto analyzer = analyzer_mgr->Lookup(tag) )
            return toggleProtocolAnalyzer(analyzer->Tag(), enable);
        else
            return false;
    }

    if ( tag->GetType() == file_mgr->GetTagType() ) {
        if ( auto analyzer = file_mgr->Lookup(tag) )
            return toggleFileAnalyzer(analyzer->Tag(), enable);
        else
            return false;
    }

    if ( tag->GetType() == packet_mgr->GetTagType() ) {
        if ( auto analyzer = packet_mgr->Lookup(tag) )
            return togglePacketAnalyzer(analyzer->Tag(), enable);
        else
            return false;
    }

    return false;
}

static std::unique_ptr<detail::Location> _makeLocation(const std::string& location) {
    static std::set<std::string> filenames; // see comment below in parse_location

    auto parse_location = [](const auto& s) -> std::unique_ptr<detail::Location> {
        // This is not so great; In the HILTI runtome we pass locations
        // around as string. To pass them to Zeek, we need to unsplit the
        // strings into file name and line number. Zeek also won't clean up
        // the file names, so we need to track them ourselves.
        auto x = hilti::rt::split(s, ":");
        if ( x[0].empty() )
            return nullptr;

        auto loc = std::make_unique<detail::Location>();
        loc->filename = filenames.insert(std::string(x[0])).first->c_str(); // we retain ownership

        if ( x.size() >= 2 ) {
            auto y = hilti::rt::split(x[1], "-");
            if ( y.size() >= 2 ) {
                loc->first_line = std::stoi(std::string(y[0]));
                loc->last_line = std::stoi(std::string(y[1]));
            }
            else if ( y[0].size() )
                loc->first_line = loc->last_line = std::stoi(std::string(y[0]));
        }

        return loc;
    };

    if ( location.size() )
        return parse_location(location);
    else if ( auto hilti_location = hilti::rt::debug::location() )
        return parse_location(hilti_location);
    else
        return nullptr;
}

void Manager::analyzerError(analyzer::Analyzer* a, const std::string& msg, const std::string& location) {
    auto zeek_location = _makeLocation(location);
    reporter->PushLocation(zeek_location.get());
    reporter->AnalyzerError(a, "%s", msg.c_str());
    reporter->PopLocation();
}

void Manager::analyzerError(file_analysis::Analyzer* a, const std::string& msg, const std::string& location) {
    auto zeek_location = _makeLocation(location);
    reporter->PushLocation(zeek_location.get());

    // We don't have an reporter error for file analyzers, so we log this as a
    // weird instead.
    if ( a && a->GetFile() )
        reporter->Weird(a->GetFile(), "file_error", msg.c_str());
    else
        reporter->Weird("file_error", msg.c_str());

    reporter->PopLocation();

    if ( a )
        a->SetSkip(1); // Imitate what AnalyzerError() does for protocol analyzers.
}

void Manager::analyzerError(packet_analysis::Analyzer* a, const std::string& msg, const std::string& location) {
    auto zeek_location = _makeLocation(location);
    reporter->PushLocation(zeek_location.get());
    // We don't have an reporter error for packet analyzers, so we log
    // this as a weird instead.
    reporter->Weird("packet_error", msg.c_str());
    reporter->PopLocation();
}

plugin::Configuration Manager::Configure() {
    ::zeek::plugin::Configuration config;
    config.name = "Zeek::Spicy";
    config.description = "Support for Spicy parsers (*.hlto)";

    EnableHook(::zeek::plugin::HOOK_LOAD_FILE);

    return config;
}

void Manager::InitPreScript() {
    SPICY_DEBUG("Beginning pre-script initialization");

#if SPICY_VERSION_NUMBER >= 10700
    hilti::rt::executeManualPreInits();
#endif

    autoDiscoverModules();

    SPICY_DEBUG("Done with pre-script initialization");
}

// Returns a port's Zeek-side transport protocol.
static ::TransportProto transport_protocol(const hilti::rt::Port port) {
#if SPICY_VERSION_NUMBER >= 10700
    auto proto = port.protocol().value();
#else
    auto proto = port.protocol();
#endif

    switch ( proto ) {
        case hilti::rt::Protocol::TCP: return ::TransportProto::TRANSPORT_TCP;
        case hilti::rt::Protocol::UDP: return ::TransportProto::TRANSPORT_UDP;
        case hilti::rt::Protocol::ICMP: return ::TransportProto::TRANSPORT_ICMP;
        default:
            reporter->InternalError("unsupported transport protocol in port '%s' for Zeek conversion",
                                    std::string(port).c_str());
            return ::TransportProto::TRANSPORT_UNKNOWN;
    }
}

static void hook_accept_input() {
    auto cookie = static_cast<rt::Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = cookie->protocol ) {
        auto tag = spicy_mgr->tagForProtocolAnalyzer(x->analyzer->GetAnalyzerTag());
        SPICY_DEBUG(hilti::rt::fmt("confirming protocol %s", tag.AsString()));
        return x->analyzer->AnalyzerConfirmation(tag);
    }
}

static void hook_decline_input(const std::string& reason) {
    auto cookie = static_cast<rt::Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = cookie->protocol ) {
        auto tag = spicy_mgr->tagForProtocolAnalyzer(x->analyzer->GetAnalyzerTag());
        SPICY_DEBUG(hilti::rt::fmt("rejecting protocol %s", tag.AsString()));
        return x->analyzer->AnalyzerViolation("protocol rejected", nullptr, 0, tag);
    }
}

void Manager::InitPostScript() {
    SPICY_DEBUG("Beginning post-script initialization");

    disableReplacedAnalyzers();

    // If there's no handler for one of our events, it won't have received a
    // type. Give it a dummy event type in that case, so that we don't walk
    // around with a nullptr.
    for ( const auto& [name, id] : _events ) {
        if ( ! id->GetType() ) {
            auto args = make_intrusive<RecordType>(new type_decl_list());
            auto et = make_intrusive<FuncType>(std::move(args), base_type(TYPE_VOID), FUNC_FLAVOR_EVENT);
            id->SetType(std::move(et));
        }
    }

    // Init runtime, which will trigger all initialization code to execute.
    SPICY_DEBUG("Initializing Spicy runtime");

    auto hilti_config = hilti::rt::configuration::get();

    if ( id::find_const("Spicy::enable_print")->AsBool() ) // NOLINT(clang-analyzer-cplusplus.NewDeleteLeaks)
        hilti_config.cout = std::cout;
    else
        hilti_config.cout.reset();

    if ( id::find_const("Spicy::enable_profiling")->AsBool() )
#if SPICY_VERSION_NUMBER >= 10800
        hilti_config.enable_profiling = true;
#else
        std::cerr << "Profiling is not supported with this version of Spicy, ignoring "
                     "'Spicy::enable_profiling'\n";
#endif

    hilti_config.abort_on_exceptions = id::find_const("Spicy::abort_on_exceptions")->AsBool();
    hilti_config.show_backtraces = id::find_const("Spicy::show_backtraces")->AsBool();

    hilti::rt::configuration::set(hilti_config);

#if SPICY_VERSION_NUMBER >= 10700
    auto spicy_config = ::spicy::rt::configuration::get();
    spicy_config.hook_accept_input = hook_accept_input;
    spicy_config.hook_decline_input = hook_decline_input;
    ::spicy::rt::configuration::set(std::move(spicy_config));
#endif

    try {
        ::hilti::rt::init();
        ::spicy::rt::init();
    } catch ( const hilti::rt::Exception& e ) {
        std::cerr << hilti::rt::fmt("uncaught runtime exception %s during initialization: %s",
                                    hilti::rt::demangle(typeid(e).name()), e.what())
                  << std::endl;
        exit(1);
    } catch ( const std::runtime_error& e ) {
        std::cerr << hilti::rt::fmt("uncaught C++ exception %s during initialization: %s",
                                    hilti::rt::demangle(typeid(e).name()), e.what())
                  << std::endl;
        exit(1);
    }

    // Fill in the parser information now that we derived from the ASTs.
    auto find_parser = [](const std::string& analyzer, const std::string& parser,
                          const std::string& linker_scope) -> const ::spicy::rt::Parser* {
        if ( parser.empty() )
            return nullptr;

        for ( auto p : ::spicy::rt::parsers() ) {
            if ( p->name == parser && p->linker_scope == linker_scope )
                return p;
        }

        reporter->InternalError("Unknown Spicy parser '%s' requested by analyzer '%s'", parser.c_str(),
                                analyzer.c_str());

        return nullptr; // cannot be reached
    };

    for ( auto& p : _protocol_analyzers_by_type ) {
        if ( p.type == 0 )
            // vector element not set
            continue;

        SPICY_DEBUG(hilti::rt::fmt("Registering %s protocol analyzer %s with Zeek", p.protocol, p.name_analyzer));

        p.parser_orig = find_parser(p.name_analyzer, p.name_parser_orig, p.linker_scope);
        p.parser_resp = find_parser(p.name_analyzer, p.name_parser_resp, p.linker_scope);

        // Register analyzer for its well-known ports.
        auto tag = analyzer_mgr->GetAnalyzerTag(p.name_zeek.c_str());
        if ( ! tag )
            reporter->InternalError("cannot get analyzer tag for '%s'", p.name_analyzer.c_str());

        for ( const auto& ports : p.ports ) {
            const auto proto = ports.begin.protocol();

            // Port ranges are closed intervals.
            for ( auto port = ports.begin.port(); port <= ports.end.port(); ++port ) {
                const auto port_ = hilti::rt::Port(port, proto);
                SPICY_DEBUG(hilti::rt::fmt("  Scheduling analyzer for port %s", port_));
                analyzer_mgr->RegisterAnalyzerForPort(tag, transport_protocol(port_), port);

                // Don't double register in case of single-port ranges.
                if ( ports.begin.port() == ports.end.port() )
                    break;

                // Explicitly prevent overflow.
                if ( port == std::numeric_limits<decltype(port)>::max() )
                    break;
            }
        }

        if ( p.parser_resp ) {
            for ( auto port : p.parser_resp->ports ) {
                if ( port.direction != ::spicy::rt::Direction::Both &&
                     port.direction != ::spicy::rt::Direction::Responder )
                    continue;

                SPICY_DEBUG(hilti::rt::fmt("  Scheduling analyzer for port %s", port.port));
                analyzer_mgr->RegisterAnalyzerForPort(tag, transport_protocol(port.port), port.port.port());
            }
        }
    }

    for ( auto& p : _file_analyzers_by_type ) {
        if ( p.type == 0 )
            // vector element not set
            continue;

        SPICY_DEBUG(hilti::rt::fmt("Registering file analyzer %s with Zeek", p.name_analyzer.c_str()));

        p.parser = find_parser(p.name_analyzer, p.name_parser, p.linker_scope);

        // Register analyzer for its MIME types.
        auto tag = file_mgr->GetComponentTag(p.name_zeek.c_str());
        if ( ! tag )
            reporter->InternalError("cannot get analyzer tag for '%s'", p.name_analyzer.c_str());

        auto register_analyzer_for_mime_type = [&](auto tag, const std::string& mt) {
            SPICY_DEBUG(hilti::rt::fmt("  Scheduling analyzer for MIME type %s", mt));

            // MIME types are registered in scriptland, so we'll raise an
            // event that will do it for us through a predefined handler.
            zeek::Args vals = Args();
            vals.emplace_back(tag.AsVal());
            vals.emplace_back(make_intrusive<StringVal>(mt));
            EventHandlerPtr handler = event_registry->Register("spicy_analyzer_for_mime_type");
            event_mgr.Enqueue(handler, vals);
        };

        for ( const auto& mt : p.mime_types )
            register_analyzer_for_mime_type(tag, mt);

        if ( p.parser ) {
            for ( const auto& mt : p.parser->mime_types )
                register_analyzer_for_mime_type(tag, mt);
        }
    }

    for ( auto& p : _packet_analyzers_by_type ) {
        if ( p.type == 0 )
            // vector element not set
            continue;

        SPICY_DEBUG(hilti::rt::fmt("Registering packet analyzer %s with Zeek", p.name_analyzer.c_str()));
        p.parser = find_parser(p.name_analyzer, p.name_parser, p.linker_scope);
    }

    SPICY_DEBUG("Done with post-script initialization");
}

void Manager::Done() {
    SPICY_DEBUG("Shutting down Spicy runtime");
    ::spicy::rt::done();
    hilti::rt::done();
}

void Manager::loadModule(const hilti::rt::filesystem::path& path) {
    try {
        // If our auto discovery ends up finding the same module multiple times,
        // we ignore subsequent requests.
        std::error_code ec;
        auto canonical_path = hilti::rt::filesystem::canonical(path, ec);
        if ( ec )
            hilti::rt::fatalError(hilti::rt::fmt("could not compute canonical path for %s: %s", path, ec.message()));

        if ( auto [library, inserted] = _libraries.insert({canonical_path, hilti::rt::Library(canonical_path)});
             inserted ) {
            SPICY_DEBUG(hilti::rt::fmt("Loading %s", canonical_path.native()));
            if ( auto load = library->second.open(); ! load )
                hilti::rt::fatalError(
                    hilti::rt::fmt("could not open library path %s: %s", canonical_path, load.error()));
        }
        else {
            SPICY_DEBUG(hilti::rt::fmt("Ignoring duplicate loading request for %s", canonical_path.native()));
        }
#if SPICY_VERSION_NUMBER >= 10700
    } catch ( const ::hilti::rt::UsageError& e ) {
#else
    } catch ( const ::hilti::rt::UserException& e ) {
#endif
        hilti::rt::fatalError(e.what());
    }
}

int Manager::HookLoadFile(const LoadType type, const std::string& file, const std::string& resolved) {
    auto ext = hilti::rt::filesystem::path(file).extension();

    if ( ext == ".hlto" ) {
        loadModule(file);
        return 1;
    }

    if ( ext == ".spicy" || ext == ".evt" || ext == ".hlt" )
        reporter->FatalError("cannot load '%s': analyzers need to be precompiled with 'spicyz' ", file.c_str());

    return -1;
}

void Manager::searchModules(const std::string& paths) {
    for ( const auto& dir : hilti::rt::split(paths, ":") ) {
        auto trimmed_dir = hilti::rt::trim(dir);
        if ( trimmed_dir.empty() )
            continue;

        std::error_code ec;
        if ( auto is_directory = hilti::rt::filesystem::is_directory(trimmed_dir, ec); ec || ! is_directory ) {
            SPICY_DEBUG(hilti::rt::fmt("Module directory %s cannot be read, skipping", trimmed_dir));
            continue;
        }

        SPICY_DEBUG(hilti::rt::fmt("Searching %s for *.hlto", trimmed_dir));

        auto it = hilti::rt::filesystem::recursive_directory_iterator(trimmed_dir, ec);
        if ( ! ec ) {
            while ( it != hilti::rt::filesystem::recursive_directory_iterator() ) {
                if ( it->is_regular_file() && it->path().extension() == ".hlto" )
                    loadModule(it->path());

                if ( it.increment(ec); ec ) {
                    hilti::rt::warning(hilti::rt::fmt("Error iterating over %s, skipping any remaining files: %s",
                                                      trimmed_dir, ec.message()));
                    break;
                }
            }
        }
        else
            hilti::rt::warning(hilti::rt::fmt("Cannot iterate over %s, skipping: %s", trimmed_dir, ec.message()));
    }
};

detail::Location Manager::makeLocation(const std::string& fname) {
    auto x = _locations.insert(fname);
    return detail::Location(x.first->c_str(), 0, 0, 0, 0);
}

void Manager::autoDiscoverModules() {
    // Always search Zeek's plugin path for modules, that's where zkg puts
    // them.
    searchModules(util::zeek_plugin_path());

    if ( auto search_paths = hilti::rt::getenv("ZEEK_SPICY_MODULE_PATH"); search_paths && search_paths->size() )
        // This overrides all other paths.
        searchModules(*search_paths);
    else
        searchModules(ZEEK_SPICY_MODULE_PATH);
}

void Manager::disableReplacedAnalyzers() {
    for ( auto& info : _protocol_analyzers_by_type ) {
        if ( info.name_replaces.empty() )
            continue;

        auto replaces = info.name_replaces.c_str();

        if ( file_mgr->Lookup(replaces) || packet_mgr->Lookup(replaces) )
            reporter->FatalError("cannot replace '%s' analyzer with a protocol analyzer", replaces);

        auto tag = analyzer_mgr->GetAnalyzerTag(replaces);
        if ( ! tag ) {
            SPICY_DEBUG(hilti::rt::fmt("%s is supposed to replace protocol analyzer %s, but that does not exist",
                                       info.name_analyzer, replaces));

            continue;
        }

        SPICY_DEBUG(hilti::rt::fmt("%s replaces existing protocol analyzer %s", info.name_analyzer, replaces));
        info.replaces = tag;
        analyzer_mgr->DisableAnalyzer(tag);
    }

    for ( auto& info : _file_analyzers_by_type ) {
        if ( info.name_replaces.empty() )
            continue;

        auto replaces = info.name_replaces.c_str();

        if ( analyzer_mgr->Lookup(replaces) || packet_mgr->Lookup(replaces) )
            reporter->FatalError("cannot replace '%s' analyzer with a file analyzer", replaces);

        auto component = file_mgr->Lookup(replaces);
        if ( ! component ) {
            SPICY_DEBUG(hilti::rt::fmt("%s is supposed to replace file analyzer %s, but that does not exist",
                                       info.name_analyzer, replaces));

            continue;
        }

        SPICY_DEBUG(hilti::rt::fmt("%s replaces existing file analyzer %s", info.name_analyzer, replaces));
        info.replaces = component->Tag();
        component->SetEnabled(false);
    }

    for ( auto& info : _packet_analyzers_by_type ) {
        if ( info.name_replaces.empty() )
            continue;

        auto replaces = info.name_replaces.c_str();

        auto component = packet_mgr->Lookup(replaces);
        if ( ! component ) {
            SPICY_DEBUG(hilti::rt::fmt("%s is supposed to replace packet analyzer %s, but that does not exist",
                                       info.name_analyzer, replaces));

            continue;
        }

        SPICY_DEBUG(hilti::rt::fmt("%s replaces existing packet analyzer %s", info.name_analyzer, replaces));
        info.replaces = component->Tag();
        component->SetEnabled(false);
    }
}

void Manager::trackComponent(plugin::Component* c, int32_t tag_type) {
    auto i = _analyzer_name_to_tag_type.insert({c->Name(), tag_type});
    if ( ! i.second )
        // We enforce on our end that an analyzer name can appear only once
        // across all types of analyzers. Makes things easier and avoids
        // confusion.
        reporter->FatalError("duplicate analyzer name '%s'", c->Name().c_str());
}

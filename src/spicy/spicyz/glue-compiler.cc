// See the file "COPYING" in the main distribution directory for copyright.

#include "glue-compiler.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

#include <hilti/ast/all.h>
#include <hilti/ast/builder/all.h>
#include <hilti/base/preprocessor.h>
#include <hilti/base/util.h>
#include <hilti/compiler/unit.h>

#include <spicy/ast/detail/visitor.h>
#include <spicy/global.h>

#include "config.h"
#include "zeek/spicy/port-range.h"

using namespace zeek::spicy;

namespace builder = hilti::builder;

#if SPICY_VERSION_NUMBER >= 10700
static inline auto _linker_scope() { return hilti::builder::scope(); }
#else
static inline auto _linker_scope() { return hilti::builder::call("hilti::linker_scope", {}); }
#endif

// Small parsing helpers.

using ParseError = std::runtime_error;

static void eat_spaces(const std::string& chunk, size_t* i) {
    while ( *i < chunk.size() && isspace(chunk[*i]) )
        ++*i;
}

static std::string::size_type looking_at(const std::string& chunk, std::string::size_type i,
                                         const std::string_view& token) {
    eat_spaces(chunk, &i);

    for ( char j : token ) {
        if ( i >= chunk.size() || chunk[i++] != j )
            return 0;
    }

    return i;
}

static void eat_token(const std::string& chunk, std::string::size_type* i, const std::string_view& token) {
    eat_spaces(chunk, i);

    auto j = looking_at(chunk, *i, token);

    if ( ! j )
        throw ParseError(hilti::util::fmt("expected token '%s'", token));

    *i = j;
}

static bool is_id_char(const std::string& chunk, size_t i) {
    char c = chunk[i];

    if ( isalnum(c) )
        return true;

    if ( strchr("_$%", c) != nullptr )
        return true;

    char prev = (i > 0) ? chunk[i - 1] : '\0';
    char next = (i + 1 < chunk.size()) ? chunk[i + 1] : '\0';

    if ( c == ':' && next == ':' )
        return true;

    if ( c == ':' && prev == ':' )
        return true;

    return false;
}

static bool is_path_char(const std::string& chunk, size_t i) {
    char c = chunk[i];
    return (! isspace(c)) && c != ';';
}

static hilti::ID extract_id(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    size_t j = *i;

    while ( j < chunk.size() && is_id_char(chunk, j) )
        ++j;

    if ( *i == j )
        throw ParseError("expected id");

    auto id = chunk.substr(*i, j - *i);
    *i = j;
    return hilti::ID(hilti::util::replace(id, "%", "0x25_"));
}

static hilti::Type extract_type(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    // We currently only parse Spicy types that can appear in parameters of
    // built-in hooks--which are not many.
    auto token = extract_id(chunk, i);

    if ( token == hilti::ID("string") )
        return hilti::type::String();

    if ( token == hilti::ID("uint64") )
        return hilti::type::UnsignedInteger(64);

    throw ParseError("mismatching type");
}

static hilti::type::function::Parameter extract_parameter(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    auto id = extract_id(chunk, i);

    if ( ! looking_at(chunk, *i, ":") )
        throw ParseError("expected ':'");

    eat_token(chunk, i, ":");

    auto type = extract_type(chunk, i);
    return builder::parameter(std::move(id), std::move(type));
}

static hilti::rt::filesystem::path extract_path(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    size_t j = *i;

    while ( j < chunk.size() && is_path_char(chunk, j) )
        ++j;

    if ( *i == j )
        throw ParseError("expected path");

    auto path = chunk.substr(*i, j - *i);
    *i = j;
    return path;
}

static int extract_int(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    size_t j = *i;

    if ( j < chunk.size() ) {
        if ( chunk[j] == '-' ) {
            ++j;
        }
        if ( chunk[j] == '+' )
            ++j;
    }

    while ( j < chunk.size() && isdigit(chunk[j]) )
        ++j;

    if ( *i == j )
        throw ParseError("expected integer");

    auto x = chunk.substr(*i, j - *i);
    *i = j;

    int integer = 0;
    hilti::util::atoi_n(x.begin(), x.end(), 10, &integer);
    return integer;
}

static std::string extract_expr(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    int level = 0;
    bool done = false;
    size_t j = *i;

    while ( j < chunk.size() ) {
        switch ( chunk[j] ) {
            case '(':
            case '[':
            case '{':
                ++level;
                ++j;
                continue;

            case ')':
                if ( level == 0 ) {
                    done = true;
                    break;
                }

                // fall-through

            case ']':
            case '}':
                if ( level == 0 )
                    throw ParseError("expected Spicy expression");

                --level;
                ++j;
                continue;

            case ',':
                if ( level == 0 ) {
                    done = true;
                    break;
                }

                // fall-through

            default: ++j;
        }

        if ( done )
            break;

        if ( *i == j )
            break;
    }

    auto expr = hilti::util::trim(chunk.substr(*i, j - *i));
    *i = j;
    return expr;
}

static hilti::rt::Port extract_port(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    std::string s;
    size_t j = *i;

    while ( j < chunk.size() && isdigit(chunk[j]) )
        ++j;

    if ( *i == j )
        throw ParseError("cannot parse port specification");

    hilti::rt::Protocol proto;
    uint64_t port = std::numeric_limits<uint64_t>::max();

    s = chunk.substr(*i, j - *i);
    hilti::util::atoi_n(s.begin(), s.end(), 10, &port);

    if ( port > 65535 )
        throw ParseError("port outside of valid range");

    *i = j;

    if ( chunk[*i] != '/' )
        throw ParseError("cannot parse port specification");

    (*i)++;

    if ( looking_at(chunk, *i, "tcp") ) {
        proto = hilti::rt::Protocol::TCP;
        eat_token(chunk, i, "tcp");
    }

    else if ( looking_at(chunk, *i, "udp") ) {
        proto = hilti::rt::Protocol::UDP;
        eat_token(chunk, i, "udp");
    }

    else if ( looking_at(chunk, *i, "icmp") ) {
        proto = hilti::rt::Protocol::ICMP;
        eat_token(chunk, i, "icmp");
    }

    else
        throw ParseError("cannot parse port specification");

    return {static_cast<uint16_t>(port), proto};
}

static ::zeek::spicy::rt::PortRange extract_port_range(const std::string& chunk, size_t* i) {
    auto start = extract_port(chunk, i);
    auto end = std::optional<hilti::rt::Port>();

    if ( looking_at(chunk, *i, "-") ) {
        eat_token(chunk, i, "-");
        end = extract_port(chunk, i);
    }

    if ( end ) {
        if ( start.protocol() != end->protocol() )
            throw ParseError("start and end of port range must have same protocol");

        if ( start.port() > end->port() )
            throw ParseError("start of port range cannot be after its end");
    }

    if ( ! end )
        // EVT port ranges are a closed.
        end = hilti::rt::Port(start.port(), start.protocol());

    return {start, *end};
}

void GlueCompiler::Init(Driver* driver, int zeek_version) {
    _driver = driver;
    _zeek_version = zeek_version;
}

GlueCompiler::~GlueCompiler() {}

hilti::Result<std::string> GlueCompiler::getNextEvtBlock(std::istream& in, int* lineno) const {
    std::string chunk;

    // Parser need to track whether we are inside a string or a comment.
    enum State { Default, InComment, InString } state = Default;
    char prev = '\0';

    while ( true ) {
        char cur;
        in.get(cur);
        if ( in.eof() ) {
            chunk = hilti::util::trim(chunk);
            if ( chunk.empty() )
                // Legitimate end of data.
                return std::string();
            else
                // End of input before semicolon.
                return hilti::result::Error("unexpected end of file");
        }

        switch ( state ) {
            case Default:
                if ( cur == '"' && prev != '\\' )
                    state = InString;

                if ( cur == '#' && prev != '\\' ) {
                    state = InComment;
                    continue;
                }

                if ( cur == '\n' )
                    ++*lineno;

                if ( cur == ';' ) {
                    // End of block found.
                    chunk = hilti::util::trim(chunk);
                    if ( chunk.size() )
                        return chunk + ';';
                    else
                        return hilti::result::Error("empty block");
                }

                break;

            case InString:
                if ( cur == '"' && prev != '\\' )
                    state = Default;

                if ( cur == '\n' )
                    ++*lineno;

                break;

            case InComment:
                if ( cur != '\n' )
                    // skip
                    continue;

                state = Default;
                ++*lineno;
        }

        chunk += cur;
        prev = cur;
    }
}

void GlueCompiler::preprocessEvtFile(hilti::rt::filesystem::path& path, std::istream& in, std::ostream& out) {
    hilti::util::SourceCodePreprocessor pp({{"ZEEK_VERSION", *_zeek_version}});
    int lineno = 0;

    std::string line;
    while ( std::getline(in, line) ) {
        lineno++;

        auto trimmed = hilti::util::trim(line);
        _locations.emplace_back(path, lineno);

        if ( hilti::util::startsWith(trimmed, "@") ) {
            // Output empty line to keep line numbers the same
            out << '\n';

            auto m = hilti::util::split1(trimmed);

            if ( auto rc = pp.processLine(m.first, m.second); ! rc )
                throw ParseError(rc.error());
        }

        else {
            switch ( pp.state() ) {
                case hilti::util::SourceCodePreprocessor::State::Include: out << line << '\n'; break;
                case hilti::util::SourceCodePreprocessor::State::Skip:
                    // Output empty line to keep line numbers the same
                    out << '\n';
                    break;
            }
        }
    }

    if ( pp.expectingDirective() )
        throw ParseError("unterminated preprocessor directive");
}

bool GlueCompiler::loadEvtFile(hilti::rt::filesystem::path& path) {
    assert(_zeek_version);

    std::ifstream in(path);

    if ( ! in ) {
        hilti::logger().error(hilti::util::fmt("cannot open %s", path));
        return false;
    }

    SPICY_DEBUG(hilti::util::fmt("Loading events from %s", path));

    std::vector<glue::Event> new_events;

    try {
        std::stringstream preprocessed;
        preprocessEvtFile(path, in, preprocessed);
        preprocessed.clear();
        preprocessed.seekg(0);

        int lineno = 1;

        while ( true ) {
            _locations.emplace_back(path, lineno);
            auto chunk = getNextEvtBlock(preprocessed, &lineno);
            if ( ! chunk )
                throw ParseError(chunk.error());

            if ( chunk->empty() )
                break; // end of input

            _locations.pop_back();
            _locations.emplace_back(path, lineno);

            if ( looking_at(*chunk, 0, "protocol") ) {
                auto a = parseProtocolAnalyzer(*chunk);
                SPICY_DEBUG(hilti::util::fmt("  Got protocol analyzer definition for %s", a.name));
                _protocol_analyzers.push_back(a);
            }

            else if ( looking_at(*chunk, 0, "file") ) {
                auto a = parseFileAnalyzer(*chunk);
                SPICY_DEBUG(hilti::util::fmt("  Got file analyzer definition for %s", a.name));
                _file_analyzers.push_back(a);
            }

            else if ( looking_at(*chunk, 0, "packet") ) {
                auto a = parsePacketAnalyzer(*chunk);
                SPICY_DEBUG(hilti::util::fmt("  Got packet analyzer definition for %s", a.name));
                _packet_analyzers.push_back(a);
            }

            else if ( looking_at(*chunk, 0, "on") ) {
                auto ev = parseEvent(*chunk);
                ev.file = path;
                new_events.push_back(ev);
                SPICY_DEBUG(hilti::util::fmt("  Got event definition for %s", ev.name));
            }

            else if ( looking_at(*chunk, 0, "import") ) {
                size_t i = 0;
                eat_token(*chunk, &i, "import");

                hilti::ID module = extract_id(*chunk, &i);
                std::optional<hilti::ID> scope;

                if ( looking_at(*chunk, i, "from") ) {
                    eat_token(*chunk, &i, "from");
                    scope = extract_path(*chunk, &i);
                    SPICY_DEBUG(hilti::util::fmt("  Got module %s to import from scope %s", module, *scope));
                }
                else
                    SPICY_DEBUG(hilti::util::fmt("  Got module %s to import", module));

                _imports.emplace_back(hilti::ID(module), std::move(scope));
            }

            else if ( looking_at(*chunk, 0, "export") ) {
                size_t i = 0;
                eat_token(*chunk, &i, "export");

                hilti::ID spicy_id = extract_id(*chunk, &i);
                hilti::ID zeek_id = spicy_id;

                if ( looking_at(*chunk, i, "as") ) {
                    eat_token(*chunk, &i, "as");
                    zeek_id = extract_id(*chunk, &i);
                }

                eat_spaces(*chunk, &i);
                if ( ! looking_at(*chunk, i, ";") )
                    throw ParseError("syntax error in export");

                _exports.emplace_back(std::move(spicy_id), std::move(zeek_id), _locations.back());
            }

            else
                throw ParseError("expected 'import', 'export', '{file,packet,protocol} analyzer', or 'on'");

            _locations.pop_back();
        }
    } catch ( const ParseError& e ) {
        if ( *e.what() )
            hilti::logger().error(e.what(), _locations.back());

        return false;
    }

    for ( auto&& ev : new_events )
        _events.push_back(ev);

    return true;
}

void GlueCompiler::addSpicyModule(const hilti::ID& id, const hilti::rt::filesystem::path& file) {
    glue::SpicyModule module;
    module.id = id;
    module.file = file;
    _spicy_modules[id] = std::make_shared<glue::SpicyModule>(std::move(module));
}

glue::ProtocolAnalyzer GlueCompiler::parseProtocolAnalyzer(const std::string& chunk) {
    glue::ProtocolAnalyzer a;
    a.location = _locations.back();

    size_t i = 0;

    eat_token(chunk, &i, "protocol");
    eat_token(chunk, &i, "analyzer");
    a.name = extract_id(chunk, &i).str();

    eat_token(chunk, &i, "over");

    auto proto = hilti::util::tolower(extract_id(chunk, &i).str());

    if ( proto == "tcp" )
        a.protocol = hilti::rt::Protocol::TCP;

    else if ( proto == "udp" )
        a.protocol = hilti::rt::Protocol::UDP;

    else if ( proto == "icmp" )
        a.protocol = hilti::rt::Protocol::ICMP;

    else
        throw ParseError(hilti::util::fmt("unknown transport protocol '%s'", proto));

    eat_token(chunk, &i, ":");

    enum { orig, resp, both } dir;

    while ( true ) {
        if ( looking_at(chunk, i, "parse") ) {
            eat_token(chunk, &i, "parse");

            if ( looking_at(chunk, i, "originator") ) {
                eat_token(chunk, &i, "originator");
                dir = orig;
            }

            else if ( looking_at(chunk, i, "responder") ) {
                eat_token(chunk, &i, "responder");
                dir = resp;
            }

            else if ( looking_at(chunk, i, "with") )
                dir = both;

            else
                throw ParseError("invalid \"parse with ...\" specification");

            eat_token(chunk, &i, "with");
            auto unit = extract_id(chunk, &i);

            switch ( dir ) {
                case orig: a.unit_name_orig = unit; break;

                case resp: a.unit_name_resp = unit; break;

                case both:
                    a.unit_name_orig = unit;
                    a.unit_name_resp = unit;
                    break;
            }
        }

        else if ( looking_at(chunk, i, "ports") ) {
            eat_token(chunk, &i, "ports");
            eat_token(chunk, &i, "{");

            while ( true ) {
                a.ports.push_back(extract_port_range(chunk, &i));

                if ( looking_at(chunk, i, "}") ) {
                    eat_token(chunk, &i, "}");
                    break;
                }

                eat_token(chunk, &i, ",");
            }
        }

        else if ( looking_at(chunk, i, "port") ) {
            eat_token(chunk, &i, "port");
            a.ports.push_back(extract_port_range(chunk, &i));
        }

        else if ( looking_at(chunk, i, "replaces") ) {
            eat_token(chunk, &i, "replaces");
            a.replaces = extract_id(chunk, &i);
        }

        else
            throw ParseError("unexpected token");

        if ( looking_at(chunk, i, ";") )
            break; // All done.

        eat_token(chunk, &i, ",");
    }

    return a;
}

glue::FileAnalyzer GlueCompiler::parseFileAnalyzer(const std::string& chunk) {
    glue::FileAnalyzer a;
    a.location = _locations.back();

    size_t i = 0;

    eat_token(chunk, &i, "file");
    eat_token(chunk, &i, "analyzer");
    a.name = extract_id(chunk, &i).str();

    eat_token(chunk, &i, ":");

    while ( true ) {
        if ( looking_at(chunk, i, "parse") ) {
            eat_token(chunk, &i, "parse");
            eat_token(chunk, &i, "with");
            a.unit_name = extract_id(chunk, &i);
        }

        else if ( looking_at(chunk, i, "mime-type") ) {
            eat_token(chunk, &i, "mime-type");
            auto mtype = extract_path(chunk, &i);
            a.mime_types.push_back(mtype.string());
        }

        else if ( looking_at(chunk, i, "replaces") ) {
            eat_token(chunk, &i, "replaces");
            a.replaces = extract_id(chunk, &i);
        }

        else
            throw ParseError("unexpected token");

        if ( looking_at(chunk, i, ";") )
            break; // All done.

        eat_token(chunk, &i, ",");
    }

    return a;
}

glue::PacketAnalyzer GlueCompiler::parsePacketAnalyzer(const std::string& chunk) {
    glue::PacketAnalyzer a;
    a.location = _locations.back();

    size_t i = 0;

    eat_token(chunk, &i, "packet");
    eat_token(chunk, &i, "analyzer");
    a.name = extract_id(chunk, &i).str();

    eat_token(chunk, &i, ":");

    while ( true ) {
        if ( looking_at(chunk, i, "parse") ) {
            eat_token(chunk, &i, "parse");
            eat_token(chunk, &i, "with");
            a.unit_name = extract_id(chunk, &i);
        }

        else if ( looking_at(chunk, i, "replaces") ) {
            eat_token(chunk, &i, "replaces");
            a.replaces = extract_id(chunk, &i);
        }

        else
            throw ParseError("unexpected token");

        if ( looking_at(chunk, i, ";") )
            break; // All done.

        eat_token(chunk, &i, ",");
    }

    return a;
}

glue::Event GlueCompiler::parseEvent(const std::string& chunk) {
    glue::Event ev;
    ev.location = _locations.back();

    // We use a quite negative hook priority here to make sure these run last
    // after anything the grammar defines by default.
    ev.priority = -1000;

    size_t i = 0;

    eat_token(chunk, &i, "on");
    ev.path = extract_id(chunk, &i);

    if ( looking_at(chunk, i, "(") ) {
        eat_token(chunk, &i, "(");

        if ( ! looking_at(chunk, i, ")") ) {
            while ( true ) {
                auto param = extract_parameter(chunk, &i);
                ev.parameters.push_back(std::move(param));

                if ( looking_at(chunk, i, ")") )
                    break;

                eat_token(chunk, &i, ",");
            }
        }

        eat_token(chunk, &i, ")");
    }

    if ( looking_at(chunk, i, "if") ) {
        eat_token(chunk, &i, "if");
        eat_token(chunk, &i, "(");

        ev.condition = extract_expr(chunk, &i);
        eat_token(chunk, &i, ")");
    }

    eat_token(chunk, &i, "->");
    eat_token(chunk, &i, "event");
    ev.name = extract_id(chunk, &i);

    eat_token(chunk, &i, "(");

    bool first = true;
    size_t j = 0;

    while ( true ) {
        j = looking_at(chunk, i, ")");

        if ( j ) {
            i = j;
            break;
        }

        if ( ! first )
            eat_token(chunk, &i, ",");

        auto expr = extract_expr(chunk, &i);
        ev.exprs.push_back(expr);
        first = false;
    }

    if ( looking_at(chunk, i, "&priority") ) {
        eat_token(chunk, &i, "&priority");
        eat_token(chunk, &i, "=");
        ev.priority = extract_int(chunk, &i);
    }

    eat_token(chunk, &i, ";");
    eat_spaces(chunk, &i);

    if ( i < chunk.size() )
        // This shouldn't actually be possible ...
        throw ParseError("unexpected characters at end of line");

    return ev;
}

bool GlueCompiler::compile() {
    assert(_driver);

    auto init_module = hilti::Module(hilti::ID("spicy_init"));

    auto import_ = hilti::builder::import(hilti::ID("zeek_rt"), ".hlt");
    init_module.add(std::move(import_));

    import_ = hilti::builder::import(hilti::ID("hilti"), ".hlt");
    init_module.add(std::move(import_));

    auto preinit_body = hilti::builder::Builder(_driver->context());

    for ( auto&& [id, m] : _spicy_modules )
        m->spicy_module = hilti::Module(hilti::ID(hilti::util::fmt("spicy_hooks_%s", id)));

    if ( ! PopulateEvents() )
        return false;

    for ( auto& a : _protocol_analyzers ) {
        SPICY_DEBUG(hilti::util::fmt("Adding protocol analyzer '%s'", a.name));

        if ( a.unit_name_orig ) {
            if ( auto ui = _driver->lookupType<::spicy::type::Unit>(a.unit_name_orig) )
                a.unit_orig = *ui;
            else {
                hilti::logger().error(hilti::util::fmt("error with protocol analyzer %s: %s", a.name, ui.error()));
                return false;
            }
        }

        if ( a.unit_name_resp ) {
            if ( auto ui = _driver->lookupType<::spicy::type::Unit>(a.unit_name_resp) )
                a.unit_resp = *ui;
            else {
                hilti::logger().error(hilti::util::fmt("error with protocol analyzer %s: %s", a.name, ui.error()));
                return false;
            }
        }

#if SPICY_VERSION_NUMBER >= 10700
        auto proto = a.protocol.value();
#else
        auto proto = a.protocol;
#endif

        hilti::ID protocol;
        switch ( proto ) {
            case hilti::rt::Protocol::TCP: protocol = hilti::ID("hilti::Protocol::TCP"); break;
            case hilti::rt::Protocol::UDP: protocol = hilti::ID("hilti::Protocol::UDP"); break;
            default: hilti::logger().internalError("unexpected protocol");
        }

        preinit_body.addCall(
            "zeek_rt::register_protocol_analyzer",
            {builder::string(a.name), builder::id(protocol),
             builder::vector(hilti::util::transform(
                 a.ports,
                 [](const auto& p) {
                     return builder::call("zeek_rt::make_port_range", {builder::port(p.begin), builder::port(p.end)});
                 })),
             builder::string(a.unit_name_orig), builder::string(a.unit_name_resp), builder::string(a.replaces),
             _linker_scope()});
    }

    for ( auto& a : _file_analyzers ) {
        SPICY_DEBUG(hilti::util::fmt("Adding file analyzer '%s'", a.name));

        if ( a.unit_name ) {
            if ( auto ui = _driver->lookupType<::spicy::type::Unit>(a.unit_name) )
                a.unit = *ui;
            else {
                hilti::logger().error(hilti::util::fmt("error with file analyzer %s: %s", a.name, ui.error()));
                return false;
            }
        }

        preinit_body.addCall("zeek_rt::register_file_analyzer",
                             {builder::string(a.name),
                              builder::vector(
                                  hilti::util::transform(a.mime_types, [](auto m) { return builder::string(m); })),
                              builder::string(a.unit_name), builder::string(a.replaces), _linker_scope()});
    }

    for ( auto& a : _packet_analyzers ) {
        SPICY_DEBUG(hilti::util::fmt("Adding packet analyzer '%s'", a.name));

        if ( a.unit_name ) {
            if ( auto ui = _driver->lookupType<::spicy::type::Unit>(a.unit_name) )
                a.unit = *ui;
            else {
                hilti::logger().error(hilti::util::fmt("error with packet analyzer %s: %s", a.name, ui.error()));
                return false;
            }
        }

        preinit_body.addCall("zeek_rt::register_packet_analyzer",
                             {builder::string(a.name), builder::string(a.unit_name), builder::string(a.replaces),
                              _linker_scope()});
    }

    // Create the Spicy hooks and accessor functions.
    for ( auto&& ev : _events ) {
        if ( ! CreateSpicyHook(&ev) )
            return false;
    }

    // Register our Zeek events at pre-init time.
    for ( auto&& ev : _events )
        preinit_body.addCall("zeek_rt::install_handler", {builder::string(ev.name)});

    // Create Zeek types for exported Spicy types.
    for ( const auto& [tinfo, id] : _driver->exportedTypes() ) {
        if ( auto type = createZeekType(tinfo.type, id) )
            preinit_body.addCall("zeek_rt::register_type",
                                 {builder::string(id.namespace_()), builder::string(id.local()), *type});
        else
            hilti::logger().error(hilti::util::fmt("cannot export Spicy type '%s': %s", id, type.error()),
                                  tinfo.location);
    }

    for ( auto&& [id, m] : _spicy_modules ) {
        // Import runtime module.
        auto import_ = hilti::builder::import(hilti::ID("zeek_rt"), ".hlt");
        m->spicy_module->add(std::move(import_));

        // Create a vector of unique parent paths from all EVTs files going into this module.
        auto search_dirs = hilti::util::transform(m->evts, [](auto p) { return p.parent_path(); });
        auto search_dirs_vec = std::vector<hilti::rt::filesystem::path>(search_dirs.begin(), search_dirs.end());

        // Import any dependencies.
        for ( const auto& [module, scope] : _imports ) {
            auto import_ = hilti::declaration::ImportedModule(module, std::string(".spicy"), scope, search_dirs_vec);
            m->spicy_module->add(std::move(import_));
        }

        auto unit = hilti::Unit::fromModule(_driver->context(), *m->spicy_module, ".spicy");
        _driver->addInput(unit);
    }

    if ( ! preinit_body.empty() ) {
        auto preinit_function =
            hilti::builder::function("zeek_preinit", hilti::type::void_, {}, preinit_body.block(),
                                     hilti::type::function::Flavor::Standard, hilti::declaration::Linkage::PreInit);
        init_module.add(std::move(preinit_function));
    }

    auto unit = hilti::Unit::fromModule(_driver->context(), init_module, ".hlt");
    _driver->addInput(unit);
    return true;
}

bool GlueCompiler::PopulateEvents() {
    for ( auto& ev : _events ) {
        if ( ev.unit_type )
            // Already done.
            continue;

        TypeInfo uinfo;

        // If we find the path itself, it's referring to a unit type directly;
        // then add a "%done" to form the hook name.
        if ( auto ui = _driver->lookupType<::spicy::type::Unit>(ev.path) ) {
            // TODO: Check that it's a unit type.
            uinfo = *ui;
            ev.unit = ev.path;
            ev.hook = ev.unit + hilti::ID("0x25_done");
        }

        else {
            // Strip the last element of the path, the remainder must refer
            // to a unit now.
            ev.unit = ev.path.namespace_();
            if ( ! ev.unit ) {
                hilti::logger().error(hilti::util::fmt("unit type missing in hook '%s'", ev.path));
                return false;
            }

            if ( auto ui = _driver->lookupType(ev.unit) ) {
                uinfo = *ui;
                ev.hook = ev.path;
            }
            else {
                hilti::logger().error(hilti::util::fmt("unknown unit type '%s'", ev.unit));
                return false;
            }
        }

        ev.unit_type = uinfo.type.as<::spicy::type::Unit>();
        ev.unit_module_id = uinfo.module_id;
        ev.unit_module_path = uinfo.module_path;

        if ( auto i = _spicy_modules.find(uinfo.module_id); i != _spicy_modules.end() ) {
            ev.spicy_module = i->second;
            i->second->evts.insert(ev.file);
        }
        else
            hilti::logger().internalError(
                hilti::util::fmt("module %s not known in Spicy module list", uinfo.module_id));

        // Create accessor expression for event parameters.
        int nr = 0;

        for ( const auto& e : ev.exprs ) {
            glue::ExpressionAccessor acc;
            acc.nr = ++nr;
            acc.expression = e;
            acc.location = ev.location;
            // acc.dollar_id = util::startsWith(e, "$");
            ev.expression_accessors.push_back(acc);
        }
    }

    return true;
}

#include <hilti/ast/operators/struct.h>

#include <spicy/ast/detail/visitor.h>

// Helper visitor to wrap expressions using the the TryMember operator into a
// "deferred" expression.
class WrapTryMemberVisitor : public hilti::visitor::PostOrder<void, WrapTryMemberVisitor> {
public:
    WrapTryMemberVisitor(bool catch_exception) : _catch_exception(catch_exception) {}

    void operator()(const hilti::expression::UnresolvedOperator& n, position_t p) {
        if ( n.kind() == hilti::operator_::Kind::TryMember )
            p.node = hilti::expression::Deferred(hilti::Expression(n), _catch_exception);
    }

private:
    bool _catch_exception;
};

static hilti::Result<hilti::Expression> _parseArgument(const std::string& expression, bool catch_exception,
                                                       const hilti::Meta& meta) {
    auto expr = spicy::parseExpression(expression, meta);
    if ( ! expr )
        return hilti::result::Error(hilti::util::fmt("error parsing event argument expression '%s'", expression));

    // If the expression uses the ".?" operator, we need to defer evaluation
    // so that we can handle potential exceptions at runtime.
    auto v = WrapTryMemberVisitor(catch_exception);
    auto n = hilti::Node(*expr);
    for ( auto i : v.walk(&n) )
        v.dispatch(i);

    return n.as<hilti::Expression>();
}

bool GlueCompiler::CreateSpicyHook(glue::Event* ev) {
    auto mangled_event_name =
        hilti::util::fmt("%s_%p", hilti::util::replace(ev->name.str(), "::", "_"), std::hash<glue::Event>()(*ev));
    auto meta = hilti::Meta(ev->location);

    // Find the Spicy module that this event belongs to.
    SPICY_DEBUG(hilti::util::fmt("Adding Spicy hook '%s' for event %s", ev->hook, ev->name));

    auto import_ = hilti::declaration::ImportedModule(ev->unit_module_id, ev->unit_module_path);
    ev->spicy_module->spicy_module->add(std::move(import_));

    // Define Zeek-side event handler.
    auto handler_id = hilti::ID(hilti::util::fmt("__zeek_handler_%s", mangled_event_name));
    auto handler = builder::global(handler_id, builder::call("zeek_rt::internal_handler", {builder::string(ev->name)}),
                                   hilti::declaration::Linkage::Private, meta);
    ev->spicy_module->spicy_module->add(std::move(handler));

    // Create the hook body that raises the event.
    auto body = hilti::builder::Builder(_driver->context());

#if SPICY_VERSION_NUMBER >= 10800
    body.startProfiler(hilti::util::fmt("zeek/event/%s", ev->name));
#endif

    // If the event comes with a condition, evaluate that first.
    if ( ev->condition.size() ) {
        auto cond = ::spicy::parseExpression(ev->condition, meta);
        if ( ! cond ) {
            hilti::logger().error(hilti::util::fmt("error parsing conditional expression '%s'", ev->condition));
            return false;
        }

        auto exit_ = body.addIf(builder::not_(*cond), meta);
        exit_->addReturn(meta);
    }

    // Log event in debug code. Note: We cannot log the Zeek-side version
    // (i.e., Vals with their types) because we wouldn't be able to determine
    // those for events that don't have a handler (or at least a prototype)
    // defined because we use the existing type definition to determine what
    // Zeek type to convert an Spicy type into. However, we wouldn't want
    // limit logging to events with handlers.
    if ( _driver->hiltiOptions().debug ) {
        std::vector<hilti::Expression> fmt_args = {builder::string(ev->name)};

        for ( const auto&& [i, e] : hilti::util::enumerate(ev->expression_accessors) ) {
            if ( hilti::util::startsWith(e.expression, "$") ) {
                fmt_args.emplace_back(builder::string(e.expression));
                continue;
            }

            if ( auto expr = _parseArgument(e.expression, true, meta) )
                fmt_args.emplace_back(std::move(*expr));
            else
                // We'll catch and report this below.
                fmt_args.emplace_back(builder::string("<error>"));
        }

        std::vector<std::string> fmt_ctrls(fmt_args.size() - 1, "%s");
        auto fmt_str = hilti::util::fmt("-> event %%s(%s)", hilti::util::join(fmt_ctrls, ", "));
        auto msg = builder::modulo(builder::string(fmt_str), builder::tuple(fmt_args));
        auto call = builder::call("zeek_rt::debug", {std::move(msg)});
        body.addExpression(call);
    }

    auto handler_expr = builder::id(handler_id);

    if ( _driver->hiltiOptions().cxx_enable_dynamic_globals ) {
        // Store reference to handler locally to avoid repeated lookups through globals store.
        body.addLocal("handler", builder::id(handler_id), meta);
        handler_expr = builder::id("handler");
    }

    // Nothing to do if there's not handler defined.
    auto have_handler = builder::call("zeek_rt::have_handler", {handler_expr}, meta);
    auto exit_ = body.addIf(builder::not_(have_handler), meta);
    exit_->addReturn(meta);

    // Build event's argument vector.
    body.addLocal(hilti::ID("args"), hilti::type::Vector(builder::typeByID("zeek_rt::Val"), meta), meta);
    body.addMemberCall(builder::id("args"), "reserve",
                       {builder::integer(static_cast<uint64_t>(ev->expression_accessors.size()))}, meta);

    int i = 0;
    for ( const auto& e : ev->expression_accessors ) {
        hilti::Expression val;

        if ( e.expression == "$conn" )
            val = builder::call("zeek_rt::current_conn", {}, meta);
        else if ( e.expression == "$file" )
            val = builder::call("zeek_rt::current_file", {}, meta);
        else if ( e.expression == "$packet" )
            val = builder::call("zeek_rt::current_packet", {}, meta);
        else if ( e.expression == "$is_orig" )
            val = builder::call("zeek_rt::current_is_orig", {}, meta);
        else {
            if ( hilti::util::startsWith(e.expression, "$") ) {
                hilti::logger().error(hilti::util::fmt("unknown reserved parameter '%s'", e.expression));
                return false;
            }

            auto expr = _parseArgument(e.expression, false, meta);
            if ( ! expr ) {
                hilti::logger().error(expr.error());
                return false;
            }

            auto ztype = builder::call("zeek_rt::event_arg_type", {handler_expr, builder::integer(i)}, meta);
            val = builder::call("zeek_rt::to_val", {std::move(*expr), ztype}, meta);
        }

        body.addMemberCall(builder::id("args"), "push_back", {val}, meta);
        i++;
    }

    body.addCall("zeek_rt::raise_event", {handler_expr, builder::move(builder::id("args"))}, meta);

    auto attrs = hilti::AttributeSet({hilti::Attribute("&priority", builder::integer(ev->priority))});
    auto unit_hook = ::spicy::Hook(ev->parameters, body.block(), ::spicy::Engine::All, {}, meta);
    auto hook_decl = ::spicy::declaration::UnitHook(ev->hook, unit_hook, meta);
    ev->spicy_module->spicy_module->add(hilti::Declaration(hook_decl));

    return true;
}

namespace {
// Visitor creating code to instantiate a Zeek type corresponding to a give
// HILTI type.
//
// Note: Any logic changes here must be reflected in the plugin driver's
// corresponding `VisitorZeekType` as well.
struct VisitorZeekType : hilti::visitor::PreOrder<hilti::Result<hilti::Expression>, VisitorZeekType> {
    VisitorZeekType(const GlueCompiler* gc) : gc(gc) {}

    const GlueCompiler* gc;

    std::set<hilti::ID> zeek_types;
    std::vector<std::optional<hilti::ID>> ids = {};

    // Returns current ID, if any.
    auto id() const { return ids.empty() ? std::nullopt : ids.back(); }

    // Returns namespace of top-level ID, if any.
    auto namespace_() const {
        return (! ids.empty() && ids.front().has_value()) ? ids.front()->namespace_() : hilti::ID();
    }

    result_t create_record_type(const hilti::ID& ns, const hilti::ID& local,
                                const std::vector<hilti::Expression>& fields) {
        if ( hilti::logger().isEnabled(ZeekPlugin) ) {
            if ( ! fields.empty() ) {
                SPICY_DEBUG(hilti::util::fmt("Creating Zeek record type %s::%s with fields:", ns, local));

                for ( const auto& f : fields )
                    SPICY_DEBUG(hilti::util::fmt("  %s", f.as<hilti::expression::Ctor>()
                                                             .ctor()
                                                             .as<hilti::ctor::Tuple>()
                                                             .value()[0]
                                                             .as<hilti::expression::Ctor>()
                                                             .ctor()
                                                             .as<hilti::ctor::String>()
                                                             .value()));
            }
            else
                SPICY_DEBUG(hilti::util::fmt("Creating (empty) Zeek record type %s::%s", ns, local));
        }

        return builder::call("zeek_rt::create_record_type",
                             {builder::string(ns), builder::string(local), builder::vector(fields)});
    }

    result_t base_type(const char* tag) { return builder::call("zeek_rt::create_base_type", {builder::id(tag)}); }

    result_t createZeekType(const hilti::Type& t, const std::optional<hilti::ID>& id_ = {}) {
        if ( id_ )
            ids.push_back(id_);
        else if ( auto x = t.typeID() )
            ids.push_back(*x);
        else
            ids.push_back(std::nullopt);

        if ( id() ) {
            // Avoid infinite recursion.
            if ( zeek_types.count(*id()) )
                return hilti::result::Error("type is self-recursive");

            zeek_types.insert(*id());
        }

        auto x = dispatch(t);
        if ( ! x )
            return hilti::result::Error(
                hilti::util::fmt("no support for automatic conversion into a Zeek type (%s)", t.typename_()));

        if ( id() )
            zeek_types.erase(*id());

        ids.pop_back();

        return *x;
    }

    result_t operator()(const hilti::type::Address& t) { return base_type("zeek_rt::ZeekTypeTag::Addr"); }
    result_t operator()(const hilti::type::Bool& t) { return base_type("zeek_rt::ZeekTypeTag::Bool"); }
    result_t operator()(const hilti::type::Bytes& t) { return base_type("zeek_rt::ZeekTypeTag::String"); }
    result_t operator()(const hilti::type::Interval& t) { return base_type("zeek_rt::ZeekTypeTag::Interval"); }
    result_t operator()(const hilti::type::Port& t) { return base_type("zeek_rt::ZeekTypeTag::Port"); }
    result_t operator()(const hilti::type::Real& t) { return base_type("zeek_rt::ZeekTypeTag::Double"); }
    result_t operator()(const hilti::type::SignedInteger& t) { return base_type("zeek_rt::ZeekTypeTag::Int"); }
    result_t operator()(const hilti::type::String& t) { return base_type("zeek_rt::ZeekTypeTag::String"); }
    result_t operator()(const hilti::type::Time& t) { return base_type("zeek_rt::ZeekTypeTag::Time"); }
    result_t operator()(const hilti::type::UnsignedInteger& t) { return base_type("zeek_rt::ZeekTypeTag::Count"); }

    result_t operator()(const hilti::type::Enum& t) {
        assert(id());

        auto labels = hilti::rt::transform(t.labels(), [](const auto& l) {
            return builder::tuple({builder::string(l.get().id()), builder::integer(l.get().value())});
        });

        return builder::call("zeek_rt::create_enum_type", {builder::string(id()->namespace_()),
                                                           builder::string(id()->local()), builder::vector(labels)});
    }

    result_t operator()(const hilti::type::Map& t) {
        auto key = createZeekType(t.keyType());
        if ( ! key )
            return key.error();

        auto value = createZeekType(t.valueType());
        if ( ! value )
            return value.error();

        return builder::call("zeek_rt::create_table_type", {*key, *value});
    }

    result_t operator()(const hilti::type::Optional& t) { return createZeekType(t.dereferencedType()); }

    result_t operator()(const hilti::type::Set& t) {
        auto elem = createZeekType(t.elementType());
        if ( ! elem )
            return elem.error();

        return builder::call("zeek_rt::create_table_type", {*elem, builder::null()});
    }

    result_t operator()(const hilti::type::Struct& t) {
        assert(id());

        std::vector<hilti::Expression> fields;
        for ( const auto& f : t.fields() ) {
            auto ztype = createZeekType(f.type());
            if ( ! ztype )
                return ztype.error();

            fields.emplace_back(builder::tuple({builder::string(f.id()), *ztype, builder::bool_(f.isOptional())}));
        }

        return create_record_type(id()->namespace_(), id()->local(), fields);
    }

    result_t operator()(const hilti::type::Tuple& t) {
        std::vector<hilti::Expression> fields;
        for ( const auto& f : t.elements() ) {
            if ( ! f.id() )
                return hilti::result::Error("can only convert tuple types with all-named fields to Zeek");

            auto ztype = createZeekType(f.type());
            if ( ! ztype )
                return ztype.error();

            fields.emplace_back(builder::tuple({builder::string(*f.id()), *ztype, builder::bool_(false)}));
        }

        hilti::ID local;
        hilti::ID ns;

        if ( auto id_ = id() ) {
            local = id_->local();
            ns = id_->namespace_();
        }
        else {
            // Invent a (hopefully unique) name for the Zeek-side record type
            // so that we can handle anonymous tuple types.
            static uint64_t i = 0;
            local = hilti::util::
                fmt("__spicy_tuple_%u"
                    "_%" PRIu64,
                    static_cast<unsigned int>(getpid()), ++i);
            ns = namespace_();
        }

        return create_record_type(ns, local, fields);
    }

    result_t operator()(const ::spicy::type::Unit& t) {
        assert(id());

        std::vector<hilti::Expression> fields;
        for ( const auto& f : gc->recordFields(t) ) {
            auto ztype = createZeekType(std::get<1>(f));
            if ( ! ztype )
                return ztype.error();

            fields.emplace_back(
                builder::tuple({builder::string(std::get<0>(f)), *ztype, builder::bool_(std::get<2>(f))}));
        }

        return create_record_type(id()->namespace_(), id()->local(), fields);
    }

    result_t operator()(const hilti::type::Vector& t) {
        auto elem = createZeekType(t.elementType());
        if ( ! elem )
            return elem.error();

        return builder::call("zeek_rt::create_vector_type", {*elem});
    }
};
} // namespace

hilti::Result<hilti::Expression> GlueCompiler::createZeekType(const hilti::Type& t, const hilti::ID& id) const {
    auto v = VisitorZeekType(this);
    return v.createZeekType(t, id);
}

namespace {
struct VisitorUnitFields : hilti::visitor::PreOrder<void, VisitorUnitFields> {
    // NOTE: Align this logic with struct generation in Spicy's unit builder.
    std::vector<GlueCompiler::RecordField> fields;

    void operator()(const ::spicy::type::unit::item::Field& f, position_t p) {
        if ( f.isTransient() || f.parseType().isA<hilti::type::Void>() )
            return;

        fields.emplace_back(f.id(), f.itemType(), true);
    }

    void operator()(const ::spicy::type::unit::item::Variable& f, const position_t p) {
        fields.emplace_back(f.id(), f.itemType(), f.isOptional());
    }

    void operator()(const ::spicy::type::unit::item::Switch& f, const position_t p) {
        for ( const auto& c : f.cases() ) {
            for ( const auto& i : c.items() )
                dispatch(i);
        }
    }
};
} // namespace

std::vector<GlueCompiler::RecordField> GlueCompiler::recordFields(const ::spicy::type::Unit& unit) {
    VisitorUnitFields unit_field_converter;

    for ( const auto& i : unit.items() )
        unit_field_converter.dispatch(i);

    return std::move(unit_field_converter.fields);
}

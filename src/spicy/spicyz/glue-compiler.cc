// See the file "COPYING" in the main distribution directory for copyright.

#include "glue-compiler.h"

#include <limits>
#include <stdexcept>

#include <hilti/ast/all.h>
#include <hilti/ast/builder/all.h>
#include <hilti/ast/builder/builder.h>
#include <hilti/ast/visitor.h>
#include <hilti/base/preprocessor.h>
#include <hilti/base/util.h>
#include <hilti/compiler/unit.h>

#include <spicy/ast/visitor.h>

#include "config.h"
#include "zeek/spicy/port-range.h"

using namespace zeek::spicy;
using Builder = spicy::Builder;

namespace zeek::spicy::logging::debug {
inline const hilti::logging::DebugStream GlueCompiler("zeek-glue");
} // namespace zeek::spicy::logging::debug

// Small parsing helpers.

using ParseError = std::runtime_error;

static void eat_spaces(const std::string& chunk, size_t* i) {
    while ( *i < chunk.size() && isspace(chunk[*i]) )
        ++*i;
}

static std::string::size_type looking_at(const std::string& chunk, std::string::size_type i,
                                         const std::string_view& token) {
    eat_spaces(chunk, &i);

    bool token_at_position = i < chunk.size() && token == std::string_view(chunk).substr(i, token.size());
    return token_at_position ? i + token.size() : 0;
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

static std::string extract_string(const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    if ( *i >= chunk.size() || chunk[*i] != '"' )
        throw ParseError("expected string");

    size_t j = *i + 1;

    std::string str = "";
    bool in_escape = false;
    while ( j < chunk.size() - 1 ) {
        if ( chunk[j] == '"' && ! in_escape )
            break;

        if ( chunk[j] == '\\' && ! in_escape ) {
            in_escape = true;
            ++j;
            continue;
        }

        str += chunk[j++];
        in_escape = false;
    }

    if ( j >= chunk.size() || chunk[j] != '"' )
        throw ParseError("string not terminated");

    *i = j + 1;
    return str;
}

static hilti::UnqualifiedType* extract_type(Builder* builder, const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    // We currently only parse Spicy types that can appear in parameters of
    // built-in hooks--which are not many.
    auto token = extract_id(chunk, i);

    if ( token == hilti::ID("string") )
        return builder->typeString();

    if ( token == hilti::ID("uint64") )
        return builder->typeUnsignedInteger(64);

    throw ParseError("mismatching type");
}

static hilti::type::function::Parameter* extract_parameter(Builder* builder, const std::string& chunk, size_t* i) {
    eat_spaces(chunk, i);

    auto id = extract_id(chunk, i);

    if ( ! looking_at(chunk, *i, ":") )
        throw ParseError("expected ':'");

    eat_token(chunk, i, ":");

    auto type = extract_type(builder, chunk, i);
    return builder->parameter(std::move(id), type);
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

void GlueCompiler::init(Driver* driver, int zeek_version) {
    _driver = driver;
    _zeek_version = zeek_version;
}

GlueCompiler::~GlueCompiler() = default;

hilti::Result<std::string> GlueCompiler::getNextEvtBlock(std::istream& in, int* lineno) const {
    std::string chunk;

    // Parser need to track whether we are inside a string or a comment.
    enum State : char { Default, InComment, InString } state = Default;
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

            auto m = hilti::util::split1(std::move(trimmed));

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
                _protocol_analyzers.push_back(std::move(a));
            }

            else if ( looking_at(*chunk, 0, "file") ) {
                auto a = parseFileAnalyzer(*chunk);
                SPICY_DEBUG(hilti::util::fmt("  Got file analyzer definition for %s", a.name));
                _file_analyzers.push_back(std::move(a));
            }

            else if ( looking_at(*chunk, 0, "packet") ) {
                auto a = parsePacketAnalyzer(*chunk);
                SPICY_DEBUG(hilti::util::fmt("  Got packet analyzer definition for %s", a.name));
                _packet_analyzers.push_back(std::move(a));
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
                hilti::ID scope;

                if ( looking_at(*chunk, i, "from") ) {
                    eat_token(*chunk, &i, "from");
                    scope = hilti::ID(extract_path(*chunk, &i).native());
                    SPICY_DEBUG(hilti::util::fmt("  Got module %s to import from scope %s", module, scope));
                }
                else
                    SPICY_DEBUG(hilti::util::fmt("  Got module %s to import", module));

                _imports.emplace_back(hilti::ID(std::move(module)), std::move(scope));
            }

            else if ( looking_at(*chunk, 0, "export") ) {
                auto export_ = parseExport(*chunk);
                if ( _exports.contains(export_.zeek_id) )
                    throw ParseError(hilti::util::fmt("export of '%s' already defined", export_.zeek_id));

                _exports[export_.zeek_id] = export_;
            }

            else if ( looking_at(*chunk, 0, "%doc-id") ) {
                if ( ! _doc_id.empty() )
                    throw ParseError("multiple %doc-id directives");

                size_t i = 0;
                eat_token(*chunk, &i, "%doc-id");
                eat_token(*chunk, &i, "=");
                _doc_id = extract_id(*chunk, &i);
                SPICY_DEBUG(hilti::util::fmt("  Got module's documentation name: %s", _doc_id));
            }

            else if ( looking_at(*chunk, 0, "%doc-description") ) {
                size_t i = 0;
                eat_token(*chunk, &i, "%doc-description");
                eat_token(*chunk, &i, "=");
                _doc_description = extract_string(*chunk, &i);
                SPICY_DEBUG(hilti::util::fmt("  Got module's documentation description: %s",
                                             hilti::util::escapeUTF8(_doc_description)));
            }

            else
                throw ParseError(
                    "expected 'import', 'export', '{file,packet,protocol} analyzer', 'on', or '%doc-{id,description}' "
                    "directive");

            _locations.pop_back();
        }
    } catch ( const ParseError& e ) {
        if ( *e.what() )
            hilti::logger().error(e.what(), _locations.back());

        return false;
    }

    for ( auto&& ev : new_events )
        _events.push_back(std::move(ev));

    return true;
}

std::optional<glue::Export> GlueCompiler::exportForZeekID(const hilti::ID& id) const {
    if ( auto i = _exports.find(id); i != _exports.end() )
        return i->second;
    else
        return {};
}

GlueCompiler::ExportedField GlueCompiler::exportForField(const hilti::ID& zeek_id, const hilti::ID& field_id) const {
    ExportedField field;

    auto export_ = exportForZeekID(zeek_id);
    if ( ! export_ )
        // No `export` for this type, return defaults.
        return field;

    if ( export_->with.empty() ) {
        // Include unless explicitly excluded.
        if ( export_->without.contains(field_id) )
            field.skip = true;
    }
    else {
        // Exclude unless explicitly included.
        if ( ! export_->with.contains(field_id) )
            field.skip = true;
    }

    if ( export_->log_all )
        field.log = true;

    if ( export_->logs.contains(field_id) )
        field.log = true;

    return field;
}


bool glue::Export::validate(const TypeInfo& ti) const {
    auto utype = ti.type->type()->tryAs<::spicy::type::Unit>();
    if ( ! utype )
        return true;

    auto check_field_names = [&](const auto& fields) {
        for ( const auto& f : fields ) {
            if ( ! utype->itemByName(f) ) {
                hilti::logger().error(hilti::rt::fmt("type '%s' does not have field '%s'", ti.id, f), ti.location);
                return false;
            }
        }

        return true;
    };

    if ( ! check_field_names(with) )
        return false;

    if ( ! check_field_names(without) )
        return false;

    if ( ! check_field_names(logs) )
        return false;

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
    a.name = hilti::ID(extract_id(chunk, &i).str());

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

    enum Dir : char { orig, resp, both } dir;

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
                    a.unit_name_resp = std::move(unit);
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
    a.name = extract_id(chunk, &i);

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
    a.name = extract_id(chunk, &i);

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
                auto param = extract_parameter(builder(), chunk, &i);
                ev.parameters.emplace_back(param);

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
        ev.exprs.push_back(std::move(expr));
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

glue::Export GlueCompiler::parseExport(const std::string& chunk) {
    glue::Export export_;

    size_t i = 0;
    eat_token(chunk, &i, "export");

    export_.spicy_id = extract_id(chunk, &i);
    export_.zeek_id = export_.spicy_id;
    export_.location = _locations.back();

    if ( looking_at(chunk, i, "as") ) {
        eat_token(chunk, &i, "as");
        export_.zeek_id = extract_id(chunk, &i);
    }

    if ( looking_at(chunk, i, "&log") ) {
        eat_token(chunk, &i, "&log");
        export_.log_all = true;
    }

    bool expect_fields = false;
    bool include_fields;

    if ( looking_at(chunk, i, "without") ) {
        eat_token(chunk, &i, "without");
        include_fields = false;
        expect_fields = true;
    }
    else if ( looking_at(chunk, i, "with") ) {
        eat_token(chunk, &i, "with");
        include_fields = true;
        expect_fields = true;
    }

    if ( expect_fields ) {
        eat_token(chunk, &i, "{");

        while ( true ) {
            auto field = extract_id(chunk, &i);
            if ( include_fields )
                export_.with.insert(field);
            else
                export_.without.insert(field);

            if ( looking_at(chunk, i, "&log") ) {
                eat_token(chunk, &i, "&log");
                export_.logs.insert(std::move(field));
            }

            if ( looking_at(chunk, i, "}") ) {
                eat_token(chunk, &i, "}");
                break; // All done.
            }

            eat_token(chunk, &i, ",");
        }
    }

    if ( ! looking_at(chunk, i, ";") )
        throw ParseError("syntax error in export");

    return export_;
}

bool GlueCompiler::compile() {
    assert(_driver);

    auto init_module = context()->newModule(builder(), hilti::ID("spicy_init"), ".spicy");

    auto import_ = builder()->import(hilti::ID("zeek_rt"), ".hlt");
    init_module->add(context(), import_);

    import_ = builder()->import(hilti::ID("hilti"), ".hlt");
    init_module->add(context(), import_);

    auto preinit_body = Builder(context());

    for ( auto&& [id, m] : _spicy_modules )
        m->spicy_module = context()->newModule(builder(), hilti::ID(hilti::util::fmt("spicy_hooks_%s", id)), ".spicy");

    if ( ! PopulateEvents() )
        return false;

    if ( ! _doc_id.empty() ) {
        preinit_body.addCall("zeek_rt::register_spicy_module_begin", {
                                                                         builder()->stringMutable(_doc_id),
                                                                         builder()->stringMutable(_doc_description),
                                                                     });
    }

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

        hilti::ID protocol;
        switch ( a.protocol.value() ) {
            case hilti::rt::Protocol::TCP: protocol = hilti::ID("hilti::Protocol::TCP"); break;
            case hilti::rt::Protocol::UDP: protocol = hilti::ID("hilti::Protocol::UDP"); break;
            default: hilti::logger().internalError("unexpected protocol");
        }

        preinit_body.addCall("zeek_rt::register_protocol_analyzer",
                             {builder()->stringMutable(a.name.str()), builder()->id(protocol),
                              builder()->vector(hilti::util::toVector(
                                  a.ports | std::views::transform([this](const auto& p) -> hilti::Expression* {
                                      return builder()->call("zeek_rt::make_port_range",
                                                             {builder()->port(p.begin), builder()->port(p.end)});
                                  }))),
                              builder()->stringMutable(a.unit_name_orig.str()),
                              builder()->stringMutable(a.unit_name_resp.str()), builder()->stringMutable(a.replaces),
                              builder()->scope()});
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
                             {builder()->stringMutable(a.name.str()),
                              builder()->vector(hilti::util::toVector(
                                  a.mime_types | std::views::transform([&](const auto& m) {
                                      return builder()->stringMutable(m)->template as<hilti::Expression>();
                                  }))),
                              builder()->stringMutable(a.unit_name.str()), builder()->stringMutable(a.replaces),
                              builder()->scope()});
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
                             {builder()->stringMutable(a.name.str()), builder()->stringMutable(a.unit_name.str()),
                              builder()->stringMutable(a.replaces), builder()->scope()});
    }

    // Create the Spicy hooks and accessor functions.
    for ( auto&& ev : _events ) {
        if ( ! CreateSpicyHook(&ev) )
            return false;
    }

    // Register our Zeek events at pre-init time.
    for ( auto&& ev : _events )
        preinit_body.addCall("zeek_rt::install_handler", {builder()->stringMutable(ev.name.str())});

    // Create Zeek types for exported Spicy types.
    GlueCompiler::ZeekTypeCache cache;

    for ( const auto& [tinfo, id] : _driver->exportedTypes() ) {
        if ( auto rc = createZeekType(tinfo.type, id, &preinit_body, &cache); ! rc )
            hilti::logger().error(hilti::util::fmt("cannot export Spicy type '%s': %s", id, rc.error()),
                                  tinfo.location);
    }

    for ( auto&& [id, m] : _spicy_modules ) {
        // Import runtime module.
        auto import_ = builder()->import(hilti::ID("zeek_rt"), ".hlt");
        m->spicy_module->add(context(), import_);

        import_ = builder()->import(hilti::ID("hilti"), ".hlt");
        m->spicy_module->add(context(), import_);

        // Create a vector of unique parent paths from all EVTs files going into this module.
        auto search_dirs_vec =
            hilti::util::toVector(m->evts | std::views::transform([](const auto& p) { return p.parent_path(); }));

        // Import any dependencies.
        for ( const auto& [module, scope] : _imports ) {
            auto import_ = builder()->declarationImportedModule(module, std::string(".spicy"), scope);
            import_->as<hilti::declaration::ImportedModule>()->setSearchDirectories(search_dirs_vec);
            m->spicy_module->add(context(), import_);
        }

        if ( auto rc = _driver->addInput(m->spicy_module->uid()); ! rc ) {
            hilti::logger().error(hilti::util::fmt("error adding Spicy unit: %s", rc.error()));
            return false;
        }
    }

    if ( ! _doc_id.empty() )
        preinit_body.addCall("zeek_rt::register_spicy_module_end", {});

    if ( ! preinit_body.empty() ) {
#if SPICY_VERSION_NUMBER >= 11400
        constexpr auto zeek_preinit_flavor = hilti::type::function::Flavor::Function;
#else
        constexpr auto zeek_preinit_flavor = hilti::type::function::Flavor::Standard;
#endif
        auto preinit_function =
            builder()->function(hilti::ID("zeek_preinit"),
                                builder()->qualifiedType(builder()->typeVoid(), hilti::Constness::Const), {},
                                preinit_body.block(), zeek_preinit_flavor, hilti::declaration::Linkage::PreInit);
        init_module->add(context(), preinit_function);
    }

    if ( auto rc = _driver->addInput(init_module->uid()); ! rc ) {
        hilti::logger().error(hilti::util::fmt("error adding init unit: %s", rc.error()));
        return false;
    }

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
                hilti::logger().error(hilti::util::fmt("namespace missing for '%s'", ev.path), ev.location);
                return false;
            }

            if ( auto ui = _driver->lookupType(ev.unit) ) {
                uinfo = *ui;
                ev.hook = ev.path;
            }
            else {
                hilti::logger().error(hilti::util::fmt("no unit type of name '%s'", ev.path), ev.location);
                return false;
            }
        }

        ev.unit_type = uinfo.type->type()->as<::spicy::type::Unit>();
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
            ev.expression_accessors.push_back(std::move(acc));
        }
    }

    return true;
}

#include <hilti/ast/operators/struct.h>

#include <spicy/ast/visitor.h>

static hilti::Result<hilti::Expression*> parseArgument(Builder* builder, const std::string& expression,
                                                       bool catch_exception, const hilti::Meta& meta) {
    auto expr = ::spicy::builder::parseExpression(builder, expression, meta);
    if ( ! expr )
        return hilti::result::Error(hilti::util::fmt("error parsing event argument expression '%s'", expression));

    return expr;
}

bool GlueCompiler::CreateSpicyHook(glue::Event* ev) {
    auto mangled_event_name =
        hilti::util::fmt("%s_%p", hilti::util::replace(ev->name.str(), "::", "_"), std::hash<glue::Event>()(*ev));
    auto meta = hilti::Meta(ev->location);

    // Find the Spicy module that this event belongs to.
    SPICY_DEBUG(hilti::util::fmt("Adding Spicy hook '%s' for event %s", ev->hook, ev->name));

    auto import_ = builder()->declarationImportedModule(ev->unit_module_id, ev->unit_module_path);
    ev->spicy_module->spicy_module->add(context(), import_);

    // Define Zeek-side event handler.
    auto handler_id = hilti::ID(hilti::util::fmt("__zeek_handler_%s", mangled_event_name));
    auto handler =
        builder()->global(handler_id,
                          builder()->call("zeek_rt::internal_handler", {builder()->stringMutable(ev->name.str())}),
                          hilti::declaration::Linkage::Private, meta);
    ev->spicy_module->spicy_module->add(context(), handler);

    // Create the hook body that raises the event.
    auto body = Builder(context());

    body.startProfiler(hilti::util::fmt("zeek/event/%s", ev->name));

    // If the event comes with a condition, evaluate that first.
    if ( ev->condition.size() ) {
        auto cond = ::spicy::builder::parseExpression(&body, ev->condition, meta);
        if ( ! cond ) {
            hilti::logger().error(hilti::util::fmt("error parsing conditional expression '%s'", ev->condition));
            return false;
        }

        auto exit_ = body.addIf(builder()->not_(*cond), meta);
        exit_->addReturn(meta);
    }

    // Log event in debug code. Note: We cannot log the Zeek-side version
    // (i.e., Vals with their types) because we wouldn't be able to determine
    // those for events that don't have a handler (or at least a prototype)
    // defined because we use the existing type definition to determine what
    // Zeek type to convert an Spicy type into. However, we wouldn't want
    // limit logging to events with handlers.
    if ( _driver->hiltiOptions().debug ) {
        hilti::Expressions fmt_args = {builder()->stringLiteral(ev->name.str())};

        for ( const auto&& [i, e] : hilti::util::enumerate(ev->expression_accessors) ) {
            if ( hilti::util::startsWith(e.expression, "$") ) {
                fmt_args.emplace_back(builder()->stringLiteral(e.expression));
                continue;
            }

            if ( auto expr = parseArgument(builder(), e.expression, true, meta) )
                fmt_args.emplace_back(*expr);
            else
                // We'll catch and report this below.
                fmt_args.emplace_back(builder()->stringLiteral("<error>"));
        }

        std::vector<std::string> fmt_ctrls(fmt_args.size() - 1, "%s");
        auto fmt_str = hilti::util::fmt("-> event %%s(%s)", hilti::util::join(fmt_ctrls, ", "));
        auto msg = builder()->modulo(builder()->stringLiteral(fmt_str), builder()->tuple(fmt_args));
        auto call = builder()->call("zeek_rt::debug", {msg});
        body.addExpression(call);
    }

    auto handler_expr = builder()->id(handler_id);

    if ( _driver->hiltiOptions().cxx_enable_dynamic_globals ) {
        // Store reference to handler locally to avoid repeated lookups through globals store.
        body.addLocal("handler", builder()->id(handler_id), meta);
        handler_expr = builder()->id("handler");
    }

    // Nothing to do if there's not handler defined.
    auto have_handler = builder()->call("zeek_rt::have_handler", {handler_expr}, meta);
    auto exit_ = body.addIf(builder()->not_(have_handler), meta);
    exit_->addReturn(meta);

    // Build event's argument vector.
    body.addLocal(hilti::ID("args"),
                  builder()->qualifiedType(builder()->typeVector(builder()->qualifiedType(builder()->typeName(
                                                                                              "zeek_rt::Val"),
                                                                                          hilti::Constness::Const),
                                                                 meta),
                                           hilti::Constness::Const),
                  meta);

    body.addMemberCall(builder()->id("args"), "reserve",
                       {builder()->integer(static_cast<uint64_t>(ev->expression_accessors.size()))}, meta);

    int i = 0;
    for ( const auto& e : ev->expression_accessors ) {
        hilti::Expression* val = nullptr;

        if ( e.expression == "$conn" )
            val = builder()->call("zeek_rt::current_conn", {}, meta);
        else if ( e.expression == "$file" )
            val = builder()->call("zeek_rt::current_file", {}, meta);
        else if ( e.expression == "$packet" )
            val = builder()->call("zeek_rt::current_packet", {}, meta);
        else if ( e.expression == "$is_orig" )
            val = builder()->call("zeek_rt::current_is_orig", {}, meta);
        else {
            if ( hilti::util::startsWith(e.expression, "$") ) {
                hilti::logger().error(hilti::util::fmt("unknown reserved parameter '%s'", e.expression));
                return false;
            }

            auto expr = parseArgument(builder(), e.expression, false, meta);
            if ( ! expr ) {
                hilti::logger().error(expr.error());
                return false;
            }

            auto ztype = builder()->call("zeek_rt::event_arg_type", {handler_expr, builder()->integer(i)}, meta);
            val = builder()->call("zeek_rt::to_val", {*expr, ztype}, meta);
        }

        body.addMemberCall(builder()->id("args"), "push_back", {val}, meta);
        i++;
    }

    body.addCall("zeek_rt::raise_event", {handler_expr, builder()->move(builder()->id("args"))}, meta);

#if SPICY_VERSION_NUMBER >= 11300
    auto attrs = builder()->attributeSet(
        {builder()->attribute(hilti::attribute::kind::Priority, builder()->integer(ev->priority))});
#elif SPICY_VERSION_NUMBER >= 11200
    auto attrs = builder()->attributeSet(
        {builder()->attribute(hilti::Attribute::Kind::Priority, builder()->integer(ev->priority))});
#else
    auto attrs = builder()->attributeSet({builder()->attribute("&priority", builder()->integer(ev->priority))});
#endif
    auto parameters = ev->parameters | std::views::transform([](const auto& p) { return p.get(); });
    auto unit_hook = builder()->declarationHook(hilti::util::toVector(parameters), body.block(), attrs, meta);
    auto hook_decl = builder()->declarationUnitHook(ev->hook, unit_hook, std::move(meta));
    ev->spicy_module->spicy_module->add(context(), hook_decl);

    return true;
}

namespace {
// Visitor creating code to instantiate a Zeek type corresponding to a give
// HILTI type.
//
// Note: Any logic changes here must be reflected in the plugin driver's
// corresponding `VisitorZeekType` as well.
struct VisitorZeekType : spicy::visitor::PreOrder {
    VisitorZeekType(const GlueCompiler* gc, Builder* builder, GlueCompiler::ZeekTypeCache* cache)
        : gc(gc), builder(builder), cache(cache) {}

    const GlueCompiler* gc;
    Builder* builder;
    GlueCompiler::ZeekTypeCache* cache;

    std::vector<hilti::Result<hilti::Expression*>> results;

    std::set<hilti::ID> zeek_types;
    std::vector<hilti::ID> ids = {};

    // Record the resulting Zeek type for the currently processed type (or an error).
    void result(hilti::Result<hilti::Expression*> r) { results.push_back(std::move(r)); }

    // Returns current ID, if any.
    auto id() const { return ids.empty() ? hilti::ID() : ids.back(); }

    // Returns namespace of top-level ID, if any.
    auto namespace_() const { return (! ids.empty() && ids.front()) ? ids.front().namespace_() : hilti::ID(); }

    // Returns prefix for a new tmp that includes the given ID in its name.
    auto tmpName(const std::string& prefix, const hilti::ID& id) const {
        return hilti::util::fmt("%s_%s", prefix, hilti::util::replace(id, "::", "_"));
    }

    hilti::Result<hilti::Expression*> create_record_type(const hilti::ID& ns, const hilti::ID& local,
                                                         const hilti::Expressions& fields) {
        if ( hilti::logger().isEnabled(ZeekPlugin) ) {
            if ( ! fields.empty() ) {
                SPICY_DEBUG(hilti::util::fmt("Creating Zeek record type %s::%s with fields:", ns, local));

                for ( const auto& f : fields )
                    SPICY_DEBUG(hilti::util::fmt("  %s", f));
            }
            else
                SPICY_DEBUG(hilti::util::fmt("Creating (empty) Zeek record type %s::%s", ns, local));
        }

        auto tmp = builder->addTmp(tmpName("fields", {ns, local}),
                                   builder->vector(builder->qualifiedType(builder->typeName("zeek_rt::RecordField"),
                                                                          hilti::Constness::Const)));

        for ( const auto& f : fields )
            builder->addMemberCall(tmp, "push_back", {f});

        return builder->call("zeek_rt::create_record_type",
                             {builder->stringMutable(ns.str()), builder->stringMutable(local.str()), tmp});
    }

    hilti::Expression* create_record_field(const hilti::ID& id, hilti::Expression* type, bool optional,
                                           bool log) const {
        return builder->call("zeek_rt::create_record_field",
                             {builder->stringMutable(id.str()), type, builder->bool_(optional), builder->bool_(log)});
    }

    hilti::Result<hilti::Expression*> base_type(const char* tag) {
        return builder->call("zeek_rt::create_base_type", {builder->id(tag)});
    }

    hilti::Result<hilti::Expression*> createZeekType(hilti::QualifiedType* t, hilti::ID id = {}) {
        if ( ! id )
            id = t->type()->typeID(); // may still be unset

        if ( id ) {
            if ( auto x = cache->find(id); x != cache->end() )
                return x->second;

            // Avoid infinite recursion.
            if ( zeek_types.contains(id) )
                return hilti::result::Error("type is self-recursive");

            zeek_types.insert(id);
        }

        auto old_results = results.size();

        ids.push_back(id);
        dispatch(t->type());
        ids.pop_back();

        if ( results.size() != old_results + 1 )
            return hilti::result::Error(
                hilti::util::fmt("no support for automatic conversion into a Zeek type (%s)", t->type()->typename_()));

        auto x = results.back();
        results.pop_back();

        if ( ! x )
            return x;

        if ( id ) {
            zeek_types.erase(id);

            if ( *x ) {
                auto zt = builder->addTmp(tmpName("type", id), *x);
                cache->emplace(id, zt);
                return zt;
            }
        }

        return *x;
    }

    void operator()(hilti::type::Address* t) final { result(base_type("zeek_rt::ZeekTypeTag::Addr")); }

    void operator()(hilti::type::Bitfield* t) final {
        hilti::Expressions fields;
        for ( auto b : t->bits() ) {
            if ( auto ztype = createZeekType(b->itemType()) )
                fields.emplace_back(create_record_field(b->id(), *ztype, false, false));
            else {
                result(ztype.error());
                return;
            }
        }

        hilti::ID local;
        hilti::ID ns;

        if ( auto id_ = id() ) {
            local = id_.local();
            ns = id_.namespace_();
        }
        else {
            // Invent a (hopefully unique) name for the Zeek-side record type
            // so that we can handle anonymous tuple types.
            static uint64_t i = 0;
            local =
                hilti::ID(hilti::util::fmt("__spicy_bitfield_%u"
                                           "_%" PRIu64,
                                           static_cast<unsigned int>(getpid()), ++i));
            ns = namespace_();
        }

        result(create_record_type(ns, local, fields));
    }

    void operator()(hilti::type::Bool* t) final { result(base_type("zeek_rt::ZeekTypeTag::Bool")); }
    void operator()(hilti::type::Bytes* t) final { result(base_type("zeek_rt::ZeekTypeTag::String")); }
    void operator()(hilti::type::Interval* t) final { result(base_type("zeek_rt::ZeekTypeTag::Interval")); }
    void operator()(hilti::type::Port* t) final { result(base_type("zeek_rt::ZeekTypeTag::Port")); }
    void operator()(hilti::type::Real* t) final { result(base_type("zeek_rt::ZeekTypeTag::Double")); }
    void operator()(hilti::type::SignedInteger* t) final { result(base_type("zeek_rt::ZeekTypeTag::Int")); }
    void operator()(hilti::type::String* t) final { result(base_type("zeek_rt::ZeekTypeTag::String")); }
    void operator()(hilti::type::Time* t) final { result(base_type("zeek_rt::ZeekTypeTag::Time")); }
    void operator()(hilti::type::UnsignedInteger* t) final { result(base_type("zeek_rt::ZeekTypeTag::Count")); }

    void operator()(hilti::type::Enum* t) final {
        assert(id());

        auto tmp = builder->addTmp(tmpName("labels", id()),
                                   builder->typeSet(
                                       builder->qualifiedType(builder->typeTuple(hilti::QualifiedTypes{
                                                                  builder->qualifiedType(builder->typeString(),
                                                                                         hilti::Constness::Const),
                                                                  builder->qualifiedType(builder->typeSignedInteger(64),
                                                                                         hilti::Constness::Const)}),
                                                              hilti::Constness::Const)));

        for ( const auto& l : t->labels() )
            builder->addExpression(builder->add(tmp, builder->tuple({builder->stringMutable(l->id().str()),
                                                                     builder->integer(l->value())})));

        result(builder->call("zeek_rt::create_enum_type", {builder->stringMutable(id().namespace_().str()),
                                                           builder->stringMutable(id().local().str()), tmp}));
    }

    void operator()(hilti::type::Map* t) final {
        auto key = createZeekType(t->keyType());
        if ( ! key ) {
            result(key.error());
            return;
        }

        auto value = createZeekType(t->valueType());
        if ( ! value ) {
            result(value.error());
            return;
        }

        result(builder->call("zeek_rt::create_table_type", {*key, *value}));
    }

    void operator()(hilti::type::Optional* t) final { result(createZeekType(t->dereferencedType())); }

    void operator()(hilti::type::Set* t) final {
        if ( auto elem = createZeekType(t->elementType()) )
            result(builder->call("zeek_rt::create_table_type", {*elem, builder->null()}));
        else
            result(elem.error());
    }

    void operator()(hilti::type::Struct* t) final {
        assert(id());

        hilti::Expressions fields;
        for ( const auto& f : t->fields() ) {
            if ( auto ztype = createZeekType(f->type()) )
                fields.emplace_back(create_record_field(f->id(), *ztype, f->isOptional(), false));
            else {
                result(ztype.error());
                return;
            }
        }

        result(create_record_type(id().namespace_(), id().local(), fields));
    }

    void operator()(hilti::type::Tuple* t) final {
        hilti::Expressions fields;
        for ( const auto& f : t->elements() ) {
            if ( ! f->id() ) {
                result(hilti::result::Error("can only convert tuple types with all-named fields to Zeek"));
                return;
            }

            auto ztype = createZeekType(f->type());
            if ( ! ztype ) {
                result(ztype.error());
                return;
            }

            fields.emplace_back(create_record_field(f->id(), *ztype, false, false));
        }

        hilti::ID local;
        hilti::ID ns;

        if ( auto id_ = id() ) {
            local = id_.local();
            ns = id_.namespace_();
        }
        else {
            // Invent a (hopefully unique) name for the Zeek-side record type
            // so that we can handle anonymous tuple types.
            static uint64_t i = 0;
            local =
                hilti::ID(hilti::util::fmt("__spicy_tuple_%u"
                                           "_%" PRIu64,
                                           static_cast<unsigned int>(getpid()), ++i));
            ns = namespace_();
        }

        result(create_record_type(ns, local, fields));
    }

    void operator()(::spicy::type::Unit* t) final {
        assert(id());

        hilti::Expressions fields;
        for ( const auto& f : gc->recordFields(t) ) {
            auto export_ = gc->exportForField(id(), hilti::ID(f.id));

            if ( export_.skip )
                continue;

            // Special-case: Lift up elements of anonymous bitfields.
            if ( auto bf = f.type->type()->tryAs<hilti::type::Bitfield>(); bf && f.is_anonymous ) {
                for ( const auto& b : bf->bits() ) {
                    auto ztype = createZeekType(b->itemType());
                    if ( ! ztype ) {
                        result(ztype.error());
                        return;
                    }

                    fields.emplace_back(create_record_field(b->id(), *ztype, f.is_optional, export_.log));
                }
            }
            else if ( ! f.is_anonymous ) {
                auto ztype = createZeekType(f.type);
                if ( ! ztype ) {
                    result(ztype.error());
                    return;
                }

                fields.emplace_back(create_record_field(f.id, *ztype, f.is_optional, export_.log));
            }
        }

        result(create_record_type(id().namespace_(), id().local(), fields));
    }

    void operator()(hilti::type::Vector* t) final {
        if ( auto elem = createZeekType(t->elementType()) )
            result(builder->call("zeek_rt::create_vector_type", {*elem}));
        else
            result(elem.error());
    }
};
} // namespace

hilti::Result<hilti::Nothing> GlueCompiler::createZeekType(hilti::QualifiedType* t, const hilti::ID& id,
                                                           Builder* builder, GlueCompiler::ZeekTypeCache* cache) const {
    builder->addComment(hilti::util::fmt("Creating Zeek type %s", id));

    auto v = VisitorZeekType(this, builder, cache);

    if ( auto zt = v.createZeekType(t, id) ) {
        builder->addCall("zeek_rt::register_type", {builder->stringMutable(id.namespace_().str()),
                                                    builder->stringMutable(id.local().str()), *zt});
        return hilti::Nothing();
    }
    else
        return zt.error();
}

namespace {
struct VisitorUnitFields : spicy::visitor::PreOrder {
    // NOTE: Align this logic with struct generation in Spicy's unit builder.
    std::vector<GlueCompiler::RecordField> fields;

    void operator()(::spicy::type::unit::item::Field* n) override {
        if ( (n->isTransient() && ! n->isAnonymous()) || n->parseType()->type()->isA<hilti::type::Void>() )
            return;

        auto field = GlueCompiler::RecordField{.id = n->id(),
                                               .type = n->itemType(),
                                               .is_optional = true,
                                               .is_anonymous = n->isAnonymous()};
        fields.emplace_back(std::move(field));
    }

    void operator()(::spicy::type::unit::item::Variable* b) override {
        auto field = GlueCompiler::RecordField{.id = b->id(),
                                               .type = b->itemType(),
                                               .is_optional = b->isOptional(),
                                               .is_anonymous = false};
        fields.emplace_back(std::move(field));
    }

    void operator()(::spicy::type::unit::item::Switch* n) override {
        for ( const auto& c : n->cases() )
            dispatch(c->block());
    }

    void operator()(::spicy::type::unit::item::Block* n) override {
        for ( const auto& i : n->items() )
            dispatch(i);
    }
};
} // namespace

std::vector<GlueCompiler::RecordField> GlueCompiler::recordFields(const ::spicy::type::Unit* unit) {
    VisitorUnitFields unit_field_converter;

    for ( const auto& i : unit->items() )
        unit_field_converter.dispatch(i);

    return std::move(unit_field_converter.fields);
}

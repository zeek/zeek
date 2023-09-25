// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/spicy/runtime-support.h"

#include <algorithm>
#include <memory>

#include <hilti/rt/exception.h>
#include <hilti/rt/profiler.h>
#include <hilti/rt/types/port.h>
#include <hilti/rt/util.h>

#include "zeek/Event.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/spicy/manager.h"

using namespace zeek;
using namespace zeek::spicy;

void rt::register_protocol_analyzer(const std::string& name, hilti::rt::Protocol proto,
                                    const hilti::rt::Vector<::zeek::spicy::rt::PortRange>& ports,
                                    const std::string& parser_orig, const std::string& parser_resp,
                                    const std::string& replaces, const std::string& linker_scope) {
    auto _ = hilti::rt::profiler::start("zeek/rt/register_protocol_analyzer");
    spicy_mgr->registerProtocolAnalyzer(name, proto, ports, parser_orig, parser_resp, replaces, linker_scope);
}

void rt::register_file_analyzer(const std::string& name, const hilti::rt::Vector<std::string>& mime_types,
                                const std::string& parser, const std::string& replaces,
                                const std::string& linker_scope) {
    auto _ = hilti::rt::profiler::start("zeek/rt/register_file_analyzer");
    spicy_mgr->registerFileAnalyzer(name, mime_types, parser, replaces, linker_scope);
}

void rt::register_packet_analyzer(const std::string& name, const std::string& parser, const std::string& replaces,
                                  const std::string& linker_scope) {
    auto _ = hilti::rt::profiler::start("zeek/rt/register_packet_analyzer");
    spicy_mgr->registerPacketAnalyzer(name, parser, replaces, linker_scope);
}

void rt::register_type(const std::string& ns, const std::string& id, const TypePtr& type) {
    auto _ = hilti::rt::profiler::start("zeek/rt/register_type");
    spicy_mgr->registerType(hilti::rt::fmt("%s::%s", (! ns.empty() ? ns : std::string("GLOBAL")), id), type);
}

// Helper to look up a global Zeek-side type, enforcing that it's of the expected type.
static TypePtr findType(TypeTag tag, const std::string& ns, const std::string& id) {
    auto id_ = hilti::rt::fmt("%s::%s", ns, id);
    auto type = spicy_mgr->findType(id_);

    if ( ! type )
        return nullptr;

    if ( type->Tag() != tag )
        reporter->FatalError("ID %s is not of expected type %s", id_.c_str(), type_name(tag));

    return type;
}

TypePtr rt::create_base_type(ZeekTypeTag tag) {
    auto _ = hilti::rt::profiler::start("zeek/rt/create_base_type");
    TypeTag ztag;

    switch ( tag ) {
        case ZeekTypeTag::Addr: ztag = TYPE_ADDR; break;
        case ZeekTypeTag::Any: ztag = TYPE_ANY; break;
        case ZeekTypeTag::Bool: ztag = TYPE_BOOL; break;
        case ZeekTypeTag::Count: ztag = TYPE_COUNT; break;
        case ZeekTypeTag::Double: ztag = TYPE_DOUBLE; break;
        case ZeekTypeTag::Enum: ztag = TYPE_ENUM; break;
        case ZeekTypeTag::Error: ztag = TYPE_ERROR; break;
        case ZeekTypeTag::File: ztag = TYPE_FILE; break;
        case ZeekTypeTag::Func: ztag = TYPE_FUNC; break;
        case ZeekTypeTag::List: ztag = TYPE_LIST; break;
        case ZeekTypeTag::Int: ztag = TYPE_INT; break;
        case ZeekTypeTag::Interval: ztag = TYPE_INTERVAL; break;
        case ZeekTypeTag::Opaque: ztag = TYPE_OPAQUE; break;
        case ZeekTypeTag::Pattern: ztag = TYPE_PATTERN; break;
        case ZeekTypeTag::Port: ztag = TYPE_PORT; break;
        case ZeekTypeTag::Record: ztag = TYPE_RECORD; break;
        case ZeekTypeTag::String: ztag = TYPE_STRING; break;
        case ZeekTypeTag::Subnet: ztag = TYPE_SUBNET; break;
        case ZeekTypeTag::Table: ztag = TYPE_TABLE; break;
        case ZeekTypeTag::Time: ztag = TYPE_TIME; break;
        case ZeekTypeTag::Type: ztag = TYPE_TYPE; break;
        case ZeekTypeTag::Vector: ztag = TYPE_VECTOR; break;
        case ZeekTypeTag::Void: ztag = TYPE_VOID; break;
        default: hilti::rt::cannot_be_reached();
    }

    return base_type(ztag);
}

TypePtr rt::create_enum_type(
    const std::string& ns, const std::string& id,
    const hilti::rt::Vector<std::tuple<std::string, hilti::rt::integer::safe<int64_t>>>& labels) {
    auto _ = hilti::rt::profiler::start("zeek/rt/create_enum_type");

    if ( auto t = findType(TYPE_ENUM, ns, id) )
        return t;

    auto etype = make_intrusive<EnumType>(ns + "::" + id);

    for ( auto [lid, lval] : labels ) {
        auto name = ::hilti::rt::fmt("%s_%s", id, lid);

        if ( lval == -1 )
            // Zeek's enum can't be negative, so swap in max_int for our Undef.
            lval = std::numeric_limits<::zeek_int_t>::max();

        etype->AddName(ns, name.c_str(), lval, true);
    }

    return etype;
}

TypePtr rt::create_record_type(const std::string& ns, const std::string& id,
                               const hilti::rt::Vector<RecordField>& fields) {
    auto _ = hilti::rt::profiler::start("zeek/rt/create_record_type");

    if ( auto t = findType(TYPE_RECORD, ns, id) )
        return t;

    auto decls = std::make_unique<type_decl_list>();

    for ( const auto& [id, type, optional] : fields ) {
        auto attrs = make_intrusive<detail::Attributes>(nullptr, true, false);

        if ( optional ) {
            auto optional_ = make_intrusive<detail::Attr>(detail::ATTR_OPTIONAL);
            attrs->AddAttr(optional_);
        }

        decls->append(new TypeDecl(util::copy_string(id.c_str()), type, std::move(attrs)));
    }

    return make_intrusive<RecordType>(decls.release());
}

TypePtr rt::create_table_type(TypePtr key, std::optional<TypePtr> value) {
    auto _ = hilti::rt::profiler::start("zeek/rt/create_table_type");
    auto idx = make_intrusive<TypeList>();
    idx->Append(std::move(key));
    return make_intrusive<TableType>(std::move(idx), value ? *value : nullptr);
}

TypePtr rt::create_vector_type(const TypePtr& elem) {
    auto _ = hilti::rt::profiler::start("zeek/rt/create_vector_type");
    return make_intrusive<VectorType>(elem);
}

void rt::install_handler(const std::string& name) {
    auto _ = hilti::rt::profiler::start("zeek/rt/install_handler");
    spicy_mgr->registerEvent(name);
}

EventHandlerPtr rt::internal_handler(const std::string& name) {
    auto _ = hilti::rt::profiler::start("zeek/rt/internal_handler");
    auto handler = event_registry->Lookup(name);

    if ( ! handler )
        reporter->InternalError("Spicy event %s was not installed", name.c_str());

    return handler;
}

void rt::raise_event(const EventHandlerPtr& handler, const hilti::rt::Vector<ValPtr>& args) {
    auto _ = hilti::rt::profiler::start("zeek/rt/raise_event");

    // Caller must have checked already that there's a handler available.
    assert(handler);

    const auto& zeek_args = const_cast<EventHandlerPtr&>(handler)->GetType()->ParamList()->GetTypes();
    if ( args.size() != static_cast<uint64_t>(zeek_args.size()) )
        throw TypeMismatch(hilti::rt::fmt("expected %" PRIu64 " parameters, but got %zu",
                                          static_cast<uint64_t>(zeek_args.size()), args.size()));

    Args vl = Args();
    vl.reserve(args.size());
    for ( const auto& v : args ) {
        if ( v )
            vl.emplace_back(v);
        else
            // Shouldn't happen here, but we have to_vals() that
            // (legitimately) return null in certain contexts.
            throw InvalidValue("null value encountered after conversion");
    }

    event_mgr.Enqueue(handler, std::move(vl));
}

TypePtr rt::event_arg_type(const EventHandlerPtr& handler, const hilti::rt::integer::safe<uint64_t>& idx) {
    auto _ = hilti::rt::profiler::start("zeek/rt/event_arg_type");
    assert(handler);

    const auto& zeek_args = const_cast<EventHandlerPtr&>(handler)->GetType()->ParamList()->GetTypes();
    if ( idx >= static_cast<uint64_t>(zeek_args.size()) )
        throw TypeMismatch(hilti::rt::fmt("more parameters given than the %" PRIu64 " that the Zeek event expects",
                                          static_cast<uint64_t>(zeek_args.size())));

    return zeek_args[idx];
}

ValPtr& rt::current_conn() {
    auto _ = hilti::rt::profiler::start("zeek/rt/current_conn");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( cookie->cache.conn )
        return cookie->cache.conn;

    if ( auto x = cookie->protocol ) {
        cookie->cache.conn = x->analyzer->Conn()->GetVal();
        return cookie->cache.conn;
    }
    else
        throw ValueUnavailable("$conn not available");
}

ValPtr& rt::current_is_orig() {
    auto _ = hilti::rt::profiler::start("zeek/rt/current_is_orig");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( cookie->cache.is_orig )
        return cookie->cache.is_orig;

    if ( auto x = cookie->protocol ) {
        cookie->cache.is_orig = val_mgr->Bool(x->is_orig);
        return cookie->cache.is_orig;
    }
    else
        throw ValueUnavailable("$is_orig not available");
}

void rt::debug(const std::string& msg) {
    auto _ = hilti::rt::profiler::start("zeek/rt/debug");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);
    rt::debug(*cookie, msg);
}

void rt::debug(const Cookie& cookie, const std::string& msg) {
    auto _ = hilti::rt::profiler::start("zeek/rt/debug");
    std::string name;
    std::string id;

    if ( const auto p = cookie.protocol ) {
        auto name = p->analyzer->GetAnalyzerName();
        SPICY_DEBUG(
            hilti::rt::fmt("[%s/%" PRIu32 "/%s] %s", name, p->analyzer->GetID(), (p->is_orig ? "orig" : "resp"), msg));
    }
    else if ( const auto f = cookie.file ) {
        auto name = file_mgr->GetComponentName(f->analyzer->Tag());
        SPICY_DEBUG(hilti::rt::fmt("[%s/%" PRIu32 "] %s", name, f->analyzer->GetID(), msg));
    }
    else if ( const auto f = cookie.packet ) {
        auto name = packet_mgr->GetComponentName(f->analyzer->GetAnalyzerTag());
        SPICY_DEBUG(hilti::rt::fmt("[%s] %s", name, msg));
    }
    else
        throw ValueUnavailable("neither $conn nor $file nor packet analyzer available for debug logging");
}

inline rt::cookie::FileStateStack* _file_state_stack(rt::Cookie* cookie) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file_state_stack");

    if ( auto c = cookie->protocol )
        return c->is_orig ? &c->fstate_orig : &c->fstate_resp;
    else if ( auto f = cookie->file )
        return &f->fstate;
    else
        throw rt::ValueUnavailable("no current connection or file available");
}

inline const rt::cookie::FileState* _file_state(rt::Cookie* cookie, std::optional<std::string> fid) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file_state");

    auto* stack = _file_state_stack(cookie);
    if ( fid ) {
        if ( auto* fstate = stack->find(*fid) )
            return fstate;
        else
            throw rt::ValueUnavailable(hilti::rt::fmt("no file analysis currently in flight for file ID %s", fid));
    }
    else {
        if ( stack->isEmpty() )
            throw rt::ValueUnavailable("no file analysis currently in flight");

        return stack->current();
    }
}

ValPtr rt::current_file() {
    auto _ = hilti::rt::profiler::start("zeek/rt/current_file");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = cookie->file )
        return x->analyzer->GetFile()->ToVal();
    else if ( auto* fstate = _file_state(cookie, {}) ) {
        if ( auto* f = file_mgr->LookupFile(fstate->fid) )
            return f->ToVal();
    }

    throw ValueUnavailable("$file not available");
}

ValPtr rt::current_packet() {
    auto _ = hilti::rt::profiler::start("zeek/rt/current_packet");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = cookie->packet ) {
        if ( ! c->packet_val )
            // We cache the built value in case we need it multiple times.
            c->packet_val = c->packet->ToRawPktHdrVal();

        return c->packet_val;
    }
    else
        throw ValueUnavailable("$packet not available");
}

hilti::rt::Bool rt::is_orig() {
    auto _ = hilti::rt::profiler::start("zeek/rt/is_orig");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = cookie->protocol )
        return x->is_orig;
    else
        throw ValueUnavailable("is_orig() not available in current context");
}

std::string rt::uid() {
    auto _ = hilti::rt::profiler::start("zeek/rt/uid");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = cookie->protocol ) {
        // Retrieve the ConnVal() so that we ensure the UID has been set.
        c->analyzer->ConnVal();
        return c->analyzer->Conn()->GetUID().Base62("C");
    }
    else
        throw ValueUnavailable("uid() not available in current context");
}

std::tuple<hilti::rt::Address, hilti::rt::Port, hilti::rt::Address, hilti::rt::Port> rt::conn_id() {
    auto _ = hilti::rt::profiler::start("zeek/rt/conn_id");

    static auto convert_address = [](const IPAddr& zaddr) -> hilti::rt::Address {
        const uint32_t* bytes = nullptr;
        if ( auto n = zaddr.GetBytes(&bytes); n == 1 )
            // IPv4
            return hilti::rt::Address(*reinterpret_cast<const struct in_addr*>(bytes));
        else if ( n == 4 )
            // IPv6
            return hilti::rt::Address(*reinterpret_cast<const struct in6_addr*>(bytes));
        else
            throw ValueUnavailable("unexpected IP address side from Zeek"); // shouldn't really be able to happen
    };

    static auto convert_port = [](uint32_t port, TransportProto proto) -> hilti::rt::Port {
        auto p = ntohs(static_cast<uint16_t>(port));

        switch ( proto ) {
            case TransportProto::TRANSPORT_ICMP: return {p, hilti::rt::Protocol::ICMP};
            case TransportProto::TRANSPORT_TCP: return {p, hilti::rt::Protocol::TCP};
            case TransportProto::TRANSPORT_UDP: return {p, hilti::rt::Protocol::UDP};
            case TransportProto::TRANSPORT_UNKNOWN: return {p, hilti::rt::Protocol::Undef};
        }

        hilti::rt::cannot_be_reached();
    };

    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = cookie->protocol ) {
        const auto* conn = c->analyzer->Conn();
        return std::make_tuple(convert_address(conn->OrigAddr()), convert_port(conn->OrigPort(), conn->ConnTransport()),
                               convert_address(conn->RespAddr()),
                               convert_port(conn->RespPort(), conn->ConnTransport()));
    }
    else
        throw ValueUnavailable("conn_id() not available in current context");
}

void rt::flip_roles() {
    auto _ = hilti::rt::profiler::start("zeek/rt/flip_roles");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    rt::debug(*cookie, "flipping roles");

    if ( auto x = cookie->protocol )
        x->analyzer->Conn()->FlipRoles();
    else
        throw ValueUnavailable("flip_roles() not available in current context");
}

hilti::rt::integer::safe<uint64_t> rt::number_packets() {
    auto _ = hilti::rt::profiler::start("zeek/rt/number_packets");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto x = cookie->protocol ) {
        return x->num_packets;
    }
    else
        throw ValueUnavailable("number_packets() not available in current context");
}

void rt::confirm_protocol() {
    auto _ = hilti::rt::profiler::start("zeek/rt/confirm_protocol");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( cookie->cache.confirmed )
        return;

    if ( auto x = cookie->protocol ) {
        auto tag = spicy_mgr->tagForProtocolAnalyzer(x->analyzer->GetAnalyzerTag());
        SPICY_DEBUG(hilti::rt::fmt("confirming protocol %s", tag.AsString()));
        cookie->cache.confirmed = true;
        return x->analyzer->AnalyzerConfirmation(tag);
    }
    throw ValueUnavailable("no current connection available");
}

void rt::reject_protocol(const std::string& reason) {
    auto _ = hilti::rt::profiler::start("zeek/rt/reject_protocol");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());

    // We might be invoked during teardown when the cookie has already been
    // cleared. These other code paths also take care of sending an analyzer
    // violation to Zeek, so we can immediately return for such cases here.
    if ( ! cookie )
        return;

    if ( auto x = cookie->protocol ) {
        auto tag = spicy_mgr->tagForProtocolAnalyzer(x->analyzer->GetAnalyzerTag());
        SPICY_DEBUG(hilti::rt::fmt("rejecting protocol %s", tag.AsString()));
        return x->analyzer->AnalyzerViolation("protocol rejected", nullptr, 0, tag);
    }
    else
        throw ValueUnavailable("no current connection available");
}

void rt::weird(const std::string& id, const std::string& addl) {
    auto _ = hilti::rt::profiler::start("zeek/rt/weird");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( const auto x = cookie->protocol )
        x->analyzer->Weird(id.c_str(), addl.data());
    else if ( const auto x = cookie->file )
        zeek::reporter->Weird(x->analyzer->GetFile(), id.c_str(), addl.data());
    else if ( const auto x = cookie->packet ) {
        x->analyzer->Weird(id.c_str(), x->packet, addl.c_str());
    }
    else
        throw ValueUnavailable("none of $conn, $file, or $packet available for weird reporting");
}

void rt::protocol_begin(const std::optional<std::string>& analyzer) {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_begin");

    if ( analyzer ) {
        protocol_handle_get_or_create(*analyzer);
        return;
    }

    // Instantiate a DPD analyzer.
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = cookie->protocol;
    if ( ! c )
        throw ValueUnavailable("no current connection available");

    // Use a Zeek PIA stream analyzer performing DPD.
    auto pia_tcp = std::make_unique<analyzer::pia::PIA_TCP>(c->analyzer->Conn());

    // Forward empty payload to trigger lifecycle management in this analyzer tree.
    c->analyzer->ForwardStream(0, reinterpret_cast<const u_char*>(c->analyzer), true);
    c->analyzer->ForwardStream(0, reinterpret_cast<const u_char*>(c->analyzer), false);

    // Direct child of this type already exists. We ignore this silently
    // because that makes usage nicer if either side of the connection
    // might end up creating the analyzer; this way the user doesn't
    // need to track what the other side already did.
    //
    // We inspect the children directly to work around zeek/zeek#2899.
    const auto& children = c->analyzer->GetChildren();
    if ( auto it = std::find_if(children.begin(), children.end(),
                                [&](const auto& it) {
                                    return ! it->Removing() && ! it->IsFinished() &&
                                           it->GetAnalyzerTag() == pia_tcp->GetAnalyzerTag();
                                });
         it != children.end() )
        return;

    auto child = pia_tcp.release();
    c->analyzer->AddChildAnalyzer(child);

    child->FirstPacket(true, nullptr);
    child->FirstPacket(false, nullptr);
}

rt::ProtocolHandle rt::protocol_handle_get_or_create(const std::string& analyzer) {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_handle_get_or_create");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = cookie->protocol;
    if ( ! c )
        throw ValueUnavailable("no current connection available");

    // Forward empty payload to trigger lifecycle management in this analyzer tree.
    c->analyzer->ForwardStream(0, reinterpret_cast<const u_char*>(c->analyzer), true);
    c->analyzer->ForwardStream(0, reinterpret_cast<const u_char*>(c->analyzer), false);

    // If the child already exists, do not add it again so this function is idempotent.
    //
    // We inspect the children directly to work around zeek/zeek#2899.
    const auto& children = c->analyzer->GetChildren();
    if ( auto it = std::find_if(children.begin(), children.end(),
                                [&](const auto& it) {
                                    return ! it->Removing() && ! it->IsFinished() && it->GetAnalyzerName() == analyzer;
                                });
         it != children.end() )
        return rt::ProtocolHandle((*it)->GetID());

    auto child = analyzer_mgr->InstantiateAnalyzer(analyzer.c_str(), c->analyzer->Conn());
    if ( ! child )
        throw ZeekError(::hilti::rt::fmt("unknown analyzer '%s' requested", analyzer));

    // If we had no such child before but cannot add it the analyzer was prevented.
    //
    // NOTE: We make this a hard error since returning e.g., an empty optional
    // here would make it easy to incorrectly use the return value with e.g.,
    // `protocol_data_in` or `protocol_gap`.
    if ( ! c->analyzer->AddChildAnalyzer(child) )
        throw ZeekError(::hilti::rt::fmt("creation of child analyzer %s was prevented", analyzer));

    if ( c->analyzer->Conn()->ConnTransport() != TRANSPORT_TCP ) {
        // Some TCP application analyzer may expect to have access to a TCP
        // analyzer. To make that work, we'll create a fake TCP analyzer,
        // just so that they have something to access. It won't
        // semantically have any "TCP" to analyze obviously.
        c->fake_tcp = std::make_shared<packet_analysis::TCP::TCPSessionAdapter>(c->analyzer->Conn());
        static_cast<analyzer::Analyzer*>(c->fake_tcp.get())
            ->Done(); // will never see packets; cast to get around protected inheritance
    }

    auto* child_as_tcp = dynamic_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(child);
    if ( ! child_as_tcp )
        throw ZeekError(
            ::hilti::rt::fmt("could not add analyzer '%s' to connection; not a TCP-based analyzer", analyzer));

    if ( c->fake_tcp )
        child_as_tcp->SetTCP(c->fake_tcp.get());

    return rt::ProtocolHandle(child->GetID());
}

void rt::protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data,
                          const std::optional<rt::ProtocolHandle>& h) {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_data_in");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = cookie->protocol;
    if ( ! c )
        throw ValueUnavailable("no current connection available");

    auto len = data.size();
    auto* data_ = reinterpret_cast<const u_char*>(data.data());

    if ( h ) {
        if ( auto* output_handler = c->analyzer->GetOutputHandler() )
            output_handler->DeliverStream(len, data_, is_orig);

        auto* child = c->analyzer->FindChild(h->id());
        if ( ! child )
            throw ValueUnavailable(hilti::rt::fmt("unknown child analyzer %s", *h));

        if ( child->IsFinished() || child->Removing() )
            throw ValueUnavailable(hilti::rt::fmt("child analyzer %s no longer exist", *h));

        child->NextStream(len, data_, is_orig);
    }

    else
        c->analyzer->ForwardStream(len, data_, is_orig);
}

void rt::protocol_gap(const hilti::rt::Bool& is_orig, const hilti::rt::integer::safe<uint64_t>& offset,
                      const hilti::rt::integer::safe<uint64_t>& len, const std::optional<rt::ProtocolHandle>& h) {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_gap");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = cookie->protocol;
    if ( ! c )
        throw ValueUnavailable("no current connection available");

    if ( h ) {
        if ( auto* output_handler = c->analyzer->GetOutputHandler() )
            output_handler->Undelivered(offset, len, is_orig);

        auto* child = c->analyzer->FindChild(h->id());
        if ( ! child )
            throw ValueUnavailable(hilti::rt::fmt("unknown child analyzer %s", *h));

        if ( child->IsFinished() || child->Removing() )
            throw ValueUnavailable(hilti::rt::fmt("child analyzer %s no longer exist", *h));

        child->NextUndelivered(offset, len, is_orig);
    }

    else
        c->analyzer->ForwardUndelivered(offset, len, is_orig);
}

void rt::protocol_end() {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_end");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = cookie->protocol;
    if ( ! c )
        throw ValueUnavailable("no current connection available");

    for ( const auto& i : c->analyzer->GetChildren() )
        c->analyzer->RemoveChildAnalyzer(i);
}

void rt::protocol_handle_close(const ProtocolHandle& handle) {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_handle_close");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    auto c = cookie->protocol;
    if ( ! c )
        throw ValueUnavailable("no current connection available");

    auto child = c->analyzer->FindChild(handle.id());
    if ( ! child )
        throw ValueUnavailable(hilti::rt::fmt("unknown child analyzer %s", handle));

    if ( child->IsFinished() || child->Removing() )
        throw ValueUnavailable(hilti::rt::fmt("child analyzer %s no longer exist", handle));

    child->NextEndOfData(true);
    child->NextEndOfData(false);

    c->analyzer->RemoveChildAnalyzer(handle.id());
}

rt::cookie::FileState* rt::cookie::FileStateStack::push() {
    auto _ = hilti::rt::profiler::start("zeek/rt/file-stack-push");
    auto fid = file_mgr->HashHandle(hilti::rt::fmt("%s.%d", _analyzer_id, ++_id_counter));
    _stack.emplace_back(fid);
    return &_stack.back();
}

const rt::cookie::FileState* rt::cookie::FileStateStack::find(const std::string& fid) const {
    auto _ = hilti::rt::profiler::start("zeek/rt/file-stack-find");

    // Reverse search as the default state would be on top of the stack.
    for ( auto i = _stack.rbegin(); i != _stack.rend(); i++ ) {
        if ( i->fid == fid )
            return &*i;
    }

    return nullptr;
}

void rt::cookie::FileStateStack::remove(const std::string& fid) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file-stack-remove");

    // Reverse search as the default state would be on top of the stack.
    for ( auto i = _stack.rbegin(); i != _stack.rend(); i++ ) {
        if ( i->fid == fid ) {
            _stack.erase((i + 1).base()); // https://stackoverflow.com/a/1830240
            return;
        }
    }
}

static void _data_in(const char* data, uint64_t len, std::optional<uint64_t> offset,
                     const std::optional<std::string>& fid) {
    auto cookie = static_cast<rt::Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state(cookie, fid);
    auto data_ = reinterpret_cast<const unsigned char*>(data);
    auto mime_type = (fstate->mime_type ? *fstate->mime_type : std::string());

    if ( auto c = cookie->protocol ) {
        auto tag = spicy_mgr->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag());

        if ( offset )
            file_mgr->DataIn(data_, len, *offset, tag, c->analyzer->Conn(), c->is_orig, fstate->fid, mime_type);
        else
            file_mgr->DataIn(data_, len, tag, c->analyzer->Conn(), c->is_orig, fstate->fid, mime_type);
    }
    else {
        if ( offset )
            file_mgr->DataIn(data_, len, *offset, Tag(), nullptr, false, fstate->fid, mime_type);
        else
            file_mgr->DataIn(data_, len, Tag(), nullptr, false, fstate->fid, mime_type);
    }
}

void rt::terminate_session() {
    auto _ = hilti::rt::profiler::start("zeek/rt/terminate_session");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = cookie->protocol ) {
        assert(session_mgr);
        session_mgr->Remove(c->analyzer->Conn());
    }
    else
        throw spicy::rt::ValueUnavailable("terminate_session() not available in the current context");
}

std::string rt::fuid() {
    auto _ = hilti::rt::profiler::start("zeek/rt/fuid");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto f = cookie->file ) {
        if ( auto file = f->analyzer->GetFile() )
            return file->GetID();
    }

    throw ValueUnavailable("fuid() not available in current context");
}

std::string rt::file_begin(const std::optional<std::string>& mime_type) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file_begin");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state_stack(cookie)->push();
    fstate->mime_type = mime_type;

    // Feed an empty chunk into the analysis to force creating the file state inside Zeek.
    _data_in("", 0, {}, {});

    auto file = file_mgr->LookupFile(fstate->fid);
    assert(file); // passing in empty data ensures that this is now available

    if ( auto f = cookie->file ) {
        // We need to initialize some fa_info fields ourselves that would
        // normally be inferred from the connection.

        // Set the source to the current file analyzer.
        file->SetSource(file_mgr->GetComponentName(f->analyzer->Tag()));

        // There are some fields inside the new fa_info record that we want to
        // set, but don't have a Zeek API for. Hence, we need to play some
        // tricks: we can get to the fa_info value, but read-only; const_cast
        // comes to our rescue. And then we just write directly into the
        // record fields.
        auto rval = file->ToVal()->AsRecordVal();
        auto current = f->analyzer->GetFile()->ToVal()->AsRecordVal();
        rval->Assign(id::fa_file->FieldOffset("parent_id"),
                     current->GetField("id")); // set to parent
        rval->Assign(id::fa_file->FieldOffset("conns"),
                     current->GetField("conns")); // copy from parent
        rval->Assign(id::fa_file->FieldOffset("is_orig"),
                     current->GetField("is_orig")); // copy from parent
    }

    // Double check everybody agrees on the file ID.
    assert(fstate->fid == file->GetID());
    return fstate->fid;
}

void rt::file_set_size(const hilti::rt::integer::safe<uint64_t>& size, const std::optional<std::string>& fid) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file_set_size");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state(cookie, fid);

    if ( auto c = cookie->protocol ) {
        auto tag = spicy_mgr->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag());
        file_mgr->SetSize(size, tag, c->analyzer->Conn(), c->is_orig, fstate->fid);
    }
    else
        file_mgr->SetSize(size, Tag(), nullptr, false, fstate->fid);
}

void rt::file_data_in(const hilti::rt::Bytes& data, const std::optional<std::string>& fid) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file_data_in");
    _data_in(data.data(), data.size(), {}, fid);
}

void rt::file_data_in_at_offset(const hilti::rt::Bytes& data, const hilti::rt::integer::safe<uint64_t>& offset,
                                const std::optional<std::string>& fid) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file_data_in_at_offset");
    _data_in(data.data(), data.size(), offset, fid);
}

void rt::file_gap(const hilti::rt::integer::safe<uint64_t>& offset, const hilti::rt::integer::safe<uint64_t>& len,
                  const std::optional<std::string>& fid) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file_gap");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state(cookie, fid);

    if ( auto c = cookie->protocol ) {
        auto tag = spicy_mgr->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag());
        file_mgr->Gap(offset, len, tag, c->analyzer->Conn(), c->is_orig, fstate->fid);
    }
    else
        file_mgr->Gap(offset, len, Tag(), nullptr, false, fstate->fid);
}

void rt::file_end(const std::optional<std::string>& fid) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file_end");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state(cookie, fid);

    file_mgr->EndOfFile(fstate->fid);
    _file_state_stack(cookie)->remove(fstate->fid);
}

void rt::forward_packet(const hilti::rt::integer::safe<uint32_t>& identifier) {
    auto _ = hilti::rt::profiler::start("zeek/rt/forward_packet");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    assert(cookie);

    if ( auto c = cookie->packet )
        c->next_analyzer = identifier;
    else
        throw ValueUnavailable("no current packet analyzer available");
}

hilti::rt::Time rt::network_time() {
    auto _ = hilti::rt::profiler::start("zeek/rt/network_time");
    return hilti::rt::Time(run_state::network_time, hilti::rt::Time::SecondTag());
}

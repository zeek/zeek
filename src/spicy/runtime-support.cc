// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/spicy/runtime-support.h"

#include <memory>
#include <ranges>

#include <hilti/rt/exception.h>
#include <hilti/rt/profiler.h>
#include <hilti/rt/types/port.h>
#include <hilti/rt/util.h>

#include "zeek/Event.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/file_analysis/File.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/net_util.h"
#include "zeek/packet_analysis/Manager.h"
#include "zeek/spicy/manager.h"

using namespace zeek;
using namespace zeek::spicy;

void rt::register_spicy_module_begin(const std::string& name, const std::string& description) {
    spicy_mgr->registerSpicyModuleBegin(name, description);
}

void rt::register_spicy_module_end() { spicy_mgr->registerSpicyModuleEnd(); }

void rt::register_protocol_analyzer(const std::string& name, hilti::rt::Protocol proto,
                                    const hilti::rt::Vector<::zeek::spicy::rt::PortRange>& ports,
                                    const std::string& parser_orig, const std::string& parser_resp,
                                    const std::string& replaces,
                                    const hilti::rt::integer::safe<uint64_t>& linker_scope) {
    auto _ = hilti::rt::profiler::start("zeek/rt/register_protocol_analyzer");
    spicy_mgr->registerProtocolAnalyzer(name, proto, ports, parser_orig, parser_resp, replaces, linker_scope);
}

void rt::register_file_analyzer(const std::string& name, const hilti::rt::Vector<std::string>& mime_types,
                                const std::string& parser, const std::string& replaces,
                                const hilti::rt::integer::safe<uint64_t>& linker_scope) {
    auto _ = hilti::rt::profiler::start("zeek/rt/register_file_analyzer");
    spicy_mgr->registerFileAnalyzer(name, mime_types, parser, replaces, linker_scope);
}

void rt::register_packet_analyzer(const std::string& name, const std::string& parser, const std::string& replaces,
                                  const hilti::rt::integer::safe<uint64_t>& linker_scope) {
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

static TypeTag zeekTypeForTag(rt::ZeekTypeTag tag) {
    using namespace ::zeek::spicy::rt;

    switch ( tag ) {
        case ZeekTypeTag::Addr: return TYPE_ADDR;
        case ZeekTypeTag::Any: return TYPE_ANY;
        case ZeekTypeTag::Bool: return TYPE_BOOL;
        case ZeekTypeTag::Count: return TYPE_COUNT;
        case ZeekTypeTag::Double: return TYPE_DOUBLE;
        case ZeekTypeTag::Enum: return TYPE_ENUM;
        case ZeekTypeTag::Error: return TYPE_ERROR;
        case ZeekTypeTag::File: return TYPE_FILE;
        case ZeekTypeTag::Func: return TYPE_FUNC;
        case ZeekTypeTag::List: return TYPE_LIST;
        case ZeekTypeTag::Int: return TYPE_INT;
        case ZeekTypeTag::Interval: return TYPE_INTERVAL;
        case ZeekTypeTag::Opaque: return TYPE_OPAQUE;
        case ZeekTypeTag::Pattern: return TYPE_PATTERN;
        case ZeekTypeTag::Port: return TYPE_PORT;
        case ZeekTypeTag::Record: return TYPE_RECORD;
        case ZeekTypeTag::String: return TYPE_STRING;
        case ZeekTypeTag::Subnet: return TYPE_SUBNET;
        case ZeekTypeTag::Table: return TYPE_TABLE;
        case ZeekTypeTag::Time: return TYPE_TIME;
        case ZeekTypeTag::Type: return TYPE_TYPE;
        case ZeekTypeTag::Vector: return TYPE_VECTOR;
        case ZeekTypeTag::Void: return TYPE_VOID;
        default: hilti::rt::cannot_be_reached();
    }
}

TypePtr rt::create_base_type(ZeekTypeTag tag) {
    auto _ = hilti::rt::profiler::start("zeek/rt/create_base_type");
    return base_type(zeekTypeForTag(tag));
}

std::string hilti::rt::detail::adl::to_string(const zeek::spicy::rt::ZeekTypeTag& v, detail::adl::tag /* unused */) {
    return type_name(zeekTypeForTag(v));
}

std::string hilti::rt::detail::adl::to_string(const zeek::spicy::rt::AnalyzerType& v, detail::adl::tag /* unused */) {
    switch ( v.value() ) {
        case zeek::spicy::rt::AnalyzerType::File: return "AnalyzerType::File";
        case zeek::spicy::rt::AnalyzerType::Packet: return "AnalyzerType::Packet";
        case zeek::spicy::rt::AnalyzerType::Protocol: return "AnalyzerType::Protocol";
        case zeek::spicy::rt::AnalyzerType::Undef: return "AnalyzerType::Undef";
    }

    hilti::rt::cannot_be_reached();
}

TypePtr rt::create_enum_type(
    const std::string& ns, const std::string& id,
    const hilti::rt::Set<std::tuple<std::optional<std::string>, std::optional<hilti::rt::integer::safe<int64_t>>>>&
        labels) {
    auto _ = hilti::rt::profiler::start("zeek/rt/create_enum_type");

    if ( auto t = findType(TYPE_ENUM, ns, id) )
        return t;

    auto etype = make_intrusive<EnumType>(ns + "::" + id);

    for ( auto [lid, lval] : labels ) {
        assert(lid && lval);
        auto name = ::hilti::rt::fmt("%s_%s", id, *lid);

        if ( *lval == -1 )
            // Zeek's enum can't be negative, so swap in max_int for our Undef.
            lval = std::numeric_limits<::zeek_int_t>::max();

        etype->AddName(ns, name.c_str(), *lval, true);
    }

    return std::move(etype);
}

TypePtr rt::create_record_type(const std::string& ns, const std::string& id,
                               const hilti::rt::Vector<RecordField>& fields) {
    auto _ = hilti::rt::profiler::start("zeek/rt/create_record_type");

    if ( auto t = findType(TYPE_RECORD, ns, id) )
        return t;

    auto decls = std::make_unique<type_decl_list>();

    for ( const auto& f : fields ) {
        auto attrs = make_intrusive<::zeek::detail::Attributes>(nullptr, true, false);

        if ( f.is_optional ) {
            auto optional_ = make_intrusive<::zeek::detail::Attr>(::zeek::detail::ATTR_OPTIONAL);
            attrs->AddAttr(std::move(optional_));
        }

        if ( f.is_log ) {
            auto log_ = make_intrusive<::zeek::detail::Attr>(::zeek::detail::ATTR_LOG);
            attrs->AddAttr(std::move(log_));
        }

        decls->append(new TypeDecl(util::copy_string(f.id.c_str(), f.id.size()), f.type, std::move(attrs)));
    }

    return make_intrusive<RecordType>(decls.release());
}

rt::RecordField rt::create_record_field(const std::string& id, const TypePtr& type, hilti::rt::Bool is_optional,
                                        hilti::rt::Bool is_log) {
    return rt::RecordField{id, type, is_optional, is_log};
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
    for ( auto it = args.unsafeBegin(); it != args.unsafeEnd(); it++ ) {
        const auto& v = *it;
        if ( v )
            vl.emplace_back(v);
        else
            // Shouldn't happen here, but we have to_vals() that
            // (legitimately) return null in certain contexts.
            throw InvalidValue("null value encountered after conversion");
    }

    event_mgr.Enqueue(handler, std::move(vl), util::detail::SOURCE_LOCAL, rt::current_analyzer_id());
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

zeek::analyzer::ID rt::current_analyzer_id() {
    auto _ = hilti::rt::profiler::start("zeek/rt/current_analyzer_id");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto x = cookie->protocol ) {
            return x->analyzer->GetID();
        }
        else if ( auto x = cookie->file ) { // NOLINT(bugprone-branch-clone)
            return 0;
        }
        else if ( auto x = cookie->packet ) {
            return 0;
        }
    }

    throw ValueUnavailable("analyzer not available");
}

ValPtr& rt::current_conn() {
    auto _ = hilti::rt::profiler::start("zeek/rt/current_conn");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( cookie->cache.conn )
            return cookie->cache.conn;

        if ( auto x = cookie->protocol ) {
            cookie->cache.conn = x->analyzer->Conn()->GetVal();
            return cookie->cache.conn;
        }
    }

    throw ValueUnavailable("$conn not available");
}

ValPtr& rt::current_is_orig() {
    auto _ = hilti::rt::profiler::start("zeek/rt/current_is_orig");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( cookie->cache.is_orig )
            return cookie->cache.is_orig;

        if ( auto x = cookie->protocol ) {
            cookie->cache.is_orig = val_mgr->Bool(x->is_orig);
            return cookie->cache.is_orig;
        }
    }

    throw ValueUnavailable("$is_orig not available");
}

void rt::debug(const std::string& msg) {
    auto _ = hilti::rt::profiler::start("zeek/rt/debug");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    if ( ! cookie )
        return SPICY_DEBUG(msg);

    rt::debug(*cookie, msg);
}

void rt::debug(const Cookie& cookie, const std::string& msg) {
    auto _ = hilti::rt::profiler::start("zeek/rt/debug");

    if ( const auto p = cookie.protocol ) {
        auto name = p->analyzer->GetAnalyzerName();
        SPICY_DEBUG(
            hilti::rt::fmt("[%s/%" PRIu32 "/%s] %s", name, p->analyzer->GetID(), (p->is_orig ? "orig" : "resp"), msg));
    }
    else if ( const auto f = cookie.file ) {
        const auto& name = file_mgr->GetComponentName(f->analyzer->Tag());
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

    if ( cookie ) {
        if ( auto c = cookie->protocol )
            return c->is_orig ? &c->fstate_orig : &c->fstate_resp;
        else if ( auto f = cookie->file )
            return &f->fstate;
    }

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

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto x = cookie->file )
            return x->analyzer->GetFile()->ToVal();
        else if ( auto* fstate = _file_state(cookie, {}) ) {
            if ( auto* f = file_mgr->LookupFile(fstate->fid) )
                return f->ToVal();
        }
    }

    throw ValueUnavailable("$file not available");
}

ValPtr rt::current_packet() {
    auto _ = hilti::rt::profiler::start("zeek/rt/current_packet");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto c = cookie->packet ) {
            if ( ! c->packet_val )
                // We cache the built value in case we need it multiple times.
                c->packet_val = c->packet->ToRawPktHdrVal();

            return c->packet_val;
        }
    }

    throw ValueUnavailable("$packet not available");
}

hilti::rt::Bool rt::is_orig() {
    auto _ = hilti::rt::profiler::start("zeek/rt/is_orig");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto x = cookie->protocol )
            return x->is_orig;
    }

    throw ValueUnavailable("is_orig() not available in current context");
}

std::string rt::uid() {
    auto _ = hilti::rt::profiler::start("zeek/rt/uid");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto c = cookie->protocol ) {
            // Retrieve the ConnVal() so that we ensure the UID has been set.
            c->analyzer->ConnVal();
            return c->analyzer->Conn()->GetUID().Base62("C");
        }
    }

    throw ValueUnavailable("uid() not available in current context");
}

hilti::rt::Tuple<hilti::rt::Address, hilti::rt::Port, hilti::rt::Address, hilti::rt::Port> rt::conn_id() {
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

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto c = cookie->protocol ) {
            const auto* conn = c->analyzer->Conn();
            return hilti::rt::tuple::make(convert_address(conn->OrigAddr()),
                                          convert_port(conn->OrigPort(), conn->ConnTransport()),
                                          convert_address(conn->RespAddr()),
                                          convert_port(conn->RespPort(), conn->ConnTransport()));
        }
    }

    throw ValueUnavailable("conn_id() not available in current context");
}

void rt::flip_roles() {
    auto _ = hilti::rt::profiler::start("zeek/rt/flip_roles");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        rt::debug(*cookie, "flipping roles");

        if ( auto x = cookie->protocol )
            return x->analyzer->Conn()->FlipRoles();
    }

    throw ValueUnavailable("flip_roles() not available in current context");
}

hilti::rt::integer::safe<uint64_t> rt::number_packets() {
    auto _ = hilti::rt::profiler::start("zeek/rt/number_packets");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto x = cookie->protocol ) {
            return x->num_packets;
        }
    }

    throw ValueUnavailable("number_packets() not available in current context");
}

void rt::confirm_protocol() {
    auto _ = hilti::rt::profiler::start("zeek/rt/confirm_protocol");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( cookie->cache.confirmed )
            return;

        if ( auto x = cookie->protocol ) {
            auto tag = spicy_mgr->tagForProtocolAnalyzer(x->analyzer->GetAnalyzerTag());
            SPICY_DEBUG(hilti::rt::fmt("confirming protocol %s", tag.AsString()));
            cookie->cache.confirmed = true;
            return x->analyzer->AnalyzerConfirmation(tag);
        }
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
        SPICY_DEBUG(hilti::rt::fmt("rejecting protocol %s: %s", tag.AsString(), reason));
        return x->analyzer->AnalyzerViolation(reason.c_str(), nullptr, 0, tag);
    }
    else
        throw ValueUnavailable("no current connection available");
}

void rt::weird(const std::string& id, const std::string& addl) {
    auto _ = hilti::rt::profiler::start("zeek/rt/weird");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( const auto x = cookie->protocol )
            return x->analyzer->Weird(id.c_str(), addl.data());
        else if ( const auto x = cookie->file )
            return zeek::reporter->Weird(x->analyzer->GetFile(), id.c_str(), addl.data());
        else if ( const auto x = cookie->packet )
            return x->analyzer->Weird(id.c_str(), x->packet, addl.c_str());
    }

    throw ValueUnavailable("none of $conn, $file, or $packet available for weird reporting");
}

rt::AnalyzerType rt::analyzer_type(const std::string& analyzer, const hilti::rt::Bool& if_enabled) {
    if ( auto* c = file_mgr->Lookup(analyzer.c_str()) ) {
        if ( (! if_enabled) || c->Enabled() )
            return AnalyzerType::File;
    }

    if ( auto* c = packet_mgr->Lookup(analyzer.c_str()) ) {
        if ( (! if_enabled) || c->Enabled() )
            return AnalyzerType::Packet;
    }

    if ( auto* c = analyzer_mgr->Lookup(analyzer.c_str()) ) {
        if ( (! if_enabled) || c->Enabled() )
            return AnalyzerType::Protocol;
    }

    return AnalyzerType::Undef;
}

void rt::protocol_begin(const std::optional<std::string>& analyzer, const ::hilti::rt::Protocol& proto) {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_begin");

    if ( analyzer ) {
        protocol_handle_get_or_create(*analyzer, proto);
        return;
    }

    // Instantiate a DPD analyzer. If a direct child of this type already
    // exists, we abort silently because that makes usage nicer if either side
    // of the connection might end up creating the analyzer; this way the user
    // doesn't need to track what the other side already did.

    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());

    if ( ! cookie || ! cookie->protocol )
        throw ValueUnavailable("no current connection available");

    auto c = cookie->protocol;

    switch ( proto.value() ) {
        case ::hilti::rt::Protocol::TCP: {
            // Use a Zeek PIA stream (TCP) analyzer performing DPD.
            auto pia_tcp = std::make_unique<analyzer::pia::PIA_TCP>(c->analyzer->Conn());
            pia_tcp->FirstPacket(true, TransportProto::TRANSPORT_TCP);
            pia_tcp->FirstPacket(false, TransportProto::TRANSPORT_TCP);

            c->analyzer->CleanupChildren();

            // If the child already exists, do not add it again so this function is idempotent.
            if ( auto child = c->analyzer->GetChildAnalyzer(pia_tcp->GetAnalyzerName()) )
                return;

            auto child = pia_tcp.release();
            c->analyzer->AddChildAnalyzer(child);
            break;
        }

        case ::hilti::rt::Protocol::UDP: {
            // Use a Zeek PIA packet (UDP) analyzer performing DPD.
            auto pia_udp = std::make_unique<analyzer::pia::PIA_UDP>(c->analyzer->Conn());
            pia_udp->FirstPacket(true, TransportProto::TRANSPORT_UDP);
            pia_udp->FirstPacket(false, TransportProto::TRANSPORT_UDP);

            c->analyzer->CleanupChildren();
            auto child = pia_udp.release();
            c->analyzer->AddChildAnalyzer(child);
            break;
        }

        case ::hilti::rt::Protocol::ICMP: throw Unsupported("protocol_begin: ICMP not supported for DPD");

        case ::hilti::rt::Protocol::Undef: throw InvalidValue("protocol_begin: no protocol specified for DPD");

        default: throw InvalidValue("protocol_begin: unknown protocol for DPD");
    }
}

void rt::protocol_begin(const ::hilti::rt::Protocol& proto) { return protocol_begin(std::nullopt, proto); }

rt::ProtocolHandle rt::protocol_handle_get_or_create(const std::string& analyzer, const ::hilti::rt::Protocol& proto) {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_handle_get_or_create");

    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    if ( ! cookie || ! cookie->protocol )
        throw ValueUnavailable("no current connection available");

    auto c = cookie->protocol;

    switch ( proto.value() ) {
        case ::hilti::rt::Protocol::TCP: {
            c->analyzer->CleanupChildren();

            // If the child already exists, do not add it again so this function is idempotent.
            if ( auto child = c->analyzer->GetChildAnalyzer(analyzer) )
                return rt::ProtocolHandle(child->GetID(), proto);

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

            return rt::ProtocolHandle(child->GetID(), proto);
        }

        case ::hilti::rt::Protocol::UDP: {
            c->analyzer->CleanupChildren();

            // If the child already exists, do not add it again so this function is idempotent.
            if ( auto child = c->analyzer->GetChildAnalyzer(analyzer) )
                return rt::ProtocolHandle(child->GetID(), proto);

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

            return rt::ProtocolHandle(child->GetID(), proto);
        }

        case ::hilti::rt::Protocol::ICMP: throw Unsupported("protocol_handle_get_or_create: ICMP not supported");

        case ::hilti::rt::Protocol::Undef: throw InvalidValue("protocol_handle_get_or_create: no protocol specified");

        default: throw InvalidValue("protocol_handle_get_or_create: unknown protocol");
    }
}

namespace zeek::spicy::rt {
static void protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data,
                             const std::optional<::hilti::rt::Protocol>& proto,
                             const std::optional<rt::ProtocolHandle>& h) {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_data_in");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());

    if ( ! cookie || ! cookie->protocol )
        throw ValueUnavailable("no current connection available");

    auto c = cookie->protocol;

    // We need to copy the data here to be on the safe side: the streaming
    // input methods expect the data to stay around until they return. At first
    // sight, it might seem that that's guaranteed here, but because we'll
    // usually be called from Spicy code, the data might be on the current
    // fiber's stack, which could end up being swapped out if any of the
    // streaming input methods end up going into Spicy land as well.
    const auto len = data.size();
    auto copy = std::make_unique<u_char[]>(len);
    memcpy(copy.get(), data.data(), len);
    auto* data_ = reinterpret_cast<const u_char*>(copy.get());

    ::hilti::rt::Protocol protocol_to_use = ::hilti::rt::Protocol::Undef;

    if ( proto ) {
        if ( h && h->protocol() != *proto )
            throw InvalidValue("protocol_data_in: protocol mismatches with analyzer handle");

        protocol_to_use = *proto;
    }
    else if ( h )
        protocol_to_use = h->protocol();

    if ( protocol_to_use == ::hilti::rt::Protocol::Undef )
        throw InvalidValue("protocol_data_in: cannot determine protocol to use");

    switch ( protocol_to_use.value() ) {
        case ::hilti::rt::Protocol::TCP: {
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

            break;
        }

        case ::hilti::rt::Protocol::UDP: {
            if ( h ) {
                if ( auto* output_handler = c->analyzer->GetOutputHandler() )
                    output_handler->DeliverPacket(len, data_, is_orig, 0, nullptr, 0);

                auto* child = c->analyzer->FindChild(h->id());
                if ( ! child )
                    throw ValueUnavailable(hilti::rt::fmt("unknown child analyzer %s", *h));

                if ( child->IsFinished() || child->Removing() )
                    throw ValueUnavailable(hilti::rt::fmt("child analyzer %s no longer exist", *h));

                child->NextPacket(len, data_, is_orig);
            }

            else
                c->analyzer->ForwardPacket(len, data_, is_orig, 0, nullptr, 0);

            break;
        }

        case ::hilti::rt::Protocol::ICMP: throw Unsupported("protocol_data_in: ICMP not supported");

        case ::hilti::rt::Protocol::Undef: hilti::rt::cannot_be_reached();

        default: throw InvalidValue("protocol_data_in: unknown protocol");
    }
}
} // namespace zeek::spicy::rt

void rt::protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data,
                          const ::hilti::rt::Protocol& proto) {
    protocol_data_in(is_orig, data, proto, {});
}

void rt::protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data, const rt::ProtocolHandle& h) {
    protocol_data_in(is_orig, data, {}, h);
}

void rt::protocol_gap(const hilti::rt::Bool& is_orig, const hilti::rt::integer::safe<uint64_t>& offset,
                      const hilti::rt::integer::safe<uint64_t>& len, const std::optional<rt::ProtocolHandle>& h) {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_gap");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());

    if ( ! cookie || ! cookie->protocol )
        throw ValueUnavailable("no current connection available");

    auto c = cookie->protocol;

    switch ( h->protocol().value() ) {
        case ::hilti::rt::Protocol::TCP: {
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

            break;
        }

        case ::hilti::rt::Protocol::UDP: {
            throw Unsupported("protocol_gap: UDP not supported");
        }

        case ::hilti::rt::Protocol::ICMP: throw Unsupported("protocol_gap: ICMP not supported");

        case ::hilti::rt::Protocol::Undef: throw InvalidValue("protocol_gap: no protocol specified");

        default: throw InvalidValue("protocol_gap: unknown protocol");
    }
}

void rt::protocol_end() {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_end");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        auto c = cookie->protocol;
        if ( ! c )
            throw ValueUnavailable("no current connection available");

        for ( const auto& i : c->analyzer->GetChildren() )
            c->analyzer->RemoveChildAnalyzer(i);
    }
}

void rt::protocol_handle_close(const ProtocolHandle& handle) {
    auto _ = hilti::rt::profiler::start("zeek/rt/protocol_handle_close");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());

    if ( ! cookie || ! cookie->protocol )
        throw ValueUnavailable("no current connection available");

    auto c = cookie->protocol;

    switch ( handle.protocol().value() ) {
        case ::hilti::rt::Protocol::TCP: {
            auto child = c->analyzer->FindChild(handle.id());
            if ( ! child )
                throw ValueUnavailable(hilti::rt::fmt("unknown child analyzer %s", handle));

            if ( child->IsFinished() || child->Removing() )
                throw ValueUnavailable(hilti::rt::fmt("child analyzer %s no longer exist", handle));

            auto* tcp_child = dynamic_cast<analyzer::tcp::TCP_ApplicationAnalyzer*>(child);
            if ( ! tcp_child )
                throw ValueUnavailable(hilti::rt::fmt("child analyzer %s is not a TCP application analyzer", handle));

            tcp_child->EndpointEOF(true); // For Spicy analyzers, this will trigger Finish() ...
            child->NextEndOfData(true);   // ... whereas this won't.

            tcp_child->EndpointEOF(false);
            child->NextEndOfData(false);

            c->analyzer->RemoveChildAnalyzer(handle.id());
            break;
        }

        case ::hilti::rt::Protocol::UDP: {
            auto child = c->analyzer->FindChild(handle.id());
            if ( ! child )
                throw ValueUnavailable(hilti::rt::fmt("unknown child analyzer %s", handle));

            if ( child->IsFinished() || child->Removing() )
                throw ValueUnavailable(hilti::rt::fmt("child analyzer %s no longer exist", handle));

            c->analyzer->RemoveChildAnalyzer(handle.id());
            break;
        }

        case ::hilti::rt::Protocol::ICMP: throw Unsupported("protocol_handle_close: ICMP not supported");

        case ::hilti::rt::Protocol::Undef: throw InvalidValue("protocol_handle_close: no protocol specified");

        default: throw InvalidValue("protocol_handle_close: unknown protocol");
    }
}

rt::cookie::FileState* rt::cookie::FileStateStack::push(std::optional<std::string> fid_provided) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file-stack-push");
    if ( fid_provided && find(*fid_provided) )
        throw InvalidValue(hilti::rt::fmt("Duplicate file id %s provided", *fid_provided));

    std::string fid;
    if ( fid_provided )
        fid = *fid_provided;
    else {
        auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
        if ( ! cookie )
            throw ValueUnavailable("no current connection available");

        if ( auto c = cookie->protocol ) {
            auto tag = spicy_mgr->tagForProtocolAnalyzer(c->analyzer->GetAnalyzerTag());
            fid = file_mgr->GetFileID(tag, c->analyzer->Conn(), c->is_orig);
        }

        if ( fid.empty() )
            // If we can't get a FID from the file manager (e.g., because don't
            // have a current protocol), we make one up.
            fid = file_mgr->HashHandle(hilti::rt::fmt("%s.%d", _analyzer_id, ++_id_counter));
    }

    assert(! fid.empty());
    _stack.emplace_back(std::move(fid));
    return &_stack.back();
}

const rt::cookie::FileState* rt::cookie::FileStateStack::find(const std::string& fid) const {
    auto _ = hilti::rt::profiler::start("zeek/rt/file-stack-find");

    // Reverse search as the default state would be on top of the stack.
    for ( const auto& i : std::ranges::reverse_view(_stack) ) {
        if ( i.fid == fid )
            return &i;
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
    auto mime_type = (fstate->mime_type ? *fstate->mime_type : std::string());

    // We need to copy the data here to be on the safe side for the same reason
    // as in `protocol_data_in`; see there for more.
    std::unique_ptr<u_char[]> copy(new u_char[len]);
    memcpy(copy.get(), data, len);
    auto* data_ = reinterpret_cast<const u_char*>(copy.get());

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

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto c = cookie->protocol ) {
            assert(session_mgr);
            return session_mgr->Remove(c->analyzer->Conn());
        }
    }

    throw spicy::rt::ValueUnavailable("terminate_session() not available in the current context");
}

void rt::skip_input() {
    auto _ = hilti::rt::profiler::start("zeek/rt/skip_input");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto p = cookie->protocol )
            return p->analyzer->SetSkip(true);
        else if ( auto f = cookie->file )
            return f->analyzer->SetSkip(true);
    }

    throw spicy::rt::ValueUnavailable("skip() not available in the current context");
}

std::string rt::fuid() {
    auto _ = hilti::rt::profiler::start("zeek/rt/fuid");

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto f = cookie->file ) {
            if ( auto file = f->analyzer->GetFile() )
                return file->GetID();
        }
    }

    throw ValueUnavailable("fuid() not available in current context");
}

std::string rt::file_begin(const std::optional<std::string>& mime_type, const std::optional<std::string>& fuid) {
    auto _ = hilti::rt::profiler::start("zeek/rt/file_begin");
    auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie());
    auto* fstate = _file_state_stack(cookie)->push(fuid);
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
    if ( ! cookie )
        throw spicy::rt::ValueUnavailable("file_gap() not available in the current context");

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

    if ( auto cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( auto c = cookie->packet ) {
            c->next_analyzer = identifier;
            return;
        }
    }

    throw ValueUnavailable("no current packet analyzer available");
}

hilti::rt::Time rt::network_time() {
    auto _ = hilti::rt::profiler::start("zeek/rt/network_time");
    return hilti::rt::Time(run_state::network_time, hilti::rt::Time::SecondTag());
}

static ValPtr convertSignedInteger(int64_t i, std::string_view have_type, const TypePtr& target) {
    if ( target->Tag() == TYPE_INT )
        return val_mgr->Int(i);

    if ( target->Tag() == TYPE_COUNT ) {
        if ( i >= 0 )
            return val_mgr->Count(i);
        else
            throw rt::ParameterMismatch(hilti::rt::fmt("negative %s", have_type), target);
    }

    throw rt::ParameterMismatch(have_type, target);
}

static ValPtr convertUnsignedInteger(uint64_t i, std::string_view have_type, const TypePtr& target) {
    if ( target->Tag() == TYPE_COUNT )
        return val_mgr->Count(i);

    if ( target->Tag() == TYPE_INT ) {
        if ( i < static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) )
            return val_mgr->Int(static_cast<int64_t>(i));
        else
            throw rt::ParameterMismatch(hilti::rt::fmt("%s too large", have_type), target);
    }

    throw rt::ParameterMismatch(have_type, target);
}

inline void setRecordField(RecordVal* rval, const IntrusivePtr<RecordType>& rtype, int idx,
                           const hilti::rt::type_info::Value& v) {
    using namespace hilti::rt;

    const auto& type = v.type();

    switch ( type.tag ) {
        case TypeInfo::Bool: rval->Assign(idx, type.bool_->get(v)); return;
        case TypeInfo::Bytes: rval->Assign(idx, type.bytes->get(v).str()); return;
        case TypeInfo::Interval: rval->AssignInterval(idx, type.interval->get(v).seconds()); return;
        case TypeInfo::Optional:
            if ( const auto& x = type.optional->value(v) )
                setRecordField(rval, rtype, idx, x);
            return;

        case TypeInfo::Null: return;
        case TypeInfo::Real: rval->Assign(idx, type.real->get(v)); return;
        case TypeInfo::SignedInteger_int8: rval->Assign(idx, type.signed_integer_int8->get(v)); return;
        case TypeInfo::SignedInteger_int16: rval->Assign(idx, type.signed_integer_int16->get(v)); return;
        case TypeInfo::SignedInteger_int32: rval->Assign(idx, type.signed_integer_int32->get(v)); return;
        case TypeInfo::SignedInteger_int64: rval->Assign(idx, type.signed_integer_int64->get(v)); return;
        case TypeInfo::String: rval->Assign(idx, type.string->get(v)); return;
        case TypeInfo::Time: rval->AssignTime(idx, type.time->get(v).seconds()); return;
        case TypeInfo::UnsignedInteger_uint8: rval->Assign(idx, type.unsigned_integer_uint8->get(v)); return;
        case TypeInfo::UnsignedInteger_uint16: rval->Assign(idx, type.unsigned_integer_uint16->get(v)); return;
        case TypeInfo::UnsignedInteger_uint32: rval->Assign(idx, type.unsigned_integer_uint32->get(v)); return;
        case TypeInfo::UnsignedInteger_uint64: rval->Assign(idx, type.unsigned_integer_uint64->get(v)); return;
        case TypeInfo::StrongReference:
            if ( const auto& x = type.strong_reference->value(v) )
                setRecordField(rval, rtype, idx, x);
            return;

        case TypeInfo::ValueReference:
            if ( const auto& x = type.value_reference->value(v) )
                setRecordField(rval, rtype, idx, x);
            return;

        case TypeInfo::WeakReference:
            if ( const auto& x = type.weak_reference->value(v) )
                setRecordField(rval, rtype, idx, x);
            return;

        case TypeInfo::Address:
        case TypeInfo::Bitfield:
        case TypeInfo::Enum:
        case TypeInfo::Map:
        case TypeInfo::Port:
        case TypeInfo::Set:
        case TypeInfo::Struct:
        case TypeInfo::Tuple:
        case TypeInfo::Vector: {
            // This may return a nullptr in cases where the field is to be left unset.
            ValPtr zval = rt::detail::to_val(v, rtype->GetFieldType(idx));

            if ( v )
                rval->Assign(idx, zval);
            else {
                // Field must be &optional or &default.
                if ( auto attrs = rtype->FieldDecl(idx)->attrs;
                     ! attrs ||
                     ! (attrs->Find(zeek::detail::ATTR_DEFAULT) || attrs->Find(zeek::detail::ATTR_OPTIONAL)) )
                    throw rt::ParameterMismatch(
                        hilti::rt::fmt("missing initialization for field '%s'", rtype->FieldName(idx)));
            }

            return;
        }

        default: throw zeek::spicy::rt::InvalidValue("unsupported type for record field");
    }

    hilti::rt::cannot_be_reached();
}

ValPtr rt::detail::to_val(const hilti::rt::type_info::Value& value, const TypePtr& target) {
    using namespace hilti::rt;

    const auto& type = value.type();

    switch ( type.tag ) {
        case TypeInfo::Address: {
            if ( target->Tag() != TYPE_ADDR )
                throw ParameterMismatch(type, target);

            auto in_addr = type.address->get(value).asInAddr();
            if ( auto v4 = std::get_if<struct in_addr>(&in_addr) )
                return make_intrusive<AddrVal>(IPAddr(*v4));
            else {
                auto v6 = std::get<struct in6_addr>(in_addr);
                return make_intrusive<AddrVal>(IPAddr(v6));
            }
        }

        case TypeInfo::Bitfield: {
            if ( target->Tag() != TYPE_RECORD )
                throw ParameterMismatch(type, target);

            auto rtype = cast_intrusive<RecordType>(target);

            if ( type.bitfield->bits().size() != static_cast<size_t>(rtype->NumFields()) )
                throw ParameterMismatch(type, target);

            auto rval = make_intrusive<RecordVal>(rtype);

            int idx = 0;
            for ( const auto& [bits, bvalue] : type.bitfield->iterate(value) )
                setRecordField(rval.get(), rtype, idx++, bvalue);

            return std::move(rval);
        }

        case TypeInfo::Bool: {
            if ( target->Tag() != TYPE_BOOL )
                throw ParameterMismatch(type, target);

            return val_mgr->Bool(type.bool_->get(value));
        }

        case TypeInfo::Bytes: {
            if ( target->Tag() != TYPE_STRING )
                throw ParameterMismatch(type, target);

            const auto& b = type.bytes->get(value);
            return make_intrusive<StringVal>(b.str());
        }

        case TypeInfo::Enum: {
            if ( target->Tag() != TYPE_ENUM )
                throw ParameterMismatch(type, target);

            auto i = type.enum_->get(value);

            if ( target->GetName() == "transport_proto" ) {
                // Special case: map Spicy's `Protocol` to Zeek's `transport_proto`.
                if ( auto ty = std::string_view(type.display); ty != "hilti::Protocol" && ty != "spicy::Protocol" )
                    throw ParameterMismatch(type.display, target);

                switch ( i.value ) {
                    case hilti::rt::Protocol::TCP:
                        return id::transport_proto->GetEnumVal(::TransportProto::TRANSPORT_TCP);

                    case hilti::rt::Protocol::UDP:
                        return id::transport_proto->GetEnumVal(::TransportProto::TRANSPORT_UDP);

                    case hilti::rt::Protocol::ICMP:
                        return id::transport_proto->GetEnumVal(::TransportProto::TRANSPORT_ICMP);

                    case hilti::rt::Protocol::Undef: [[fallthrough]]; // just for readability, make Undef explicit
                    default: return id::transport_proto->GetEnumVal(::TransportProto::TRANSPORT_UNKNOWN);
                }

                hilti::rt::cannot_be_reached();
            }

            // Zeek's enum can't be negative, so we swap in max_int for our Undef (-1).
            if ( i.value == std::numeric_limits<int64_t>::max() )
                // Can't allow this ...
                throw InvalidValue("enum values with value max_int not supported by Zeek integration");

            zeek_int_t zi = (i.value >= 0 ? i.value : std::numeric_limits<::zeek_int_t>::max());
            return target->AsEnumType()->GetEnumVal(zi);
        }

        case TypeInfo::Interval: {
            if ( target->Tag() != TYPE_INTERVAL )
                throw ParameterMismatch(type, target);

            return make_intrusive<IntervalVal>(type.interval->get(value).seconds());
        }

        case TypeInfo::Map: {
            if ( target->Tag() != TYPE_TABLE )
                throw ParameterMismatch(type, target);

            if ( type.map->keyType()->tag == TypeInfo::Tuple )
                throw ParameterMismatch("internal error: maps with tuples not yet supported in to_val()");

            auto tt = cast_intrusive<TableType>(target);
            if ( tt->IsSet() )
                throw ParameterMismatch(type, target);

            if ( tt->GetIndexTypes().size() != 1 )
                throw ParameterMismatch(type, target);

            auto zv = make_intrusive<TableVal>(tt);

            for ( const auto& i : type.map->iterate(value) ) {
                auto k = to_val(i.first, tt->GetIndexTypes()[0]);
                auto v = to_val(i.second, tt->Yield());
                zv->Assign(std::move(k), std::move(v));
            }

            return std::move(zv);
        }

        case TypeInfo::Optional: {
            const auto& x = type.optional->value(value);
            return x ? detail::to_val(x, target) : nullptr;
        }

        case TypeInfo::Port: {
            if ( target->Tag() != TYPE_PORT )
                throw ParameterMismatch(type, target);

            auto p = type.port->get(value);
            switch ( p.protocol().value() ) {
                case hilti::rt::Protocol::TCP: return val_mgr->Port(p.port(), ::TransportProto::TRANSPORT_TCP);
                case hilti::rt::Protocol::UDP: return val_mgr->Port(p.port(), ::TransportProto::TRANSPORT_UDP);
                case hilti::rt::Protocol::ICMP: return val_mgr->Port(p.port(), ::TransportProto::TRANSPORT_ICMP);
                default: throw InvalidValue("port value with undefined protocol");
            }
        }

        case TypeInfo::SignedInteger_int8:
            return convertSignedInteger(type.signed_integer_int8->get(value), "int8", target);

        case TypeInfo::SignedInteger_int16:
            return convertSignedInteger(type.signed_integer_int16->get(value), "int16", target);

        case TypeInfo::SignedInteger_int32:
            return convertSignedInteger(type.signed_integer_int32->get(value), "int32", target);

        case TypeInfo::SignedInteger_int64:
            return convertSignedInteger(type.signed_integer_int64->get(value), "int64", target);

        case TypeInfo::Time: {
            if ( target->Tag() != TYPE_TIME )
                throw ParameterMismatch(type, target);

            return make_intrusive<TimeVal>(type.time->get(value).seconds());
        }

        case TypeInfo::Real: {
            if ( target->Tag() != TYPE_DOUBLE )
                throw ParameterMismatch(type, target);

            return make_intrusive<DoubleVal>(type.real->get(value));
        }

        case TypeInfo::Set: {
            if ( target->Tag() != TYPE_TABLE )
                throw ParameterMismatch(type, target);

            if ( type.set->dereferencedType()->tag == TypeInfo::Tuple )
                throw ParameterMismatch("internal error: sets with tuples not yet supported in to_val()");

            auto tt = cast_intrusive<TableType>(target);
            if ( ! tt->IsSet() )
                throw ParameterMismatch(type, target);

            auto zv = make_intrusive<TableVal>(tt);

            for ( const auto& i : type.set->iterate(value) ) {
                if ( tt->GetIndexTypes().size() != 1 )
                    throw ParameterMismatch(type, target);

                auto idx = to_val(i, tt->GetIndexTypes()[0]);
                zv->Assign(std::move(idx), nullptr);
            }

            return std::move(zv);
        }

        case TypeInfo::String: {
            if ( target->Tag() != TYPE_STRING )
                throw ParameterMismatch(type, target);

            const auto& s = type.string->get(value);
            return make_intrusive<StringVal>(s);
        }

        case TypeInfo::StrongReference: {
            const auto& x = type.strong_reference->value(value);
            return x ? detail::to_val(x, target) : nullptr;
        }

        case TypeInfo::Struct: {
            if ( target->Tag() != TYPE_RECORD )
                throw ParameterMismatch(type, target);

            auto rtype = cast_intrusive<RecordType>(target);

            auto rval = make_intrusive<RecordVal>(rtype);
            auto num_fields = rtype->NumFields();

            int idx = 0;
            for ( const auto& [field, fvalue] : type.struct_->iterate(value) ) {
                if ( idx >= num_fields )
                    throw ParameterMismatch(hilti::rt::fmt("no matching record field for field '%s'", field.name));

                // Special-case: Lift up anonymous bitfields.
                if ( field.name == "_anon" ) {
                    if ( field.type->tag == TypeInfo::Bitfield ) {
                        size_t j = 0;
                        for ( const auto& x : field.type->bitfield->iterate(fvalue) )
                            setRecordField(rval.get(), rtype, idx++, x.second);

                        continue;
                    }

                    // There can't be any other anonymous fields.
                    auto msg = hilti::rt::fmt("unexpected anonymous field: %s", field.name);
                    reporter->InternalError("%s", msg.c_str());
                }
                else {
                    auto* field_name = rtype->FieldName(idx);

                    if ( field_name != field.name )
                        throw ParameterMismatch(hilti::rt::fmt("mismatch in field name: expected '%s', found '%s'",
                                                               field.name, field_name));

                    if ( fvalue )
                        setRecordField(rval.get(), rtype, idx, fvalue);

                    idx++;
                }
            }

            // We already check above that all Spicy-side fields are mapped so we
            // can only hit this if there are uninitialized Zeek-side fields left.
            if ( idx != num_fields )
                throw ParameterMismatch(hilti::rt::fmt("missing initialization for field '%s'", rtype->FieldName(idx)));

            return std::move(rval);
        }

        case TypeInfo::Tuple: {
            if ( target->Tag() != TYPE_RECORD )
                throw ParameterMismatch(type, target);

            auto rtype = cast_intrusive<RecordType>(target);

            if ( type.tuple->elements().size() != static_cast<size_t>(rtype->NumFields()) )
                throw ParameterMismatch(type, target);

            auto rval = make_intrusive<RecordVal>(rtype);

            int idx = 0;
            for ( const auto& x : type.tuple->iterate(value) ) {
                if ( auto fval = x.second.type().optional->value(x.second) ) {
                    if ( fval )
                        setRecordField(rval.get(), rtype, idx, fval);
                }

                idx++;
            }

            return rval;
        }

        case TypeInfo::ValueReference: {
            const auto& x = type.value_reference->value(value);
            return x ? detail::to_val(x, target) : nullptr;
        }

        case TypeInfo::Vector: {
            if ( target->Tag() != TYPE_VECTOR && target->Tag() != TYPE_LIST )
                throw ParameterMismatch(type, target);

            auto vt = cast_intrusive<VectorType>(target);
            auto zv = make_intrusive<VectorVal>(vt);

            for ( const auto& i : type.vector->iterate(value) )
                zv->Assign(zv->Size(), to_val(i, vt->Yield()));

            return std::move(zv);
        }

        case TypeInfo::UnsignedInteger_uint8:
            return convertUnsignedInteger(type.unsigned_integer_uint8->get(value), "uint8", target);

        case TypeInfo::UnsignedInteger_uint16:
            return convertUnsignedInteger(type.unsigned_integer_uint16->get(value), "uint16", target);

        case TypeInfo::UnsignedInteger_uint32:
            return convertUnsignedInteger(type.unsigned_integer_uint32->get(value), "uint32", target);

        case TypeInfo::UnsignedInteger_uint64:
            return convertUnsignedInteger(type.unsigned_integer_uint64->get(value), "uint64", target);

        case TypeInfo::WeakReference: {
            const auto& x = type.weak_reference->value(value);
            return x ? detail::to_val(x, target) : nullptr;
        }

        default: throw InvalidValue(fmt("unexpected type for conversion to Zeek (%s)", type.display));
    }

    hilti::rt::cannot_be_reached();
}

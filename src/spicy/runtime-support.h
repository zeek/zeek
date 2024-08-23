// See the file "COPYING" in the main distribution directory for copyright.

/**
 * Functions and types available to generated Spicy/Zeek glue code.
 */

#pragma once

#include <limits>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>

#include <hilti/rt/deferred-expression.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/types/all.h>
#include <hilti/rt/util.h>

#include "zeek/Desc.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/spicy/cookie.h"
#include "zeek/spicy/manager.h"
#include "zeek/spicy/port-range.h"

namespace zeek::spicy::rt {

// Adapt to rename of exception.
using UsageError = ::hilti::rt::UsageError;

/**
 * Exception thrown by event generation code if the value of an `$...`
 * expression isn't available.
 */
class ValueUnavailable : public UsageError {
public:
    using UsageError::UsageError;
};

/**
 * Exception thrown by event generation code if the values can't be converted
 * to Zeek.
 */
class InvalidValue : public UsageError {
public:
    using UsageError::UsageError;
};

/**
 * Exception thrown by event generation code if functionality is used
 * that the current build does not support.
 */
class Unsupported : public UsageError {
public:
    using UsageError::UsageError;
};

/**
 * Exception thrown if there's a type mismatch between Spicy and Zeek side.
 */
class TypeMismatch : public UsageError {
    using UsageError::UsageError;
};

/**
 * Exception thrown by event generation code if there's a type mismatch between
 * a Spicy-side parameter value and what the Zeek event expects.
 */
class ParameterMismatch : public TypeMismatch {
public:
    ParameterMismatch(std::string_view msg, std::string_view location = "")
        : TypeMismatch(hilti::rt::fmt("Event parameter mismatch, %s", msg)) {}
    ParameterMismatch(std::string_view have, const TypePtr& want, std::string_view location = "")
        : ParameterMismatch(_fmt(have, want)) {}

private:
    static std::string _fmt(const std::string_view& have, const TypePtr& want) {
        ODesc d;
        want->Describe(&d);
        return hilti::rt::fmt("cannot convert Spicy value of type '%s' to Zeek value of type '%s'", have,
                              d.Description());
    }
};

/**
 * Exception thrown by the runtime library when Zeek has flagged a problem.
 */
class ZeekError : public UsageError {
public:
    using UsageError::UsageError;
};

/**
 * Begins registration of a Spicy EVT module. All subsequent, other `register_*()`
 * function call will be associated with this module for documentation purposes.
 */
void register_spicy_module_begin(const std::string& id, const std::string& description);

/**
 * Registers a Spicy protocol analyzer with its EVT meta information with the
 * plugin's runtime.
 */
void register_protocol_analyzer(const std::string& id, hilti::rt::Protocol proto,
                                const hilti::rt::Vector<::zeek::spicy::rt::PortRange>& ports,
                                const std::string& parser_orig, const std::string& parser_resp,
                                const std::string& replaces, const std::string& linker_scope);

/**
 * Registers a Spicy file analyzer with its EVT meta information with the
 * plugin's runtime.
 */
void register_file_analyzer(const std::string& id, const hilti::rt::Vector<std::string>& mime_types,
                            const std::string& parser, const std::string& replaces, const std::string& linker_scope);

/** Reports a Zeek-side "weird". */
void weird(const std::string& id, const std::string& addl);

/**
 * Registers a Spicy packet analyzer with its EVT meta information with the
 * plugin's runtime.
 */
void register_packet_analyzer(const std::string& id, const std::string& parser, const std::string& replaces,
                              const std::string& linker_scope);

/** Registers a Spicy-generated type to make it available inside Zeek. */
void register_type(const std::string& ns, const std::string& id, const TypePtr& type);

/**
 * Ends registration of a Spicy EVT module. This must follow a preceding
 * `registerSpicyModuleBegin()`.
 */
void register_spicy_module_end();


/** Identifies a Zeek-side type. */
enum class ZeekTypeTag : uint64_t {
    Addr,
    Any,
    Bool,
    Count,
    Double,
    Enum,
    Error,
    File,
    Func,
    Int,
    Interval,
    List,
    Opaque,
    Pattern,
    Port,
    Record,
    String,
    Subnet,
    Table,
    Time,
    Type,
    Vector,
    Void,
};

extern TypePtr create_base_type(ZeekTypeTag tag);

extern TypePtr create_enum_type(
    const std::string& ns, const std::string& id,
    const hilti::rt::Vector<std::tuple<std::string, hilti::rt::integer::safe<int64_t>>>& labels);

struct RecordField {
    std::string id;   /**< name of record field */
    TypePtr type;     /**< Spicy-side type object */
    bool is_optional; /**< true if field is optional */
    bool is_log;      /**< true if field has `&log` */
};

extern TypePtr create_record_type(const std::string& ns, const std::string& id,
                                  const hilti::rt::Vector<RecordField>& fields);
extern RecordField create_record_field(const std::string& id, const TypePtr& type, hilti::rt::Bool is_optional,
                                       hilti::rt::Bool is_log);

extern TypePtr create_table_type(TypePtr key, std::optional<TypePtr> value);
extern TypePtr create_vector_type(const TypePtr& elem);

/** Returns true if an event has at least one handler defined. */
inline hilti::rt::Bool have_handler(const EventHandlerPtr& handler) { return static_cast<bool>(handler); }

/**
 * Creates a new event handler under the given name.
 */
void install_handler(const std::string& name);

/**
 * Looks up an event handler by name. The handler must have been installed
 * before through `install_handler()`.
 */
EventHandlerPtr internal_handler(const std::string& name);

/** Raises a Zeek event, given the handler and arguments. */
void raise_event(const EventHandlerPtr& handler, const hilti::rt::Vector<ValPtr>& args);

/**
 * Returns the Zeek type of an event's i'th argument. The result's ref count
 * is not increased.
 */
TypePtr event_arg_type(const EventHandlerPtr& handler, const hilti::rt::integer::safe<uint64_t>& idx);

/**
 * Retrieves the connection ID for the currently processed Zeek connection.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of record type
 */
ValPtr& current_conn();

/**
 * Retrieves the direction of the currently processed Zeek connection.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of boolean type
 */
ValPtr& current_is_orig();

/**
 * Logs a string through the Spicy plugin's debug output.
 *
 * @param cookie refers to the connection or file that the message is associated with
 * @param msg message to log
 */
void debug(const Cookie& cookie, const std::string& msg);

/**
 * Logs a string through the Spicy plugin's debug output. This version logs
 * the information the currently processed connection or file.
 *
 * @param msg message to log
 */
void debug(const std::string& msg);

/**
 * Retrieves the fa_file instance for the currently processed Zeek file.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of record type
 */
ValPtr current_file();

/**
 * Retrieves a `raw_pkt_hdr` instance for the currently processed Zeek packet.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @return Zeek value of record type
 */
ValPtr current_packet();

/**
 * Returns true if we're currently parsing the originator side of a
 * connection.
 */
hilti::rt::Bool is_orig();

/**
 * Returns the current connection's UID.
 */
std::string uid();

/**
 * Returns the current connection's ID tuple.
 */
std::tuple<hilti::rt::Address, hilti::rt::Port, hilti::rt::Address, hilti::rt::Port> conn_id();

/** Instructs to Zeek to flip the directionality of the current connecction. */
void flip_roles();

/**
 * Returns the number of packets seen so far on the current side of the
 * current connection.
 */
hilti::rt::integer::safe<uint64_t> number_packets();

/**
 * Triggers a DPD protocol confirmation for the currently processed
 * connection. Assumes that the HILTI context's cookie value has been set
 * accordingly.
 */
void confirm_protocol();

/**
 * Triggers a DPD protocol violation for the currently processed connection.
 * Assumes that the HILTI context's cookie value has been set accordingly.
 *
 * @param reason short description of what went wrong
 */
void reject_protocol(const std::string& reason = "protocol rejected");

/**
 * Opaque handle to a protocol analyzer.
 */
class ProtocolHandle {
public:
    ProtocolHandle() {}
    explicit ProtocolHandle(uint64_t id, ::hilti::rt::Protocol proto) : _id(id), _proto(proto) {}

    uint64_t id() const {
        if ( ! _id )
            throw ValueUnavailable("uninitialized protocol handle");

        return *_id;
    }

    const auto& protocol() const { return _proto; }

    friend std::string to_string(const ProtocolHandle& h, ::hilti::rt::detail::adl::tag) {
        if ( ! h._id )
            return "(uninitialized protocol handle)";

        return std::to_string(*h._id);
    }

    friend std::ostream& operator<<(std::ostream& stream, const ProtocolHandle& h) {
        return stream << ::hilti::rt::to_string(h);
    }

private:
    std::optional<uint64_t> _id;
    ::hilti::rt::Protocol _proto = ::hilti::rt::Protocol::Undef;
};

/**
 * Adds a Zeek-side child protocol analyzer to the current connection.
 *
 * @param analyzer the Zeek-side name of the analyzer to instantiate; can be left unset to add a DPD analyzer
 */
void protocol_begin(const std::optional<std::string>& analyzer, const ::hilti::rt::Protocol& proto);

/**
 * Adds a Zeek-side DPD child analyzer to the current connection.
 *
 * @param proto the transport-layer protocol of the desired DPD analyzer; must be TCP or UDP
 */
void protocol_begin(const ::hilti::rt::Protocol& proto);

/**
 * Gets a handle to a child analyzer of a given type. If a child of that type
 * does not yet exist it will be created.
 *
 * @param analyzer the Zeek-side name of the analyzer to get (e.g., `HTTP`)
 * @param proto the transport-layer protocol of the analyzer, which must match
 * the type of the child analyzer that *analyzer* refers to
 *
 * @return a handle to the child analyzer. When done, the handle should be
 * closed, either explicitly with protocol_handle_close or implicitly with
 * protocol_end.
 */
rt::ProtocolHandle protocol_handle_get_or_create(const std::string& analyzer, const ::hilti::rt::Protocol& proto);

/**
 * Forwards data to all previously instantiated Zeek-side child protocol
 * analyzers of a given transport-layer protocol.
 *
 * @param is_orig true to feed data to originator side, false for responder
 * @param data next chunk of stream data for child analyzer to process
 * @param h optional handle to pass data to a specific child analyzer only
 */
void protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data, const ::hilti::rt::Protocol& proto);

/**
 * Forwards data to a specific previously instantiated Zeek-side child protocol
 * analyzer.
 *
 * @param is_orig true to feed data to originator side, false for responder
 * @param data next chunk of stream data for child analyzer to process
 * @param h handle identifying the specific child analyzer only
 */
void protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data, const ProtocolHandle& h);

/**
 * Signals a gap in input data to all previously instantiated Zeek-side child
 * protocol analyzers.
 *
 * @param is_orig true to signal gap to originator side, false for responder
 * @param offset of the gap inside the protocol stream
 * @param length of the gap
 * @param h optional handle to the child analyzer to signal a gap to
 */
void protocol_gap(const hilti::rt::Bool& is_orig, const hilti::rt::integer::safe<uint64_t>& offset,
                  const hilti::rt::integer::safe<uint64_t>& len, const std::optional<ProtocolHandle>& h = {});

/**
 * Signals EOD to all previously instantiated Zeek-side child protocol
 * analyzers and removes them.
 */
void protocol_end();

/**
 * Closes a protocol handle.
 *
 * @param handle handle of the protocol analyzer to close.
 */
void protocol_handle_close(const ProtocolHandle& handle);

/**
 * Signals the beginning of a file to Zeek's file analysis, associating it
 * with the current connection.
 *
 * @param mime_type optional mime type passed to Zeek
 * @param fid optional file ID passed to Zeek
 * @returns Zeek-side file ID of the new file
 */
std::string file_begin(const std::optional<std::string>& mime_type, const std::optional<std::string>& fid);

/**
 * Returns the current file's FUID.
 */
std::string fuid();

/**
 * Terminates the currently active Zeek-side session, flushing all state. Any
 * subsequent activity will start a new session from scratch.
 */
void terminate_session();

/**
 * Tells Zeek to skip sending any further input data to the current protocol
 * or file analyzer.
 */
void skip_input();

/**
 * Signals the expected size of a file to Zeek's file analysis.
 *
 * @param size expected final size of the file
 * @param fid ID of the file to operate on; if unset, the most recently begun file is used
 */
void file_set_size(const hilti::rt::integer::safe<uint64_t>& size, const std::optional<std::string>& fid = {});

/**
 * Passes file content on to Zeek's file analysis.
 *
 * @param data next chunk of data
 * @param fid ID of the file to operate on; if unset, the most recently begun file is used
 */
void file_data_in(const hilti::rt::Bytes& data, const std::optional<std::string>& fid = {});

/**
 * Passes file content at a specific offset on to Zeek's file analysis.
 *
 * @param data next chunk of data
 * @param offset file offset of the data geing passed in
 * @param fid ID of the file to operate on; if unset, the most recently begun file is used
 */
void file_data_in_at_offset(const hilti::rt::Bytes& data, const hilti::rt::integer::safe<uint64_t>& offset,
                            const std::optional<std::string>& fid = {});

/**
 * Signals a gap in a file to Zeek's file analysis.
 *
 * @param offset of the gap
 * @param length of the gap
 * @param fid ID of the file to operate on; if unset, the most recently begun file is used
 */
void file_gap(const hilti::rt::integer::safe<uint64_t>& offset, const hilti::rt::integer::safe<uint64_t>& len,
              const std::optional<std::string>& fid = {});

/**
 * Signals the end of a file to Zeek's file analysis.
 *
 * @param fid ID of the file to operate on; if unset, the most recently begun file is used
 */
void file_end(const std::optional<std::string>& fid = {});

/** Specifies the next-layer packet analyzer. */
void forward_packet(const hilti::rt::integer::safe<uint32_t>& identifier);

/** Gets the network time from Zeek. */
hilti::rt::Time network_time();

// Forward-declare to_val() functions.
template<typename T, typename std::enable_if_t<hilti::rt::is_tuple<T>::value>* = nullptr>
ValPtr to_val(const T& t, const TypePtr& target);
template<typename... Ts>
inline ValPtr to_val(const hilti::rt::Bitfield<Ts...>& v, const TypePtr& target);
template<typename T, typename std::enable_if_t<std::is_base_of<::hilti::rt::trait::isStruct, T>::value>* = nullptr>
ValPtr to_val(const T& t, const TypePtr& target);
template<typename T, typename std::enable_if_t<std::is_enum<typename T::Value>::value>* = nullptr>
ValPtr to_val(const T& t, const TypePtr& target);
template<typename T, typename std::enable_if_t<std::is_enum<T>::value>* = nullptr>
ValPtr to_val(const T& t, const TypePtr& target);
template<typename K, typename V>
ValPtr to_val(const hilti::rt::Map<K, V>& s, const TypePtr& target);
template<typename T>
ValPtr to_val(const hilti::rt::Set<T>& s, const TypePtr& target);
template<typename T>
ValPtr to_val(const hilti::rt::Vector<T>& v, const TypePtr& target);
template<typename T>
ValPtr to_val(const std::optional<T>& t, const TypePtr& target);
template<typename T, typename E>
ValPtr to_val(const hilti::rt::DeferredExpression<T, E>& t, const TypePtr& target);
template<typename T>
ValPtr to_val(hilti::rt::integer::safe<T> i, const TypePtr& target);
template<typename T>
ValPtr to_val(const hilti::rt::ValueReference<T>& t, const TypePtr& target);

inline ValPtr to_val(const hilti::rt::Bool& b, const TypePtr& target);
inline ValPtr to_val(const hilti::rt::Address& d, const TypePtr& target);
inline ValPtr to_val(const hilti::rt::Bytes& b, const TypePtr& target);
inline ValPtr to_val(const hilti::rt::Interval& t, const TypePtr& target);
inline ValPtr to_val(const hilti::rt::Port& d, const TypePtr& target);
inline ValPtr to_val(const hilti::rt::Time& t, const TypePtr& target);
inline ValPtr to_val(const std::string& s, const TypePtr& target);
inline ValPtr to_val(double r, const TypePtr& target);

/**
 * Converts a Spicy-side optional value to a Zeek value. This assumes the
 * optional is set, and will throw an exception if not. The result is
 * returned with ref count +1.
 */
template<typename T>
inline ValPtr to_val(const std::optional<T>& t, const TypePtr& target) {
    if ( t.has_value() )
        return to_val(hilti::rt::optional::value(t), target);

    return nullptr;
}

/**
 * Converts a Spicy-side DeferredExpression<T,E> value to a Zeek value. Such
 * result values are returned by the ``.?`` operator. If the result is not
 * set, this will convert into nullptr (which the tuple-to-record to_val()
 * picks up on).
 */
template<typename T, typename E>
inline ValPtr to_val(const hilti::rt::DeferredExpression<T, E>& t, const TypePtr& target) {
    try {
        return to_val(t(), target);
    } catch ( const hilti::rt::AttributeNotSet& ) {
        return nullptr;
    }
}

/**
 * Converts a Spicy-side string to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(const std::string& s, const TypePtr& target) {
    if ( target->Tag() != TYPE_STRING )
        throw ParameterMismatch("string", target);

    return make_intrusive<StringVal>(s);
}

/**
 * Converts a Spicy-side bytes instance to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(const hilti::rt::Bytes& b, const TypePtr& target) {
    if ( target->Tag() != TYPE_STRING )
        throw ParameterMismatch("string", target);

    return make_intrusive<StringVal>(b.str());
}

/**
 * Converts a Spicy-side integer to a Zeek value. The result is
 * returned with ref count +1.
 */
template<typename T>
inline ValPtr to_val(hilti::rt::integer::safe<T> i, const TypePtr& target) {
    ValPtr v = nullptr;
    if constexpr ( std::is_unsigned<T>::value ) {
        if ( target->Tag() == TYPE_COUNT )
            return val_mgr->Count(i);

        if ( target->Tag() == TYPE_INT )
            return val_mgr->Int(i);

        throw ParameterMismatch("uint64", target);
    }
    else {
        if ( target->Tag() == TYPE_INT )
            return val_mgr->Int(i);

        if ( target->Tag() == TYPE_COUNT ) {
            if ( i >= 0 )
                return val_mgr->Count(i);
            else
                throw ParameterMismatch("negative int64", target);
        }

        throw ParameterMismatch("int64", target);
    }
}

template<typename T>
ValPtr to_val(const hilti::rt::ValueReference<T>& t, const TypePtr& target) {
    if ( auto* x = t.get() )
        return to_val(*x, target);

    return nullptr;
}

/**
 * Converts a Spicy-side signed bool to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ValPtr to_val(const hilti::rt::Bool& b, const TypePtr& target) {
    if ( target->Tag() != TYPE_BOOL )
        throw ParameterMismatch("bool", target);

    return val_mgr->Bool(b);
}

/**
 * Converts a Spicy-side real to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(double r, const TypePtr& target) {
    if ( target->Tag() != TYPE_DOUBLE )
        throw ParameterMismatch("double", target);

    return make_intrusive<DoubleVal>(r);
}

/**
 * Converts a Spicy-side address to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(const hilti::rt::Address& d, const TypePtr& target) {
    if ( target->Tag() != TYPE_ADDR )
        throw ParameterMismatch("addr", target);

    auto in_addr = d.asInAddr();
    if ( auto v4 = std::get_if<struct in_addr>(&in_addr) )
        return make_intrusive<AddrVal>(IPAddr(*v4));
    else {
        auto v6 = std::get<struct in6_addr>(in_addr);
        return make_intrusive<AddrVal>(IPAddr(v6));
    }
}

/**
 * Converts a Spicy-side address to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(const hilti::rt::Port& p, const TypePtr& target) {
    if ( target->Tag() != TYPE_PORT )
        throw ParameterMismatch("port", target);

    switch ( p.protocol().value() ) {
        case hilti::rt::Protocol::TCP: return val_mgr->Port(p.port(), ::TransportProto::TRANSPORT_TCP);

        case hilti::rt::Protocol::UDP: return val_mgr->Port(p.port(), ::TransportProto::TRANSPORT_UDP);

        case hilti::rt::Protocol::ICMP: return val_mgr->Port(p.port(), ::TransportProto::TRANSPORT_ICMP);

        default: throw InvalidValue("port value with undefined protocol");
    }
}

/**
 * Converts a Spicy-side time to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(const hilti::rt::Interval& i, const TypePtr& target) {
    if ( target->Tag() != TYPE_INTERVAL )
        throw ParameterMismatch("interval", target);

    return make_intrusive<IntervalVal>(i.seconds());
}

/**
 * Converts a Spicy-side time to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(const hilti::rt::Time& t, const TypePtr& target) {
    if ( target->Tag() != TYPE_TIME )
        throw ParameterMismatch("time", target);

    return make_intrusive<TimeVal>(t.seconds());
}

/**
 * Converts a Spicy-side vector to a Zeek value. The result is returned with
 * ref count +1.
 */
template<typename T>
inline ValPtr to_val(const hilti::rt::Vector<T>& v, const TypePtr& target) {
    if ( target->Tag() != TYPE_VECTOR && target->Tag() != TYPE_LIST )
        throw ParameterMismatch("expected vector or list", target);

    auto vt = cast_intrusive<VectorType>(target);
    auto zv = make_intrusive<VectorVal>(vt);
    for ( const auto& i : v )
        zv->Assign(zv->Size(), to_val(i, vt->Yield()));

    return zv;
}

/**
 * Converts a Spicy-side map to a Zeek value. The result is returned with
 * ref count +1.
 */
template<typename K, typename V>
inline ValPtr to_val(const hilti::rt::Map<K, V>& m, const TypePtr& target) {
    if constexpr ( hilti::rt::is_tuple<K>::value )
        throw ParameterMismatch("internal error: sets with tuples not yet supported in to_val()");

    if ( target->Tag() != TYPE_TABLE )
        throw ParameterMismatch("map", target);

    auto tt = cast_intrusive<TableType>(target);
    if ( tt->IsSet() )
        throw ParameterMismatch("map", target);

    if ( tt->GetIndexTypes().size() != 1 )
        throw ParameterMismatch("map with non-tuple elements", target);

    auto zv = make_intrusive<TableVal>(tt);

    for ( const auto& i : m ) {
        auto k = to_val(i.first, tt->GetIndexTypes()[0]);
        auto v = to_val(i.second, tt->Yield());
        zv->Assign(std::move(k), std::move(v));
    }

    return zv;
} // namespace spicy::rt

/**
 * Converts a Spicy-side set to a Zeek value. The result is returned with
 * ref count +1.
 */
template<typename T>
inline ValPtr to_val(const hilti::rt::Set<T>& s, const TypePtr& target) {
    if ( target->Tag() != TYPE_TABLE )
        throw ParameterMismatch("set", target);

    auto tt = cast_intrusive<TableType>(target);
    if ( ! tt->IsSet() )
        throw ParameterMismatch("set", target);

    auto zv = make_intrusive<TableVal>(tt);

    for ( const auto& i : s ) {
        if constexpr ( hilti::rt::is_tuple<T>::value )
            throw ParameterMismatch("internal error: sets with tuples not yet supported in to_val()");
        else {
            if ( tt->GetIndexTypes().size() != 1 )
                throw ParameterMismatch("set with non-tuple elements", target);

            auto idx = to_val(i, tt->GetIndexTypes()[0]);
            zv->Assign(std::move(idx), nullptr);
        }
    }

    return zv;
}

namespace {
template<typename, template<typename...> typename>
struct is_instance_impl : std::false_type {};

template<template<typename...> typename U, typename... Ts>
struct is_instance_impl<U<Ts...>, U> : std::true_type {};
} // namespace

template<typename T, template<typename...> typename U>
using is_instance = is_instance_impl<std::remove_cv_t<T>, U>;

template<typename T>
inline void set_record_field(RecordVal* rval, const IntrusivePtr<RecordType>& rtype, int idx, const T& x) {
    using NoConversionNeeded = std::integral_constant<
        bool, std::is_same_v<T, int8_t> || std::is_same_v<T, int16_t> || std::is_same_v<T, int32_t> ||
                  std::is_same_v<T, int64_t> || std::is_same_v<T, uint8_t> || std::is_same_v<T, uint16_t> ||
                  std::is_same_v<T, uint32_t> || std::is_same_v<T, uint64_t> || std::is_same_v<T, double> ||
                  std::is_same_v<T, std::string> || std::is_same_v<T, bool>>;

    using IsSignedInteger = std::integral_constant<bool, std::is_same_v<T, hilti::rt::integer::safe<int8_t>> ||
                                                             std::is_same_v<T, hilti::rt::integer::safe<int16_t>> ||
                                                             std::is_same_v<T, hilti::rt::integer::safe<int32_t>> ||
                                                             std::is_same_v<T, hilti::rt::integer::safe<int64_t>>>;

    using IsUnsignedInteger = std::integral_constant<bool, std::is_same_v<T, hilti::rt::integer::safe<uint8_t>> ||
                                                               std::is_same_v<T, hilti::rt::integer::safe<uint16_t>> ||
                                                               std::is_same_v<T, hilti::rt::integer::safe<uint32_t>> ||
                                                               std::is_same_v<T, hilti::rt::integer::safe<uint64_t>>>;

    if constexpr ( NoConversionNeeded::value )
        rval->Assign(idx, x);
    else if constexpr ( IsSignedInteger::value )
        rval->Assign(idx, static_cast<int64_t>(x.Ref()));
    else if constexpr ( IsUnsignedInteger::value )
        rval->Assign(idx, static_cast<uint64_t>(x.Ref()));
    else if constexpr ( std::is_same_v<T, hilti::rt::Bytes> )
        rval->Assign(idx, x.str());
    else if constexpr ( std::is_same_v<T, hilti::rt::Bool> )
        rval->Assign(idx, static_cast<bool>(x));
    else if constexpr ( std::is_same_v<T, std::string> )
        rval->Assign(idx, x);
    else if constexpr ( std::is_same_v<T, hilti::rt::Time> )
        rval->AssignTime(idx, x.seconds());
    else if constexpr ( std::is_same_v<T, hilti::rt::Interval> )
        rval->AssignInterval(idx, x.seconds());
    else if constexpr ( std::is_same_v<T, hilti::rt::Null> ) {
        // "Null" turns into an unset optional record field.
    }
    else if constexpr ( is_instance<T, std::optional>::value ) {
        if ( x.has_value() )
            set_record_field(rval, rtype, idx, *x);
    }
    else if constexpr ( is_instance<T, hilti::rt::DeferredExpression>::value ) {
        try {
            set_record_field(rval, rtype, idx, x());
        } catch ( const hilti::rt::AttributeNotSet& ) {
            // leave unset
        }
    }
    else {
        ValPtr v = nullptr;

        // This may return a nullptr in cases where the field is to be left unset.
        v = to_val(x, rtype->GetFieldType(idx));

        if ( v )
            rval->Assign(idx, v);
        else {
            // Field must be &optional or &default.
            if ( auto attrs = rtype->FieldDecl(idx)->attrs;
                 ! attrs || ! (attrs->Find(detail::ATTR_DEFAULT) || attrs->Find(detail::ATTR_OPTIONAL)) )
                throw ParameterMismatch(hilti::rt::fmt("missing initialization for field '%s'", rtype->FieldName(idx)));
        }
    }
}

/**
 * Converts a Spicy-side tuple to a Zeek record value. The result is returned
 * with ref count +1.
 */
template<typename T, typename std::enable_if_t<hilti::rt::is_tuple<T>::value>*>
inline ValPtr to_val(const T& t, const TypePtr& target) {
    if ( target->Tag() != TYPE_RECORD )
        throw ParameterMismatch("tuple", target);

    auto rtype = cast_intrusive<RecordType>(target);

    if ( std::tuple_size<T>::value != rtype->NumFields() )
        throw ParameterMismatch("tuple", target);

    auto rval = make_intrusive<RecordVal>(rtype);
    size_t idx = 0;
    hilti::rt::tuple_for_each(t, [&](const auto& x) { set_record_field(rval.get(), rtype, idx++, x); });

    return rval;
}

/**
 * Converts a Spicy-side bitfield to a Zeek record value. The result is returned
 * with ref count +1.
 */
template<typename... Ts>
inline ValPtr to_val(const hilti::rt::Bitfield<Ts...>& v, const TypePtr& target) {
    using Bitfield = hilti::rt::Bitfield<Ts...>;

    if ( target->Tag() != TYPE_RECORD )
        throw ParameterMismatch("bitfield", target);

    auto rtype = cast_intrusive<RecordType>(target);

    if ( sizeof...(Ts) - 1 != rtype->NumFields() )
        throw ParameterMismatch("bitfield", target);

    auto rval = make_intrusive<RecordVal>(rtype);
    size_t idx = 0;
    hilti::rt::tuple_for_each(v.value, [&](const auto& x) {
        if ( idx < sizeof...(Ts) - 1 ) // last element is original integer value, with no record equivalent
            set_record_field(rval.get(), rtype, idx++, x);
    });

    return rval;
}

template<typename>
constexpr bool is_optional_impl = false;
template<typename T>
constexpr bool is_optional_impl<std::optional<T>> = true;
template<typename T>
constexpr bool is_optional = is_optional_impl<std::remove_cv_t<std::remove_reference_t<T>>>;

/**
 * Converts Spicy-side struct to a Zeek record value. The result is returned
 * with a ref count +1.
 */
template<typename T, typename std::enable_if_t<std::is_base_of<::hilti::rt::trait::isStruct, T>::value>*>
inline ValPtr to_val(const T& t, const TypePtr& target) {
    if ( target->Tag() != TYPE_RECORD )
        throw ParameterMismatch("struct", target);

    auto rtype = cast_intrusive<RecordType>(target);

    auto rval = make_intrusive<RecordVal>(rtype);
    int idx = 0;

    auto num_fields = rtype->NumFields();

    t.__visit([&](std::string_view name, const auto& val) {
        if ( idx >= num_fields )
            throw ParameterMismatch(hilti::rt::fmt("no matching record field for field '%s'", name));

        // Special-case: Lift up anonymous bitfields (which always come as std::optionals).
        if ( name == "<anon>" ) {
            using X = typename std::decay<decltype(val)>::type;
            if constexpr ( is_optional<X> ) {
                if constexpr ( std::is_base_of<::hilti::rt::trait::isBitfield, typename X::value_type>::value ) {
                    size_t j = 0;
                    hilti::rt::tuple_for_each(val->value, [&](const auto& x) {
                        if ( j++ < std::tuple_size<decltype(val->value)>() -
                                       1 ) // last element is original integer value, with no record equivalent
                            set_record_field(rval.get(), rtype, idx++, x);
                    });
                    return;
                }
            }

            // There can't be any other anonymous fields.
            auto msg = hilti::rt::fmt("unexpected anonymous field: %s", name);
            reporter->InternalError("%s", msg.c_str());
        }
        else {
            auto field = rtype->GetFieldType(idx);
            std::string field_name = rtype->FieldName(idx);

            if ( field_name != name )
                throw ParameterMismatch(
                    hilti::rt::fmt("mismatch in field name: expected '%s', found '%s'", name, field_name));

            set_record_field(rval.get(), rtype, idx++, val);
        }
    });

    // We already check above that all Spicy-side fields are mapped so we
    // can only hit this if there are uninitialized Zeek-side fields left.
    if ( idx != num_fields )
        throw ParameterMismatch(hilti::rt::fmt("missing initialization for field '%s'", rtype->FieldName(idx + 1)));

    return rval;
}

/** Maps HILTI's `Protocol` enum to Zeek's `transport_proto` enum. */
inline ValPtr to_val_for_transport_proto(int64_t val, const TypePtr& target) {
    switch ( val ) {
        case hilti::rt::Protocol::TCP: return id::transport_proto->GetEnumVal(::TransportProto::TRANSPORT_TCP);
        case hilti::rt::Protocol::UDP: return id::transport_proto->GetEnumVal(::TransportProto::TRANSPORT_UDP);
        case hilti::rt::Protocol::ICMP: return id::transport_proto->GetEnumVal(::TransportProto::TRANSPORT_ICMP);
        case hilti::rt::Protocol::Undef: [[fallthrough]]; // just for readability, make Undef explicit
        default: return id::transport_proto->GetEnumVal(::TransportProto::TRANSPORT_UNKNOWN);
    }

    hilti::rt::cannot_be_reached();
}

/**
 * Converts a Spicy-side enum to a Zeek enum value. The result is returned
 * with ref count +1.
 */
template<typename T, typename std::enable_if_t<std::is_enum<typename T::Value>::value>*>
inline ValPtr to_val(const T& t, const TypePtr& target) {
    if ( target->Tag() != TYPE_ENUM )
        throw ParameterMismatch("enum", target);

    // We'll usually be getting an int64_t for T, but allow other signed ints
    // as well.
    static_assert(std::is_signed<std::underlying_type_t<typename T::Value>>{});
    auto it = static_cast<int64_t>(t.value());

    // Special case: map enum values to Zeek's semantics.
    if ( target->GetName() == "transport_proto" ) {
        if ( ! std::is_same_v<T, hilti::rt::Protocol> )
            throw ParameterMismatch(hilti::rt::demangle(typeid(t).name()), target);

        return to_val_for_transport_proto(it, target);
    }

    // Zeek's enum can't be negative, so we swap in max_int for our Undef (-1).
    if ( it == std::numeric_limits<int64_t>::max() )
        // can't allow this ...
        throw InvalidValue("enum values with value max_int not supported by Zeek integration");

    zeek_int_t bt = (it >= 0 ? it : std::numeric_limits<::zeek_int_t>::max());

    return target->AsEnumType()->GetEnumVal(bt);
}


/**
 * Returns the Zeek value associated with a global Zeek-side ID. Throws if the
 * ID does not exist.
 */
inline ValPtr get_value(const std::string& name) {
    if ( auto id = zeek::detail::global_scope()->Find(name) )
        return id->GetVal();
    else
        throw InvalidValue(util::fmt("no such Zeek variable: '%s'", name.c_str()));
}

namespace detail {
/** Helper to raise a ``TypeMismatch`` exception. */
inline auto type_mismatch(const ValPtr& v, const char* expected) {
    throw TypeMismatch(util::fmt("type mismatch in Zeek value: expected %s, but got %s", expected,
                                 ::zeek::type_name(v->GetType()->Tag())));
}

/**
 * Helper to check the type of Zeek value against an expected type tag, raising
 * a ``TypeMismatch`` exception on mismatch.
 */
inline auto check_type(const ValPtr& v, ::zeek::TypeTag type_tag, const char* expected) {
    if ( v->GetType()->Tag() != type_tag )
        type_mismatch(v, expected);
}

} // namespace detail

/** Type for a Zeek record value. */
using ValRecordPtr = ::zeek::IntrusivePtr<::zeek::RecordVal>;

/** Type for a Zeek set value. */
using ValSetPtr = ::zeek::IntrusivePtr<::zeek::TableVal>;

/** Type for a Zeek table value. */
using ValTablePtr = ::zeek::IntrusivePtr<::zeek::TableVal>;

/** Type for a Zeek vector value. */
using ValVectorPtr = ::zeek::IntrusivePtr<::zeek::VectorVal>;

/** Converts a Zeek `addr` value to its Spicy equivalent. Throws on error. */
inline ::hilti::rt::Address as_address(const ValPtr& v) {
    detail::check_type(v, TYPE_ADDR, "address");
    return ::hilti::rt::Address(v->AsAddr());
}

/** Converts a Zeek `bool` value to its Spicy equivalent. Throws on error. */
inline ::hilti::rt::Bool as_bool(const ValPtr& v) {
    detail::check_type(v, TYPE_BOOL, "bool");
    return ::hilti::rt::Bool(v->AsBool());
}

/** Converts a Zeek `count` value to its Spicy equivalent. Throws on error. */
inline hilti::rt::integer::safe<uint64_t> as_count(const ValPtr& v) {
    detail::check_type(v, TYPE_COUNT, "count");
    return v->AsCount();
}

/** Converts a Zeek `double` value to its Spicy equivalent. Throws on error. */
inline double as_double(const ValPtr& v) {
    detail::check_type(v, TYPE_DOUBLE, "double");
    return v->AsDouble();
}

/**
 * Converts a Zeek `enum` value to a string containing the (unscoped) label
 * name. Throws on error.
 */
inline std::string as_enum(const ValPtr& v) {
    detail::check_type(v, TYPE_ENUM, "enum");
    // Zeek returns the name as "<module>::<enum>", we just want the enum name.
    return hilti::rt::rsplit1(v->GetType()->AsEnumType()->Lookup(v->AsEnum()), "::").second;
}

/** Converts a Zeek `int` value to its Spicy equivalent. Throws on error. */
inline hilti::rt::integer::safe<int64_t> as_int(const ValPtr& v) {
    detail::check_type(v, TYPE_INT, "int");
    return v->AsInt();
}

/** Converts a Zeek `interval` value to its Spicy equivalent. Throws on error. */
inline ::hilti::rt::Interval as_interval(const ValPtr& v) {
    detail::check_type(v, TYPE_INTERVAL, "interval");
    return ::hilti::rt::Interval(v->AsInterval(), hilti::rt::Interval::SecondTag{});
}

/** Converts a Zeek `port` value to its Spicy equivalent. Throws on error. */
inline ::hilti::rt::Port as_port(const ValPtr& v) {
    detail::check_type(v, TYPE_PORT, "port");
    auto p = v->AsPortVal();
    // Wrap port number into safe integer to catch any overflows (Zeek returns
    // an uint32, while HILTI wants an uint16).
    return ::hilti::rt::Port(hilti::rt::integer::safe<uint16_t>(p->Port()), p->PortType());
}

/** Converts a Zeek `record` value to its Spicy equivalent. Throws on error. */
inline ValRecordPtr as_record(const ValPtr& v) {
    detail::check_type(v, TYPE_RECORD, "record");
    return ::zeek::cast_intrusive<::zeek::RecordVal>(v);
}

/** Converts a Zeek `set` value to its Spicy equivalent. Throws on error. */
inline ValSetPtr as_set(const ValPtr& v) {
    detail::check_type(v, TYPE_TABLE, "set");

    if ( ! v->AsTableVal()->GetType()->IsSet() )
        detail::type_mismatch(v, "set");

    return ::zeek::cast_intrusive<::zeek::TableVal>(v);
}

/** Converts a Zeek `string` value to its Spicy equivalent. Throws on error. */
inline hilti::rt::Bytes as_string(const ValPtr& v) {
    detail::check_type(v, TYPE_STRING, "string");
    auto str = v->AsString();
    return hilti::rt::Bytes(reinterpret_cast<const char*>(str->Bytes()), str->Len());
}

/** Converts a Zeek `subnet` value to its Spicy equivalent. Throws on error. */
inline ::hilti::rt::Network as_subnet(const ValPtr& v) {
    detail::check_type(v, TYPE_SUBNET, "subnet");
    auto subnet = v->AsSubNet();
    return ::hilti::rt::Network(subnet.Prefix(), subnet.Length());
}

/** Converts a Zeek `table` value to its Spicy equivalent. Throws on error. */
inline ValTablePtr as_table(const ValPtr& v) {
    detail::check_type(v, TYPE_TABLE, "table");

    if ( v->AsTableVal()->GetType()->IsSet() )
        detail::type_mismatch(v, "table");

    return ::zeek::cast_intrusive<::zeek::TableVal>(v);
}

/** Converts a Zeek `time` value to its Spicy equivalent. Throws on error. */
inline ::hilti::rt::Time as_time(const ValPtr& v) {
    detail::check_type(v, TYPE_TIME, "time");
    return ::hilti::rt::Time(v->AsTime(), hilti::rt::Time::SecondTag{});
}

/** Converts a Zeek `vector` value to its Spicy equivalent. Throws on error. */
inline ValVectorPtr as_vector(const ValPtr& v) {
    detail::check_type(v, TYPE_VECTOR, "vector");
    return ::zeek::cast_intrusive<::zeek::VectorVal>(v);
}


/** Retrieves a global Zeek variable of assumed type `addr`. Throws on error. */
inline hilti::rt::Address get_address(const std::string& name) { return as_address(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `bool`. Throws on error. */
inline hilti::rt::Bool get_bool(const std::string& name) { return as_bool(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `count`. Throws on error. */
inline hilti::rt::integer::safe<uint64_t> get_count(const std::string& name) { return as_count(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `double`. Throws on error. */
inline double get_double(const std::string& name) { return as_double(get_value(name)); }

/**
 * Retrieves a global Zeek variable of assumed type `enum` as a string
 * containing the (unscoped) label name. Throws on error.
 */
inline std::string get_enum(const std::string& name) { return as_enum(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `int`. Throws on error. */
inline hilti::rt::integer::safe<int64_t> get_int(const std::string& name) { return as_int(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `interval`. Throws on error. */
inline hilti::rt::Interval get_interval(const std::string& name) { return as_interval(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `port`. Throws on error. */
inline hilti::rt::Port get_port(const std::string& name) { return as_port(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `record`. Throws on error. */
inline ValRecordPtr get_record(const std::string& name) { return as_record(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `set`. Throws on error. */
inline ValSetPtr get_set(const std::string& name) { return as_set(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `string`. Throws on error. */
inline hilti::rt::Bytes get_string(const std::string& name) { return as_string(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `subnet`. Throws on error. */
inline hilti::rt::Network get_subnet(const std::string& name) { return as_subnet(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `table`. Throws on error. */
inline ValTablePtr get_table(const std::string& name) { return as_table(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `time`. Throws on error. */
inline hilti::rt::Time get_time(const std::string& name) { return as_time(get_value(name)); }

/** Retrieves a global Zeek variable of assumed type `vector`. Throws on error. */
inline ValVectorPtr get_vector(const std::string& name) { return as_vector(get_value(name)); }

/** Retrieves the value of Zeek record field. Throws on error. */
inline ::zeek::ValPtr record_field(const zeek::spicy::rt::ValRecordPtr& v, const std::string& field) {
    auto index = v->GetType()->AsRecordType()->FieldOffset(field.c_str());
    if ( index < 0 )
        throw InvalidValue(util::fmt("no such record field: %s", field.c_str()));

    if ( auto x = v->GetFieldOrDefault(index) )
        return x;
    else
        throw InvalidValue(util::fmt("record field is not set: %s", field.c_str()));
}

/** Retrieves the value of Zeek record field. Throws on error. */
inline ::zeek::ValPtr record_field(const std::string& name, const std::string& index) {
    return record_field(get_record(name), index);
}

/** Check if a Zeek record has a field's value set. Throws on errors. */
inline hilti::rt::Bool record_has_value(const zeek::spicy::rt::ValRecordPtr& v, const std::string& field) {
    auto index = v->GetType()->AsRecordType()->FieldOffset(field.c_str());
    if ( index < 0 )
        throw InvalidValue(util::fmt("no such field in record type: %s", field.c_str()));

    return v->HasField(index);
}

/** Checks if a Zeek record has a field's value set. Throws on errors. */
inline hilti::rt::Bool record_has_value(const std::string& name, const std::string& index) {
    return record_has_value(get_record(name), index);
}

/** Check if a Zeek record type has a field of a give name. Throws on errors. */
inline hilti::rt::Bool record_has_field(const zeek::spicy::rt::ValRecordPtr& v, const std::string& field) {
    return v->GetType()->AsRecordType()->FieldOffset(field.c_str()) >= 0;
}

/** Check if a Zeek record type has a field of a give name. Throws on errors. */
inline hilti::rt::Bool record_has_field(const std::string& name, const std::string& index) {
    return record_has_value(get_record(name), index);
}

/** Checks if a Zeek set contains a given element. Throws on errors. */
template<typename T>
::hilti::rt::Bool set_contains(const ValSetPtr& v, const T& key) {
    auto index = v->GetType()->AsTableType()->GetIndexTypes()[0];
    return (v->Find(to_val(key, index)) != nullptr);
}

/** Checks if a Zeek set contains a given element. Throws on errors. */
template<typename T>
::hilti::rt::Bool set_contains(const std::string& name, const T& key) {
    return set_contains(get_set(name), key);
}

/** Checks if a Zeek table contains a given element. Throws on errors. */
template<typename T>
::hilti::rt::Bool table_contains(const ValTablePtr& v, const T& key) {
    auto index = v->GetType()->AsTableType()->GetIndexTypes()[0];
    return (v->Find(to_val(key, index)) != nullptr);
}

/** Check if a Zeek table contains a given element. Throws on errors. */
template<typename T>
::hilti::rt::Bool table_contains(const std::string& name, const T& key) {
    return table_contains(get_table(name), key);
}

/**
 * Retrieves a value from a Zeek table. Returns an error value if the key does
 * not exist. Throws on other errors.
 */
template<typename T>
std::optional<::zeek::ValPtr> table_lookup(const zeek::spicy::rt::ValTablePtr& v, const T& key) {
    auto index = v->GetType()->AsTableType()->GetIndexTypes()[0];
    if ( auto x = v->FindOrDefault(to_val(key, index)) )
        return x;
    else
        return {};
}

/**
 * Retrieves a value from a Zeek table. Returns an error value if the key does
 * not exist. Throws on other errors.
 */
template<typename T>
std::optional<::zeek::ValPtr> table_lookup(const std::string& name, const T& key) {
    return table_lookup(get_table(name), key);
}

/** Returns a Zeek vector element. Throws on errors. */
inline ::zeek::ValPtr vector_index(const zeek::spicy::rt::ValVectorPtr& v,
                                   const hilti::rt::integer::safe<uint64_t>& index) {
    if ( index >= v->Size() )
        throw InvalidValue(util::fmt("vector index out of bounds: %" PRIu64, index.Ref()));

    return v->ValAt(index);
}

/** Returns a Zeek vector element. Throws on errors. */
inline ::zeek::ValPtr vector_index(const std::string& name, const hilti::rt::integer::safe<uint64_t>& index) {
    return vector_index(get_vector(name), index);
}

/** Returns the size of a Zeek vector. Throws on errors. */
inline hilti::rt::integer::safe<uint64_t> vector_size(const zeek::spicy::rt::ValVectorPtr& v) { return v->Size(); }

/** Returns the size of a Zeek vector. Throws on errors. */
inline hilti::rt::integer::safe<uint64_t> vector_size(const std::string& name) { return vector_size(get_vector(name)); }

} // namespace zeek::spicy::rt

namespace hilti::rt::detail::adl {
// Stringification for opaque type handles.
inline std::string to_string(const zeek::ValPtr& v, detail::adl::tag /* unused */) { return "<Zeek value>"; }

inline std::string to_string(const zeek::spicy::rt::ValRecordPtr& v, detail::adl::tag /* unused */) {
    return "<Zeek record>";
}

inline std::string to_string(const zeek::spicy::rt::ValTablePtr& v, detail::adl::tag /* unused */) {
    return "<Zeek set/table>";
}

inline std::string to_string(const zeek::spicy::rt::ValVectorPtr& v, detail::adl::tag /* unused */) {
    return "<Zeek vector>";
}
} // namespace hilti::rt::detail::adl

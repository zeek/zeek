// See the file "COPYING" in the main distribution directory for copyright.

/**
 * Functions and types available to generated Spicy/Zeek glue code.
 */

#pragma once

#include <limits>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <tuple>
#include <utility>

#include <hilti/rt/deferred-expression.h>
#include <hilti/rt/exception.h>
#include <hilti/rt/extension-points.h>
#include <hilti/rt/fmt.h>
#include <hilti/rt/types/all.h>

#include "zeek/Desc.h"
#include "zeek/spicy/cookie.h"
#include "zeek/spicy/manager.h"
#include "zeek/spicy/port-range.h"

namespace zeek::spicy::rt {

// Adapt to rename of exception.
#if SPICY_VERSION_NUMBER >= 10700
using UsageError = ::hilti::rt::UsageError;
#else
using UsageError = ::hilti::rt::UserException;
#endif

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
 * Exception thrown by event generation code if there's a type mismatch
 * between the Spicy-side value and what the Zeek event expects.
 */
class TypeMismatch : public UsageError {
public:
    TypeMismatch(const std::string_view& msg, std::string_view location = "")
        : UsageError(hilti::rt::fmt("Event parameter mismatch, %s", msg)) {}
    TypeMismatch(const std::string_view& have, TypePtr want, std::string_view location = "")
        : TypeMismatch(_fmt(have, want)) {}

private:
    std::string _fmt(const std::string_view& have, TypePtr want) {
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
 * Registers a Spicy protocol analyzer with its EVT meta information with the
 * plugin's runtime.
 */
void register_protocol_analyzer(const std::string& name, hilti::rt::Protocol proto,
                                const hilti::rt::Vector<::zeek::spicy::rt::PortRange>& ports,
                                const std::string& parser_orig, const std::string& parser_resp,
                                const std::string& replaces, const std::string& linker_scope);

/**
 * Registers a Spicy file analyzer with its EVT meta information with the
 * plugin's runtime.
 */
void register_file_analyzer(const std::string& name, const hilti::rt::Vector<std::string>& mime_types,
                            const std::string& parser, const std::string& replaces, const std::string& linker_scope);

/** Reports a Zeek-side "weird". */
void weird(const std::string& id, const std::string& addl);

/**
 * Registers a Spicy packet analyzer with its EVT meta information with the
 * plugin's runtime.
 */
void register_packet_analyzer(const std::string& name, const std::string& parser, const std::string& replaces,
                              const std::string& linker_scope);

/** Registers a Spicy-generated type to make it available inside Zeek. */
void register_type(const std::string& ns, const std::string& id, const TypePtr& type);

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

using RecordField = std::tuple<std::string, TypePtr, hilti::rt::Bool>; // (ID, type, optional)
extern TypePtr create_record_type(const std::string& ns, const std::string& id,
                                  const hilti::rt::Vector<RecordField>& fields);

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
void reject_protocol(const std::string& reason);

/**
 * Opaque handle to a protocol analyzer.
 */
class ProtocolHandle {
public:
    ProtocolHandle() {}
    explicit ProtocolHandle(uint64_t id) : _id(id) {}

    uint64_t id() const {
        if ( ! _id )
            throw ValueUnavailable("uninitialized protocol handle");

        return *_id;
    }

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
};

/**
 * Adds a Zeek-side child protocol analyzer to the current connection.
 *
 * @param analyzer if given, the Zeek-side name of the analyzer to instantiate;
 * if not given, DPD will be used
 */
void protocol_begin(const std::optional<std::string>& analyzer);

/**
 * Gets a handle to a child analyzer of a given type. If a child of that type
 * does not yet exist it will be created.
 *
 * @param analyzer the Zeek-side name of the analyzer to get (e.g., `HTTP`)
 *
 * @return a handle to the child analyzer. When done, the handle should be
 * closed, either explicitly with protocol_handle_close or implicitly with
 * protocol_end.
 */
ProtocolHandle protocol_handle_get_or_create(const std::string& analyzer);

/**
 * Forwards data to all previously instantiated Zeek-side child protocol
 * analyzers.
 *
 * @param is_orig true to feed data to originator side, false for responder
 * @param data next chunk of stream data for child analyzer to process
 * @param h optional handle to the child analyzer to stream data into
 */
void protocol_data_in(const hilti::rt::Bool& is_orig, const hilti::rt::Bytes& data,
                      const std::optional<ProtocolHandle>& h = {});

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
 * param mime_type optional mime type passed to Zeek
 * @returns Zeek-side file ID of the new file
 */
std::string file_begin(const std::optional<std::string>& mime_type);

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
ValPtr to_val(const T& t, TypePtr target);
template<typename T, typename std::enable_if_t<std::is_base_of<::hilti::rt::trait::isStruct, T>::value>* = nullptr>
ValPtr to_val(const T& t, TypePtr target);
template<typename T, typename std::enable_if_t<std::is_enum<typename T::Value>::value>* = nullptr>
ValPtr to_val(const T& t, TypePtr target);
template<typename T, typename std::enable_if_t<std::is_enum<T>::value>* = nullptr>
ValPtr to_val(const T& t, TypePtr target);
template<typename K, typename V>
ValPtr to_val(const hilti::rt::Map<K, V>& s, TypePtr target);
template<typename T>
ValPtr to_val(const hilti::rt::Set<T>& s, TypePtr target);
template<typename T>
ValPtr to_val(const hilti::rt::Vector<T>& v, TypePtr target);
template<typename T>
ValPtr to_val(const std::optional<T>& t, TypePtr target);
template<typename T>
ValPtr to_val(const hilti::rt::DeferredExpression<T>& t, TypePtr target);
template<typename T>
ValPtr to_val(hilti::rt::integer::safe<T> i, TypePtr target);
template<typename T>
ValPtr to_val(const hilti::rt::ValueReference<T>& t, TypePtr target);

inline ValPtr to_val(const hilti::rt::Bool& b, TypePtr target);
inline ValPtr to_val(const hilti::rt::Address& d, TypePtr target);
inline ValPtr to_val(const hilti::rt::Bytes& b, TypePtr target);
inline ValPtr to_val(const hilti::rt::Interval& t, TypePtr target);
inline ValPtr to_val(const hilti::rt::Port& d, TypePtr target);
inline ValPtr to_val(const hilti::rt::Time& t, TypePtr target);
inline ValPtr to_val(const std::string& s, TypePtr target);
inline ValPtr to_val(double r, TypePtr target);

/**
 * Converts a Spicy-side optional value to a Zeek value. This assumes the
 * optional is set, and will throw an exception if not. The result is
 * returned with ref count +1.
 */
template<typename T>
inline ValPtr to_val(const std::optional<T>& t, TypePtr target) {
    if ( t.has_value() )
        return to_val(hilti::rt::optional::value(t), target);

    return nullptr;
}

/**
 * Converts a Spicy-side DeferredExpression<T> value to a Zeek value. Such
 * result values are returned by the ``.?`` operator. If the result is not
 * set, this will convert into nullptr (which the tuple-to-record to_val()
 * picks up on).
 */
template<typename T>
inline ValPtr to_val(const hilti::rt::DeferredExpression<T>& t, TypePtr target) {
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
inline ValPtr to_val(const std::string& s, TypePtr target) {
    if ( target->Tag() != TYPE_STRING )
        throw TypeMismatch("string", target);

    return make_intrusive<StringVal>(s);
}

/**
 * Converts a Spicy-side bytes instance to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(const hilti::rt::Bytes& b, TypePtr target) {
    if ( target->Tag() != TYPE_STRING )
        throw TypeMismatch("string", target);

    return make_intrusive<StringVal>(b.str());
}

/**
 * Converts a Spicy-side integer to a Zeek value. The result is
 * returned with ref count +1.
 */
template<typename T>
inline ValPtr to_val(hilti::rt::integer::safe<T> i, TypePtr target) {
    ValPtr v = nullptr;
    if constexpr ( std::is_unsigned<T>::value ) {
        if ( target->Tag() == TYPE_COUNT )
            return val_mgr->Count(i);

        if ( target->Tag() == TYPE_INT )
            return val_mgr->Int(i);

        throw TypeMismatch("uint64", target);
    }
    else {
        if ( target->Tag() == TYPE_INT )
            return val_mgr->Int(i);

        if ( target->Tag() == TYPE_COUNT ) {
            if ( i >= 0 )
                return val_mgr->Count(i);
            else
                throw TypeMismatch("negative int64", target);
        }

        throw TypeMismatch("int64", target);
    }
}

template<typename T>
ValPtr to_val(const hilti::rt::ValueReference<T>& t, TypePtr target) {
    if ( auto* x = t.get() )
        return to_val(*x, target);

    return nullptr;
}

/**
 * Converts a Spicy-side signed bool to a Zeek value. The result is
 * returned with ref count +1.
 */
inline ValPtr to_val(const hilti::rt::Bool& b, TypePtr target) {
    if ( target->Tag() != TYPE_BOOL )
        throw TypeMismatch("bool", target);

    return val_mgr->Bool(b);
}

/**
 * Converts a Spicy-side real to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(double r, TypePtr target) {
    if ( target->Tag() != TYPE_DOUBLE )
        throw TypeMismatch("double", target);

    return make_intrusive<DoubleVal>(r);
}

/**
 * Converts a Spicy-side address to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(const hilti::rt::Address& d, TypePtr target) {
    if ( target->Tag() != TYPE_ADDR )
        throw TypeMismatch("addr", target);

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
inline ValPtr to_val(const hilti::rt::Port& p, TypePtr target) {
    if ( target->Tag() != TYPE_PORT )
        throw TypeMismatch("port", target);

#if SPICY_VERSION_NUMBER >= 10700
    auto proto = p.protocol().value();
#else
    auto proto = p.protocol();
#endif

    switch ( proto ) {
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
inline ValPtr to_val(const hilti::rt::Interval& i, TypePtr target) {
    if ( target->Tag() != TYPE_INTERVAL )
        throw TypeMismatch("interval", target);

    return make_intrusive<IntervalVal>(i.seconds());
}

/**
 * Converts a Spicy-side time to a Zeek value. The result is returned with
 * ref count +1.
 */
inline ValPtr to_val(const hilti::rt::Time& t, TypePtr target) {
    if ( target->Tag() != TYPE_TIME )
        throw TypeMismatch("time", target);

    return make_intrusive<TimeVal>(t.seconds());
}

/**
 * Converts a Spicy-side vector to a Zeek value. The result is returned with
 * ref count +1.
 */
template<typename T>
inline ValPtr to_val(const hilti::rt::Vector<T>& v, TypePtr target) {
    if ( target->Tag() != TYPE_VECTOR && target->Tag() != TYPE_LIST )
        throw TypeMismatch("expected vector or list", target);

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
inline ValPtr to_val(const hilti::rt::Map<K, V>& m, TypePtr target) {
    if constexpr ( hilti::rt::is_tuple<K>::value )
        throw TypeMismatch("internal error: sets with tuples not yet supported in to_val()");

    if ( target->Tag() != TYPE_TABLE )
        throw TypeMismatch("map", target);

    auto tt = cast_intrusive<TableType>(target);
    if ( tt->IsSet() )
        throw TypeMismatch("map", target);

    if ( tt->GetIndexTypes().size() != 1 )
        throw TypeMismatch("map with non-tuple elements", target);

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
inline ValPtr to_val(const hilti::rt::Set<T>& s, TypePtr target) {
    if ( target->Tag() != TYPE_TABLE )
        throw TypeMismatch("set", target);

    auto tt = cast_intrusive<TableType>(target);
    if ( ! tt->IsSet() )
        throw TypeMismatch("set", target);

    auto zv = make_intrusive<TableVal>(tt);

    for ( const auto& i : s ) {
        if constexpr ( hilti::rt::is_tuple<T>::value )
            throw TypeMismatch("internal error: sets with tuples not yet supported in to_val()");
        else {
            if ( tt->GetIndexTypes().size() != 1 )
                throw TypeMismatch("set with non-tuple elements", target);

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
#if ZEEK_VERSION_NUMBER >= 50200
        rval->Assign(idx, static_cast<int64_t>(x.Ref()));
#else
        rval->Assign(idx, static_cast<int>(x.Ref()));
#endif
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
                throw TypeMismatch(hilti::rt::fmt("missing initialization for field '%s'", rtype->FieldName(idx)));
        }
    }
}

/**
 * Converts a Spicy-side tuple to a Zeek record value. The result is returned
 * with ref count +1.
 */
template<typename T, typename std::enable_if_t<hilti::rt::is_tuple<T>::value>*>
inline ValPtr to_val(const T& t, TypePtr target) {
    if ( target->Tag() != TYPE_RECORD )
        throw TypeMismatch("tuple", target);

    auto rtype = cast_intrusive<RecordType>(target);

    if ( std::tuple_size<T>::value != rtype->NumFields() )
        throw TypeMismatch("tuple", target);

    auto rval = make_intrusive<RecordVal>(rtype);
    int idx = 0;
    hilti::rt::tuple_for_each(t, [&](const auto& x) { set_record_field(rval.get(), rtype, idx++, x); });

    return rval;
}

/**
 * Converts Spicy-side struct to a Zeek record value. The result is returned
 * with a ref count +1.
 */
template<typename T, typename std::enable_if_t<std::is_base_of<::hilti::rt::trait::isStruct, T>::value>*>
inline ValPtr to_val(const T& t, TypePtr target) {
    if ( target->Tag() != TYPE_RECORD )
        throw TypeMismatch("struct", target);

    auto rtype = cast_intrusive<RecordType>(target);

    auto rval = make_intrusive<RecordVal>(rtype);
    int idx = 0;

    auto num_fields = rtype->NumFields();

    t.__visit([&](const auto& name, const auto& val) {
        if ( idx >= num_fields )
            throw TypeMismatch(hilti::rt::fmt("no matching record field for field '%s'", name));

        auto field = rtype->GetFieldType(idx);
        std::string field_name = rtype->FieldName(idx);

        if ( field_name != name )
            throw TypeMismatch(hilti::rt::fmt("mismatch in field name: expected '%s', found '%s'", name, field_name));

        set_record_field(rval.get(), rtype, idx++, val);
    });

    // We already check above that all Spicy-side fields are mapped so we
    // can only hit this if there are uninitialized Zeek-side fields left.
    if ( idx != num_fields )
        throw TypeMismatch(hilti::rt::fmt("missing initialization for field '%s'", rtype->FieldName(idx + 1)));

    return rval;
}

/**
 * Converts a Spicy-side enum to a Zeek record value. The result is returned
 * with ref count +1.
 */
template<typename T, typename std::enable_if_t<std::is_enum<typename T::Value>::value>*>
inline ValPtr to_val(const T& t, TypePtr target) {
#if SPICY_VERSION_NUMBER >= 10700
    auto proto = typename T::Value(t.value());
#else
    auto proto = t;
#endif

    return to_val(proto, target);
}

/**
 * Converts a C++ Spicy-side enum to a Zeek record value. The result is returned
 * with ref count +1. This specialization is provided for compatibility with <spicy-1.7.0.
 *
 * TODO(bbannier): remove this once we drop support for Spicy versions before 1.7.0.
 */
template<typename T, typename std::enable_if_t<std::is_enum<T>::value>*>
inline ValPtr to_val(const T& t, TypePtr target) {
    if ( target->Tag() != TYPE_ENUM )
        throw TypeMismatch("enum", target);

    // We'll usually be getting an int64_t for T, but allow other signed ints
    // as well.
    static_assert(std::is_signed<std::underlying_type_t<T>>{});
    auto it = static_cast<int64_t>(t);

    // Zeek's enum can't be negative, so we swap in max_int for our Undef (-1).
    if ( it == std::numeric_limits<int64_t>::max() )
        // can't allow this ...
        throw InvalidValue("enum values with value max_int not supported by Zeek integration");

    zeek_int_t bt = (it >= 0 ? it : std::numeric_limits<::zeek_int_t>::max());

    return target->AsEnumType()->GetEnumVal(bt);
}

} // namespace zeek::spicy::rt

// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/serializer/sans-broker/Serializer.h"

#include <netinet/in.h>
#include <cstddef>
#include <cstdio>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>

#include "zeek/Attr.h"
#include "zeek/Desc.h"
#include "zeek/Dict.h"
#include "zeek/EventRegistry.h"
#include "zeek/File.h"
#include "zeek/Frame.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/IP.h"
#include "zeek/IPAddr.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/OpaqueVal.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/ZeekString.h"
#include "zeek/cluster/Event.h"
#include "zeek/net_util.h"
#include "zeek/util-types.h"

namespace zeek::cluster {

// Not sure that namespace makes so much sense.
namespace format::broker::bin::v1 {

using It = std::back_insert_iterator<zeek::byte_buffer>;

static It encode_varbyte(size_t value, It out) {
    // From format/bin/v1.h - we don't seem to have supported 64bit values, ever.
    //
    // Use varbyte encoding to compress sequence size on the wire.
    // For 64-bit values, the encoded representation cannot get larger than 10
    // bytes. A scratch space of 16 bytes suffices as upper bound.
    if ( value > std::numeric_limits<uint32_t>::max() )
        throw std::range_error("encode_varbyte() with value > uint32_t max");

    auto x = static_cast<uint32_t>(value);
    while ( x > 0x7f ) {
        *out++ = static_cast<std::byte>((static_cast<uint8_t>(x) & 0x7f) | 0x80);
        x >>= 7;
    }
    *out++ = static_cast<std::byte>(static_cast<uint8_t>(x) & 0x7f);
    return out;
}

/**
 * Copy a uint64_t value in network byte order without a tag to out.
 */
static It encode_untagged_uint64(uint64_t u64val, It out) {
    uint64_t u64val_net = htonll(u64val);
    const std::byte* p = reinterpret_cast<std::byte*>(&u64val_net);
    return std::copy(p, p + sizeof(uint64_t), out);
}

static It encode_count(uint64_t val, It out) {
    *out++ = static_cast<std::byte>(variant_tag::count);
    return encode_untagged_uint64(val, out);
}

/**
 * Integer in broker format is just an uin64_t with an integer tagged.
 */
static It encode_integer(int64_t i64val, It out) {
    *out++ = static_cast<std::byte>(variant_tag::integer);
    out = encode_untagged_uint64(static_cast<uint64_t>(i64val), out);
    return out;
}

/**
 * Encode the payload of a string. It's varbyte prefixed.
 */
static It encode_untagged_string(const std::byte* begin, const std::byte* end, It out) {
    assert(end >= begin);
    size_t len = end - begin;
    out = encode_varbyte(len, out);
    return std::copy(begin, end, out);
}

/**
 * Add a tagged string into out with a variable length encoded length before.
 */
static It encode_string(const std::byte* begin, const std::byte* end, It out) {
    *out++ = static_cast<std::byte>(variant_tag::string);
    return encode_untagged_string(begin, end, out);
}

/**
 * Add a tagged string into out with a variable length encoded length before.
 */
static It encode_string(const char* s, It out) {
    return encode_string(reinterpret_cast<const std::byte*>(s), reinterpret_cast<const std::byte*>(s + strlen(s)), out);
}

/**
 * Add a tagged string into out with a variable length encoded length before.
 */
static It encode_string(std::string_view s, It out) {
    return encode_string(reinterpret_cast<const std::byte*>(s.data()),
                         reinterpret_cast<const std::byte*>(s.data() + s.size()), out);
}

/**
 * Put a vector tag and its length.
 */
static It encode_vector_start(size_t len, It out) {
    *out++ = static_cast<std::byte>(format::broker::bin::v1::variant_tag::vector);
    return encode_varbyte(len, out);
};

bool encode(const zeek::Val& val, std::back_insert_iterator<zeek::byte_buffer> out) {
    switch ( val.GetType()->Tag() ) {
        case TYPE_BOOL: {
            *out++ = static_cast<std::byte>(variant_tag::boolean);
            *out++ = static_cast<std::byte>(val.AsBool());
            return true;
        }
        case TYPE_INT: {
            encode_integer(val.AsInt(), out);
            return true;
        }
        case TYPE_COUNT: {
            encode_count(val.AsCount(), out);
            return true;
        }
        case TYPE_DOUBLE: {
            // XXX This is not compatible with the original CAF-based format:
            // See caf::detail::pack754 in ieee_754.hpp for what was done previously
            // for interoperability.
            //
            // We could certainly vendor that code if we wanted to keep
            // binary compatibility, but I'm not sure it matters all much.
            auto u64 = std::bit_cast<uint64_t>(val.AsDouble());
            *out++ = static_cast<std::byte>(variant_tag::real);
            encode_untagged_uint64(u64, out);
            return true;
        }
        case TYPE_TIME: {
            auto s = val.AsTime();
            uint64_t ns = static_cast<uint64_t>(s * 1000000000.0);

            *out++ = static_cast<std::byte>(variant_tag::timestamp);
            encode_untagged_uint64(ns, out);
            return true;
        }
        case TYPE_INTERVAL: {
            auto s = val.AsInterval();
            uint64_t ns = static_cast<uint64_t>(s * 1000000000.0);

            *out++ = static_cast<std::byte>(variant_tag::timespan);
            encode_untagged_uint64(ns, out);
            return true;
        }
        case TYPE_STRING: {
            encode_string(val.AsString()->ToStdStringView(), out);
            return true;
        }
        case TYPE_PATTERN: {
            // Patterns are encoded as two element vectors of two strings.
            *out++ = static_cast<std::byte>(variant_tag::vector);
            out = encode_varbyte(2, out);
            const auto* pattern = val.AsPattern();
            out = encode_string(pattern->PatternText(), out);
            encode_string(pattern->AnywherePatternText(), out);
            return true;
        }
        case TYPE_ENUM: {
            *out++ = static_cast<std::byte>(variant_tag::enum_value);
            auto* x = val.GetType<zeek::EnumType>()->Lookup(val.AsEnum());
            encode_untagged_string(reinterpret_cast<const std::byte*>(x),
                                   reinterpret_cast<const std::byte*>(x + strlen(x)), out);
            return true;
        }
        case TYPE_PORT: {
            // Port is the uin16_t port value followed by the internal
            // TransportProto enum value. The prior to_broker_port_proto()
            // converted to enum class broker::port::protocol that has the
            // same values as TransportProto, so no need for this.
            *out++ = static_cast<std::byte>(variant_tag::port);
            const auto* pv = val.AsPortVal();
            uint16_t p16 = static_cast<uint16_t>(pv->Port());
            p16 = htons(p16);

            const std::byte* p = reinterpret_cast<std::byte*>(&p16);
            out = std::copy(p, p + sizeof(uint16_t), out);

            uint8_t proto = static_cast<uint8_t>(pv->PortType());
            *out++ = static_cast<std::byte>(proto);

            return true;
        }
        case TYPE_ADDR: {
            // Zeek's internal representation is the same as the broker format expects it:
            // IPv4 is is mapped to IPv6 and it's all in network byte order.
            *out++ = static_cast<std::byte>(variant_tag::address);
            const auto& addr = val.AsAddr();
            std::byte buf[16];
            addr.CopyIPv6(reinterpret_cast<uint32_t*>(&buf));
            std::copy(buf, buf + 16, out);

            return true;
        }
        case TYPE_SUBNET: {
            // Subnet is an address + length.
            *out++ = static_cast<std::byte>(variant_tag::subnet);
            const auto& sub = val.AsSubNet();
            std::byte buf[16];
            sub.Prefix().CopyIPv6(reinterpret_cast<uint32_t*>(&buf));
            out = std::copy(buf, buf + 16, out);
            // Broker encodes the IPv6 subnetlength (96+IPv4 len)
            *out++ = static_cast<std::byte>(sub.LengthIPv6());

            return true;
        }
        case TYPE_TABLE: {
            const auto* table_val = val.AsTableVal();
            const auto* dict = val.AsTable();
            const auto& table_type = table_val->GetType<zeek::TableType>();
            const bool is_table = table_type->IsTable();

            if ( is_table )
                *out++ = static_cast<std::byte>(variant_tag::table);
            else
                *out++ = static_cast<std::byte>(variant_tag::set);

            encode_varbyte(dict->Length(), out);

            size_t key_size = table_type->GetIndexTypes().size();

            for ( const auto& te : *dict ) {
                auto hk = te.GetHashKey();
                auto vl = table_val->RecreateIndex(*hk);

                // XXX: Not sure how we would discriminate between
                // table[vector of count] of X and table[count, count] of X
                // probably never been an issue or nobody ever thought
                // about this?
                //
                // Why do we even do this? Why not just always encode
                // as a vector?
                if ( key_size == 1 ) {
                    assert(vl->Length() == 1);
                    if ( ! encode(*vl->Idx(0), out) )
                        return false;
                }
                else {
                    // encode keys individual vector.
                    *out++ = static_cast<std::byte>(variant_tag::vector);
                    encode_varbyte(key_size, out);

                    for ( int i = 0; i < vl->Length(); i++ )
                        if ( ! encode(*vl->Idx(i), out) )
                            return false;
                }

                // If this is a table, the vector is immediately
                // followed by the value.
                if ( is_table ) {
                    if ( ! encode(*(te.value->GetVal()), out) )
                        return false;
                }
            }

            return true;
        }
        case TYPE_RECORD: {
            const auto* rval = val.AsRecordVal();
            const auto& rtype = rval->GetType<zeek::RecordType>();
            size_t num_fields = rtype->NumFields();

            *out++ = static_cast<std::byte>(variant_tag::vector);
            encode_varbyte(num_fields, out);

            for ( size_t i = 0; i < num_fields; i++ ) {
                auto fv = rval->GetFieldOrDefault(i);

                // Unset fields are encoded with a none tag.
                if ( ! fv ) {
                    *out++ = static_cast<std::byte>(variant_tag::none);
                }
                else {
                    if ( ! encode(*fv, out) )
                        return false;
                }
            }

            return true;
        }
        case TYPE_VECTOR: {
            *out++ = static_cast<std::byte>(variant_tag::vector);
            const auto* vv = val.AsVectorVal();
            size_t len = vv->Size();
            out = encode_varbyte(len, out);
            for ( size_t i = 0; i < len; i++ ) {
                // XXX PERF: Going via RawVec() or ZVal could be faster so
                // we do not allocate new Val instances just for serialization.
                // Not different than what was done broker/Data.cc, but we
                // could definitely do better here for atomic types.
                const auto& x = vv->ValAt(i);
                if ( ! x ) {
                    zeek::reporter->Error("serialization of vectors with holes is unsupported");
                    return false;
                }
                if ( ! encode(*vv->ValAt(i), out) )
                    return false;
            }

            return true;
        }
        case TYPE_FILE: {
            // filename as string and the receiver just opens the file?
            // this is crazy stuff. I don't think we should support this.
            encode_string(val.AsFile()->Name(), out);
            return true;
        }
        case TYPE_OPAQUE: {
            // Opaque values are encoded as lists of v->OpaqueName() / mgr->TypeID(ov)
            // followed by another list containing the elements produced by OpaqueVal::ToListVal().
            const auto* ov = val.AsOpaqueVal();

            // This will abort if the OpaqueVal wasn't registered properly.
            const auto& type_str = OpaqueMgr::mgr()->TypeID(ov);

            auto lv = ov->ToListVal();
            if ( ! lv ) {
                reporter->Error("unsupported opaque type for serialization: %s (%s)",
                                obj_desc_short(ov->GetType()).c_str(), obj_desc_short(ov).c_str());
                return false;
            }

            size_t lv_len = lv->Length();

            *out++ = static_cast<std::byte>(variant_tag::vector);
            out = encode_varbyte(2, out);
            out = encode_string(type_str, out);

            // Start the nested list for the OpaqueVal
            *out++ = static_cast<std::byte>(variant_tag::vector);
            out = encode_varbyte(lv_len, out);
            for ( size_t i = 0; i < lv_len; i++ ) {
                auto v = lv->Idx(i);
                if ( ! is_atomic_type(v->GetType()) )
                    return false;

                if ( ! encode(*v, out) ) {
                    return false;
                }
            }

            return true;
        }

        case TYPE_FUNC: {
            // This is annoying. TYPE_FUNC is serialized as a vector of the function's name
            // and another two nested vectors, the latter holding pairs describing the captures.
            // The pairs are themselves vectors of value followed by the internal type tag as count,
            // for whatever reason.
            //
            // This is also is entangled and mixed between ZAM and non-ZAM variants, too.
            //
            // Seems it'd be nicer if we could use Frame as the serialization.
            //
            //     detail::FramePtr f = sf->CapturesToFrame()
            //
            // And then serialize in however way we think is reasonable. The Frame should
            // have IDsPtrs, too, so we can have names, maybe?
            //
            // And on the way back?
            //
            //     sf->CapturesFromFrame(detail::FramePtr&& f)
            //
            const auto* fv = val.AsFuncVal();
            // auto *f = fv->Get();
            auto* f = val.AsFunc();
            zeek::detail::FramePtr captures_frame;

            // Check if this ScriptFunc has any captures.
            if ( f->GetKind() == Func::SCRIPT_FUNC ) {
                auto* sf = static_cast<zeek::detail::ScriptFunc*>(f);
                captures_frame = sf->CapturesToFrame();
            }

            *out++ = static_cast<std::byte>(variant_tag::vector);
            // Either a one or two element vector, depending on captures.
            encode_varbyte(1 + (captures_frame ? 1 : 0), out);
            encode_string(f->GetName(), out);

            if ( captures_frame ) {
                // Start a new vector of size 1...
                *out++ = static_cast<std::byte>(variant_tag::vector);
                encode_varbyte(1, out);

                // That holds another vector with the number of captures:
                size_t sz = captures_frame->FrameSize();
                *out++ = static_cast<std::byte>(variant_tag::vector);
                encode_varbyte(sz, out);

                // Every frame element is a tuple of value and tag.
                //
                // XXX: Not sure that's all that useful. It's what the old format
                // did. A capture of a record value will be tagged with TYPE_RECORD,
                // but we won't be able to reconstruct it anyhow as we don't have
                // the name of the record type. We'd need to go back to the Func
                // captures for restoring.
                for ( size_t i = 0; i < sz; i++ ) {
                    *out++ = static_cast<std::byte>(variant_tag::vector);
                    auto element = captures_frame->GetElement(i);
                    encode_varbyte(2, out);
                    if ( ! encode(*element, out) )
                        return false;

                    encode_integer(element->GetType()->Tag(), out);
                }
            }

            return true;
        }

        case TYPE_LIST:
        case TYPE_ERROR: // ?
        case TYPE_TYPE:  // ?
        case TYPE_VOID:  // ?
        case TYPE_ANY: {
            zeek::reporter->Error("Unhandled val: %s %s", obj_desc_short(&val).c_str(),
                                  obj_desc_short(val.GetType()).c_str());
        }
    }

    return false;
}


/**
 * Does not move the span forward!
 */
uint64_t read_untagged_uint64(zeek::byte_buffer_span s) {
    assert(s.size() >= 8);

    // memcpy() to avoid unaligned access.
    uint64_t u64val;
    memcpy(&u64val, s.data(), sizeof(uint64_t));
    return ntohll(u64val);
}

/**
 * Reads a varbyte and moves the span forward.
 *
 * The lowest bits are in the first byte, later bits
 * are shifted by n * 7. See broker/format/bin.cc
 */
static bool read_varbyte(zeek::byte_buffer_span& s, size_t* res) {
    uint32_t value = 0;
    uint8_t cur = 0;
    int n = 0;

    do {
        if ( s.empty() )
            return false;

        cur = static_cast<uint8_t>(s[0]);
        s = s.subspan(1);
        value |= ((cur & 0x7f) << (n * 7));
        ++n;
    } while ( cur & 0x80 && n <= 3 );

    *res = value;
    return true;
}

static bool read_tag(zeek::byte_buffer_span& buffer_span, variant_tag* tag) {
    if ( buffer_span.empty() )
        return false;

    auto raw_tag = static_cast<uint8_t>(buffer_span[0]);

    if ( raw_tag > static_cast<uint8_t>(variant_tag::vector) ) // INVALID TAG
        return false;

    *tag = static_cast<variant_tag>(raw_tag);
    buffer_span = buffer_span.subspan(1); // Consume the tag.
    return true;
}

/**
 * Read a string without tag and update sv to point at the bytes.
 */
static bool read_untagged_string(zeek::byte_buffer_span& buffer_span, std::string_view* sv) {
    // read_varbyte() updates buffer_span
    size_t len = 0;
    if ( ! read_varbyte(buffer_span, &len) )
        return false;

    if ( buffer_span.size() < len )
        return false;

    *sv = {reinterpret_cast<const char*>(buffer_span.data()), len};
    buffer_span = buffer_span.subspan(len); // Consume the string.
    return true;
}

static bool read_string(zeek::byte_buffer_span& buffer_span, std::string_view* sv) {
    variant_tag tag;
    if ( ! read_tag(buffer_span, &tag) )
        return false;

    if ( tag != variant_tag::string )
        return false;

    return read_untagged_string(buffer_span, sv);
}

static bool read_vector_start(zeek::byte_buffer_span& buffer_span, size_t* len) {
    variant_tag tag;
    if ( ! read_tag(buffer_span, &tag) )
        return false;

    if ( tag != variant_tag::vector )
        return false;

    if ( ! read_varbyte(buffer_span, len) )
        return false;

    return true;
}

namespace {
zeek::ValPtr decode_inner(zeek::byte_buffer_span& buffer_span, const zeek::TypePtr& typ) {
    variant_tag tag;
    if ( ! read_tag(buffer_span, &tag) )
        return nullptr;

    auto zeek_tag = typ->Tag();

    switch ( tag ) {
        case variant_tag::none: {
            return nullptr;
        }
        case variant_tag::boolean: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_BOOL) )
                return nullptr;

            if ( buffer_span.empty() )
                return nullptr;

            auto val = buffer_span[0] != std::byte{0};
            buffer_span = buffer_span.subspan(1);
            return zeek::val_mgr->Bool(val);
        }
        case variant_tag::count: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_COUNT) )
                return nullptr;

            if ( buffer_span.size() < 8 )
                return nullptr;

            auto val = read_untagged_uint64(buffer_span);
            buffer_span = buffer_span.subspan(8);
            return zeek::val_mgr->Count(val);
        }
        case variant_tag::integer: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_INT) )
                return nullptr;

            if ( buffer_span.size() < 8 )
                return nullptr;

            auto val = static_cast<int64_t>(read_untagged_uint64(buffer_span));
            buffer_span = buffer_span.subspan(8);
            return zeek::val_mgr->Int(val);
        }
        case variant_tag::real: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_DOUBLE) )
                return nullptr;

            if ( buffer_span.size() < 8 )
                return nullptr;

            // XXX: See comment about std::bit_cast<> above.
            auto u64val = read_untagged_uint64(buffer_span);
            auto val = std::bit_cast<double>(u64val);
            buffer_span = buffer_span.subspan(8);
            return zeek::make_intrusive<zeek::DoubleVal>(val);
        }
        case variant_tag::string: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_STRING) )
                return nullptr;

            std::string_view sv;
            if ( ! read_untagged_string(buffer_span, &sv) )
                return nullptr;

            return zeek::make_intrusive<zeek::StringVal>(sv);
        }
        case variant_tag::address: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_ADDR) )
                return nullptr;

            // Need 16 bytes for addresses.
            if ( buffer_span.size() < 16 )
                return nullptr;

            // We used CopyIPv6() during serialization, so can read in as IPv6 address, too.
            // IPv4 addresses are mapped.
            const auto* addr = reinterpret_cast<const uint32_t*>(buffer_span.data());
            auto val = zeek::make_intrusive<zeek::AddrVal>(addr);
            buffer_span = buffer_span.subspan(16);
            return val;
        }
        case variant_tag::subnet: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_SUBNET) )
                return nullptr;

            // Need 16 bytes for addresses and 1 byte for the mask.
            if ( buffer_span.size() < 17 )
                return nullptr;

            const auto* addr = reinterpret_cast<const uint32_t*>(buffer_span.data());
            int width = static_cast<int>(buffer_span[16]);
            if ( width > 128 )
                return nullptr;

            auto val = zeek::make_intrusive<zeek::SubNetVal>(addr, width);
            buffer_span = buffer_span.subspan(17);
            return val;
        }
        case variant_tag::port: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_PORT) )
                return nullptr;

            // 3 bytes for ports.
            if ( buffer_span.size() < 3 )
                return nullptr;

            // memcpy() to avoid unaligned access.
            uint16_t u16val;
            memcpy(&u16val, buffer_span.data(), sizeof(uint16_t));
            auto proto = static_cast<TransportProto>(buffer_span[2]);

            auto val = zeek::val_mgr->Port(ntohs(u16val), proto);
            buffer_span = buffer_span.subspan(3);
            return val;
        }
        case variant_tag::timestamp: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_TIME) )
                return nullptr;

            if ( buffer_span.size() < 8 )
                return nullptr;

            uint64_t nanos = read_untagged_uint64(buffer_span);
            double ts = nanos / 1000000000.0;
            auto val = zeek::make_intrusive<zeek::TimeVal>(ts);
            buffer_span = buffer_span.subspan(8);
            return val;
        }
        case variant_tag::timespan: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_INTERVAL) )
                return nullptr;

            if ( buffer_span.size() < 8 )
                return nullptr;

            uint64_t nanos = read_untagged_uint64(buffer_span);
            double td = nanos / 1000000000.0;
            auto val = zeek::make_intrusive<zeek::IntervalVal>(td);
            buffer_span = buffer_span.subspan(8);
            return val;
        }
        case variant_tag::enum_value: {
            if ( (zeek_tag != TYPE_ANY && zeek_tag != TYPE_ENUM) )
                return nullptr;

            size_t len;
            if ( ! read_varbyte(buffer_span, &len) )
                return nullptr;

            if ( buffer_span.size() < len )
                return nullptr;

            // This is the name of a fully qualified enum value. Create a string_view
            // from it and try to look it up in the global scope.
            auto name = std::string_view{reinterpret_cast<const char*>(buffer_span.data()), len};

            buffer_span = buffer_span.subspan(len);

            auto id = zeek::id::find(name);
            if ( ! id || ! id->GetType() || id->GetType()->Tag() != TYPE_ENUM || ! id->GetVal() )
                return nullptr;

            return id->GetVal();
        }
        case variant_tag::set:
        case variant_tag::table: {
            if ( zeek_tag == TYPE_ANY ) {
                // This is a bit sad. Should we return some placeholder/stub?
                //
                // The format doesn't allow seeking, so we'd need to read through
                // all the elements and continue parsing at the right location.
                //
                // Not great either.
                return nullptr;
            }

            if ( zeek_tag != TYPE_TABLE )
                return nullptr;

            auto tt = cast_intrusive<zeek::TableType>(typ);
            const auto& indices = tt->GetIndices();
            size_t nindices = tt->GetIndexTypes().size();
            bool is_table = tt->IsTable();

            if ( tag == variant_tag::set && is_table )
                return nullptr;

            size_t entries;
            if ( ! read_varbyte(buffer_span, &entries) )
                return nullptr;

            auto tv = zeek::make_intrusive<zeek::TableVal>(tt);

            // Read key-value pairs.
            for ( size_t i = 0; i < entries; i++ ) {
                ListValPtr key = zeek::make_intrusive<zeek::ListVal>(indices);
                ValPtr val;

                // Composite index is always encoded as vector.
                if ( nindices > 1 ) {
                    variant_tag vec_tag;
                    if ( ! read_tag(buffer_span, &vec_tag) )
                        return nullptr;

                    if ( vec_tag != variant_tag::vector )
                        return nullptr;

                    size_t vec_len;
                    if ( ! read_varbyte(buffer_span, &vec_len) )
                        return nullptr;

                    if ( vec_len != nindices )
                        return nullptr;

                    for ( size_t j = 0; j < vec_len; j++ ) {
                        auto indexj = decode_inner(buffer_span, indices->GetTypes()[j]);
                        if ( ! indexj )
                            return nullptr;

                        key->Append(std::move(indexj));
                    }
                }
                else if ( nindices == 1 ) {
                    // Key isn't expected to be wrapped, so just delegate using the
                    // expected index type.
                    auto index = decode_inner(buffer_span, indices->GetTypes()[0]);
                    if ( ! index )
                        return nullptr;
                }

                // If this is a table, read the value, otherwise keep value as nil.
                if ( is_table )
                    val = decode_inner(buffer_span, tt->Yield());

                if ( ! tv->Assign(key, val) ) {
                    zeek::reporter->InternalWarning("BrokerBinV1: could not assign during deserialization");
                    return nullptr;
                }
            }

            return tv;
        }
        case variant_tag::vector: {
            // This is a vector, it could be a vector, record, pattern, opaque val, func, list, any, damnnn...
            size_t length;
            if ( ! read_varbyte(buffer_span, &length) )
                return nullptr;

            if ( zeek_tag == TYPE_ANY ) {
                // This is a bit sad. Should we return some placeholder/stub or just
                // freestyle it?
                //
                // The format doesn't allow seeking, so we'd need to read through
                // all the elements and continue parsing at the right location.
                //
                // Not great either.
                std::fprintf(stderr, "sad\n");
                return nullptr;
            }
            else if ( zeek_tag == TYPE_VECTOR ) {
                auto vt = cast_intrusive<zeek::VectorType>(typ);
                auto vv = zeek::make_intrusive<zeek::VectorVal>(vt);
                vv->Reserve(length);

                for ( size_t i = 0; i < length; i++ ) {
                    auto ve = decode_inner(buffer_span, vt->Yield());
                    if ( ! ve ) // This shouldn't fail or else it is an error.
                        return nullptr;

                    vv->Append(std::move(ve));
                }

                return vv;
            }
            else if ( zeek_tag == TYPE_LIST ) {
                // XXX: Don't think we need to support this, there's no list type and no list values
                zeek::reporter->Error("Unexpected TYPE_LIST type");
                return nullptr;
            }
            else if ( zeek_tag == TYPE_PATTERN ) {
                if ( length != 2 ) // Error
                    return nullptr;

                std::string_view exact_sv;
                if ( ! read_string(buffer_span, &exact_sv) )
                    return nullptr;

                std::string_view anywhere_sv;
                if ( ! read_string(buffer_span, &anywhere_sv) )
                    return nullptr;

                // Need null terminated strings for RE_Matcher, so make
                // the extra copy...
                std::string exact = std::string{exact_sv};
                std::string anywhere = std::string{anywhere_sv};

                auto re = std::make_unique<RE_Matcher>(exact.c_str(), anywhere.c_str());
                return zeek::make_intrusive<zeek::PatternVal>(re.release());
            }
            else if ( zeek_tag == TYPE_RECORD ) {
                auto rt = cast_intrusive<zeek::RecordType>(typ);
                auto rv = zeek::make_intrusive<zeek::RecordVal>(rt);
                if ( length != static_cast<size_t>(rt->NumFields()) )
                    return nullptr;

                for ( size_t i = 0; i < length; i++ ) {
                    const auto* fd = rt->FieldDecl(i);

                    // XXX PERF: We could check for simple types (count, int, ...) and
                    // just read them directly without going through decode and val
                    // construction, but for now this is doing a whole Val construction.
                    auto val = decode_inner(buffer_span, fd->type);

                    // Optional value?
                    if ( ! val ) {
                        // Leave unset if &optional
                        if ( fd->GetAttr(zeek::detail::ATTR_OPTIONAL) )
                            continue;

                        return nullptr; // error
                    }

                    rv->Assign(i, std::move(val));
                }

                return rv;
            }
            else if ( zeek_tag == TYPE_FUNC ) {
                if ( length < 0 ) // ERROR
                    return nullptr;

                // Func name is a tagged string.
                std::string_view func_name;
                if ( ! read_string(buffer_span, &func_name) )
                    return nullptr;

                // Lookup function.
                const auto& func_id = zeek::id::find(func_name);
                if ( ! func_id )
                    return nullptr;

                const auto& func_type = func_id->GetType();
                if ( ! func_type || func_type->Tag() != TYPE_FUNC )
                    return nullptr;

                const auto& func_val = func_id->GetVal();
                if ( ! func_val )
                    return nullptr;

                if ( length > 1 ) {
                    // We have a captures frame here.
                    std::fprintf(stderr, "TODO TODO captures frame todo!\n");
                    return nullptr;
                }
            }
            else if ( zeek_tag == TYPE_OPAQUE ) {
                if ( length != 2 ) // Error
                    return nullptr;

                std::string_view opaque_name_sv;
                if ( ! read_string(buffer_span, &opaque_name_sv) )
                    return nullptr;

                variant_tag vec_tag;
                if ( ! read_tag(buffer_span, &vec_tag) )
                    return nullptr;

                if ( vec_tag != variant_tag::vector )
                    return nullptr;

                size_t list_len;
                if ( ! read_varbyte(buffer_span, &list_len) )
                    return nullptr;


                // Should only expect atomic types for opaques.
                zeek::ListVal lv(base_type(TYPE_ANY));
                for ( size_t i = 0; i < list_len; i++ ) {
                    auto val = decode_inner(buffer_span, base_type(TYPE_ANY));
                    if ( ! val )
                        return nullptr;

                    lv.Append(val);
                }

                // XXX: string copy.
                auto opaque_name = std::string{opaque_name_sv};
                auto ov = OpaqueMgr::mgr()->Instantiate(opaque_name);
                if ( ! ov->FromListVal(lv) )
                    return nullptr;

                return ov;
            }
            else {
                zeek::reporter->Error("Unhandled vector. Have zeek_tag=%d (%s)", zeek_tag, obj_desc_short(typ).c_str());
                return nullptr;
            }
        }
    }

    return nullptr;
}
} // namespace

ValPtr decode(zeek::byte_buffer_span& buffer_span, const zeek::TypePtr& typ) {
    if ( buffer_span.empty() )
        return nullptr;

    auto result = decode_inner(buffer_span, typ);

    return result;
}

} // namespace format::broker::bin::v1

namespace detail {

bool SansBrokerBinV1_Serializer::SerializeEvent(byte_buffer& buf, const cluster::Event& event) {
    using zeek::cluster::format::broker::bin::v1::encode;
    using zeek::cluster::format::broker::bin::v1::encode_count;
    using zeek::cluster::format::broker::bin::v1::encode_string;
    using zeek::cluster::format::broker::bin::v1::encode_varbyte;
    using zeek::cluster::format::broker::bin::v1::encode_vector_start;

    auto out = std::back_insert_iterator(buf);

    // Write out protocol version an message type followed by a variable sized vector,
    // just the same thing that broker did, though protocol version and message type
    // could be irrelevant here because the cluster backend will use something like
    // a content-type, too.
    encode_vector_start(3, out);
    encode_count(uint64_t{1}, out); // protocol version
    encode_count(uint64_t{1}, out); // message type (event)

    // Vector is either 3 or 2 elements long, depending on whether
    // there is metadata attached or not.
    //
    // 0: Name
    // 1: Args as nested vector
    // 2: Optional metadata
    const auto* meta = event.Metadata();
    const size_t len = meta ? 3 : 2;

    encode_vector_start(len, out);

    // 0: Name
    encode_string(event.HandlerName(), out);


    // 1: Inline encode the args vector because cluster.Event holds std::vector<ValPtr>
    //    rather than a VectorVal, so cannot use encode for the vector and instead
    encode_vector_start(event.Args().size(), out);
    for ( const auto& a : event.Args() )
        if ( ! encode(*a, out) )
            return false;

    if ( meta ) {
        encode_vector_start(meta->size(), out);

        // Every element in the meta vector is another vector of length two (a pair)
        // of the metadata identifier and its value.
        for ( const auto& m : *meta ) {
            encode_vector_start(2, out);
            encode_count(m.Id(), out);
            if ( ! encode(*m.Val(), out) )
                return false;
        }
    }

    return true;
}

std::optional<cluster::Event> SansBrokerBinV1_Serializer::UnserializeEvent(byte_buffer_span buf) {
    using zeek::cluster::format::broker::bin::v1::decode_inner;
    using zeek::cluster::format::broker::bin::v1::read_string;
    using zeek::cluster::format::broker::bin::v1::read_tag;
    using zeek::cluster::format::broker::bin::v1::read_varbyte;
    using zeek::cluster::format::broker::bin::v1::read_vector_start;
    using zeek::cluster::format::broker::bin::v1::variant_tag;

    static const auto count_type = zeek::base_type(zeek::TYPE_COUNT);

    size_t len;
    if ( ! read_vector_start(buf, &len) )
        return std::nullopt;

    if ( len != 3 )
        return std::nullopt;

    // These should be fast given they go through ValMgr->Count()
    auto proto = decode_inner(buf, count_type);
    if ( ! proto || proto->AsCount() != 1 )
        return std::nullopt;

    auto message_type = decode_inner(buf, count_type);

    format::broker::bin::v1::variant_tag tag;

    if ( ! read_vector_start(buf, &len) )
        return std::nullopt;

    if ( len < 2 )
        return std::nullopt;

    std::string_view event_name;
    if ( ! read_string(buf, &event_name) || event_name.empty() )
        return std::nullopt;

    zeek::EventHandlerPtr handler = zeek::event_registry->Lookup(event_name);
    if ( handler == nullptr ) {
        zeek::reporter->Error("Failed to lookup handler for '%s' for remote event", std::string(event_name).c_str());
        return std::nullopt;
    }

    const auto& arg_types = handler->GetFunc()->GetType()->ParamList()->GetTypes();

    // Parse args. Args are essentially a vector of any but we have typing information
    // from the event signature and so can use decode_inner() below.
    size_t args_len;
    if ( ! read_vector_start(buf, &args_len) )
        return std::nullopt;

    if ( args_len != arg_types.size() ) {
        zeek::reporter->Error("Unserialize error '%s' arg_types.size()=%zu and args.size()=%zu",
                              std::string(event_name).c_str(), arg_types.size(), args_len);

        return std::nullopt;
    }

    zeek::Args args;
    args.reserve(args_len);
    for ( size_t i = 0; i < args_len; i++ ) {
        ValPtr arg = decode_inner(buf, arg_types[i]);
        if ( ! arg ) {
            zeek::reporter->Error("Unserialize error for event '%s': arg %zu type %s failed",
                                  std::string(event_name).c_str(), i, zeek::obj_desc_short(arg_types[i]).c_str());
            return std::nullopt;
        }

        args.push_back(std::move(arg));
    }

    zeek::detail::EventMetadataVectorPtr meta;

    if ( len >= 3 ) {
        // Metadata attached.
        size_t meta_len;
        if ( ! read_vector_start(buf, &meta_len) )
            return std::nullopt;

        meta = std::make_unique<zeek::detail::EventMetadataVector>();
        meta->reserve(meta_len);

        // Every meta element is a vector of length two.
        for ( size_t i = 0; i < meta_len; i++ ) {
            size_t mlen;
            if ( ! read_vector_start(buf, &mlen) )
                return std::nullopt;

            ValPtr meta_id = decode_inner(buf, count_type);
            if ( ! meta_id )
                return std::nullopt;

            const auto* desc = zeek::event_registry->LookupMetadata(meta_id->AsCount());
            if ( ! desc ) {
                std::fprintf(stderr, "unknown meta %zu\n", meta_id->AsCount());
                continue;
            }

            ValPtr meta_value = decode_inner(buf, desc->Type());
            if ( ! meta_value ) {
                std::fprintf(stderr, "failure to parse meta %zu\n", meta_id->AsCount());
                continue;
            }

            meta->emplace_back(meta_id->AsCount(), meta_value);
        }
    }

    return zeek::cluster::Event{handler, std::move(args), std::move(meta)};
}


} // namespace detail
} // namespace zeek::cluster

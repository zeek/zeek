// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/val-convert.h"

#include <algorithm>

#include "zeek/ZeekString.h"

namespace zeek::detail {

std::optional<double> convert_string_to_native_double(const StringVal* sv, std::string& err) {
    const char* s = sv->CheckString();
    char* end_s;
    double d = strtod(s, &end_s);
    if ( s[0] == '\0' || end_s[0] != '\0' ) {
        err = "bad conversion to double";
        return std::nullopt;
    }
    return d;
}

std::optional<zeek_int_t> convert_string_to_native_int(const StringVal* sv, std::string& err, int base) {
    const char* s = sv->CheckString();
    char* end_s;
    zeek_int_t i = strtoll(s, &end_s, base);
    if ( s[0] == '\0' || std::any_of(static_cast<const char*>(end_s), s + ::strlen(s),
                                     [](char c) { return ! (c == '\0' || ::isspace(c)); }) ) {
        err = "bad conversion to integer";
        return std::nullopt;
    }
    return i;
}

std::optional<zeek_uint_t> convert_string_to_native_count(const StringVal* sv, std::string& err, int base) {
    const char* s = sv->CheckString();
    char* end_s;
    uint64_t u = static_cast<uint64_t>(strtoull(s, &end_s, base));
    if ( s[0] == '\0' || std::any_of(static_cast<const char*>(end_s), s + ::strlen(s),
                                     [](char c) { return ! (c == '\0' || ::isspace(c)); }) ) {
        err = "bad conversion to count";
        return std::nullopt;
    }
    return u;
}

std::optional<zeek_uint_t> convert_int_to_native_count(zeek_int_t i, std::string& err) {
    if ( i < 0 ) {
        err = "bad conversion to count";
        return std::nullopt;
    }
    return i;
}

std::optional<zeek_uint_t> convert_double_to_native_count(double d, std::string& err) {
    if ( d < 0.0 ) {
        err = "bad conversion to count";
        return std::nullopt;
    }
    return rint(d);
}

ValPtr convert_string_to_double(const StringVal* sv, std::string& err) {
    auto d = convert_string_to_native_double(sv, err);
    return d ? make_intrusive<DoubleVal>(*d) : nullptr;
}

ValPtr convert_string_to_time(const StringVal* sv, std::string& err) {
    auto d = convert_string_to_double(sv, err);
    if ( d )
        return convert_double_to_time(d->AsDouble());
    err = "bad conversion to double/time";
    return nullptr;
}

ValPtr convert_string_to_interval(const StringVal* sv, std::string& err) {
    auto d = convert_string_to_double(sv, err);
    if ( d )
        return convert_double_to_interval(d->AsDouble());
    err = "bad conversion to double/interval";
    return nullptr;
}

ValPtr convert_string_to_int(const StringVal* sv, std::string& err, int base) {
    auto i = convert_string_to_native_int(sv, err, base);
    return i ? val_mgr->Int(*i) : nullptr;
}

ValPtr convert_string_to_count(const StringVal* sv, std::string& err, int base) {
    auto u = convert_string_to_native_count(sv, err, base);
    return u ? val_mgr->Count(*u) : nullptr;
}

ValPtr convert_string_to_addr(const StringVal* sv, std::string& err) {
    char* s = sv->AsString()->Render();
    in6_addr tmp;
    ValPtr ret;
    if ( IPAddr::ConvertString(s, &tmp) )
        ret = make_intrusive<AddrVal>(IPAddr(tmp));
    else
        err = "failed converting string to IP address";
    delete[] s;
    return ret;
}

ValPtr convert_string_to_subnet(const StringVal* sv) {
    char* s = sv->AsString()->Render();
    IPPrefix tmp;
    ValPtr ret;
    if ( IPPrefix::ConvertString(s, &tmp) )
        ret = make_intrusive<SubNetVal>(tmp);
    delete[] s;
    return ret;
}

ValPtr convert_string_to_port(const StringVal* sv) {
    const char* s = sv->CheckString();
    int port = 0;
    if ( sv->Len() > 0 && sv->Len() < 10 ) {
        char* slash;
        errno = 0;
        port = strtol(s, &slash, 10);
        if ( ! errno && *slash ) {
            ++slash;
            if ( util::streq(slash, "tcp") )
                return val_mgr->Port(port, TRANSPORT_TCP);
            else if ( util::streq(slash, "udp") )
                return val_mgr->Port(port, TRANSPORT_UDP);
            else if ( util::streq(slash, "icmp") )
                return val_mgr->Port(port, TRANSPORT_ICMP);
        }
    }
    return nullptr;
}

ValPtr convert_int_to_count(zeek_int_t i, std::string& err) {
    auto c = convert_int_to_native_count(i, err);
    return c ? val_mgr->Count(*c) : nullptr;
}

ValPtr convert_int_to_double(zeek_int_t i) { return make_intrusive<DoubleVal>(i); }

ValPtr convert_double_to_int(double d) { return val_mgr->Int(static_cast<zeek_int_t>(rint(d))); }

ValPtr convert_double_to_count(double d, std::string& err) {
    auto c = convert_double_to_native_count(d, err);
    return c ? val_mgr->Count(*c) : nullptr;
}

ValPtr convert_double_to_time(double d) { return make_intrusive<TimeVal>(d); }

ValPtr convert_double_to_interval(double d) { return make_intrusive<IntervalVal>(d); }

ValPtr convert_count_to_double(zeek_uint_t c) { return make_intrusive<DoubleVal>(c); }

ValPtr convert_count_to_v4_addr(zeek_uint_t c, std::string& err) {
    if ( c > 4294967295LU ) {
        err = "conversion of non-IPv4 count to addr";
        return nullptr;
    }
    return make_intrusive<AddrVal>(htonl(static_cast<uint32_t>(c)));
}

ValPtr convert_enum_to_count(zeek_uint_t e) { return val_mgr->Count(e); }

ValPtr convert_enum_to_int(zeek_int_t e) { return val_mgr->Int(e); }

ValPtr convert_interval_to_double(double i) { return make_intrusive<DoubleVal>(i); }

ValPtr convert_time_to_double(double t) { return make_intrusive<DoubleVal>(t); }

ValPtr convert_addr_to_subnet(const IPAddr& addr) {
    int width = (addr.GetFamily() == IPv4 ? 32 : 128);
    return make_intrusive<SubNetVal>(addr, width);
}

ValPtr convert_addr_to_counts(const IPAddr& addr) {
    auto rval = make_intrusive<VectorVal>(id::index_vec);
    const uint32_t* bytes;
    int len = addr.GetBytes(&bytes);
    for ( int i = 0; i < len; ++i )
        rval->Assign(i, val_mgr->Count(ntohl(bytes[i])));
    return rval;
}

ValPtr convert_subnet_to_addr(const IPPrefix& sn) { return make_intrusive<AddrVal>(sn.Prefix()); }

ValPtr convert_subnet_to_count(const IPPrefix& sn) { return val_mgr->Count(sn.Length()); }

ValPtr convert_port_to_count(uint32_t port) { return val_mgr->Count(port); }

ValPtr convert_counts_to_addr(const VectorVal* vv, std::string& err) {
    if ( vv->Size() == 1 ) {
        return make_intrusive<AddrVal>(htonl(vv->CountAt(0)));
    }
    else if ( vv->Size() == 4 ) {
        uint32_t bytes[4];
        for ( int i = 0; i < 4; ++i )
            bytes[i] = htonl(vv->CountAt(i));
        return make_intrusive<AddrVal>(bytes);
    }
    err = "invalid vector size";
    return nullptr;
}

} // namespace zeek::detail

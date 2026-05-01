// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/IPAddr.h"
#include "zeek/Val.h"

namespace zeek {

// Conversion helper functions used by both BiFs and cast_value_to_type().
// Functions with an err parameter will set it to a non-empty error message
// on failure.

extern ValPtr convert_string_to_double(const StringVal* sv, std::string& err);
extern ValPtr convert_string_to_int(const StringVal* sv, std::string& err, int base = 10);
extern ValPtr convert_string_to_count(const StringVal* sv, std::string& err, int base = 10);
extern ValPtr convert_string_to_addr(const StringVal* sv, std::string& err);
extern ValPtr convert_string_to_subnet(const StringVal* sv);
extern ValPtr convert_string_to_port(const StringVal* sv);

extern ValPtr convert_int_to_count(zeek_int_t i, std::string& err);
extern ValPtr convert_int_to_double(zeek_int_t i);

extern ValPtr convert_double_to_int(double d);
extern ValPtr convert_double_to_count(double d, std::string& err);
extern ValPtr convert_double_to_time(double d);
extern ValPtr convert_double_to_interval(double d);

extern ValPtr convert_count_to_double(zeek_uint_t c);
extern ValPtr convert_count_to_v4_addr(zeek_uint_t c, std::string& err);

extern ValPtr convert_enum_to_int(zeek_int_t e);
extern ValPtr convert_enum_to_count(zeek_uint_t e);

extern ValPtr convert_interval_to_double(double i);
extern ValPtr convert_time_to_double(double t);

extern ValPtr convert_addr_to_subnet(const IPAddr& addr);
extern ValPtr convert_addr_to_counts(const IPAddr& addr);

extern ValPtr convert_subnet_to_addr(const IPPrefix& sn);
extern ValPtr convert_subnet_to_count(const IPPrefix& sn);

extern ValPtr convert_port_to_count(uint32_t port);

extern ValPtr convert_counts_to_addr(const VectorVal* vv, std::string& err);

} // namespace zeek

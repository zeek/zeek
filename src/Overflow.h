// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Type.h"

namespace zeek::detail {

inline bool double_to_count_would_overflow(double v)
	{
	return v < 0.0 || v > static_cast<double>(UINT64_MAX);
	}

inline bool int_to_count_would_overflow(bro_int_t v)
	{
	return v < 0.0;
	}

inline bool double_to_int_would_overflow(double v)
	{
	return v < static_cast<double>(INT64_MIN) ||
	       v > static_cast<double>(INT64_MAX);
	}

inline bool count_to_int_would_overflow(bro_uint_t v)
	{
	return v > INT64_MAX;
	}

extern bool would_overflow(const zeek::Type* from_type,
                           const zeek::Type* to_type, const Val* val);

}

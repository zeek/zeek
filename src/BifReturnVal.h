// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"
#include "zeek/IntrusivePtr.h"

namespace zeek {

class Val;
using ValPtr = IntrusivePtr<Val>;

namespace detail {

/**
 * A simple wrapper class to use for the return value of BIFs so that
 * they may return either a Val* or IntrusivePtr<Val> (the former could
 * potentially be deprecated).
 */
class BifReturnVal {
public:

	template <typename T>
	BifReturnVal(IntrusivePtr<T> v) noexcept
		: rval(AdoptRef{}, v.release())
		{ }

	BifReturnVal(std::nullptr_t) noexcept;

	ValPtr rval;
};

} // namespace detail
} // namespace zeek

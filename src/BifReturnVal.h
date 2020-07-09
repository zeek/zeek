// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"
#include "IntrusivePtr.h"

ZEEK_FORWARD_DECLARE_NAMESPACED(Val, zeek);
namespace zeek {
using ValPtr = zeek::IntrusivePtr<zeek::Val>;
}

/**
 * A simple wrapper class to use for the return value of BIFs so that
 * they may return either a Val* or IntrusivePtr<Val> (the former could
 * potentially be deprecated).
 */
class BifReturnVal {
public:

	template <typename T>
	BifReturnVal(zeek::IntrusivePtr<T> v) noexcept
		: rval(zeek::AdoptRef{}, v.release())
		{ }

	BifReturnVal(std::nullptr_t) noexcept;

	[[deprecated("Remove in v4.1.  Return an IntrusivePtr instead.")]]
	BifReturnVal(zeek::Val* v) noexcept;

	zeek::ValPtr rval;
};

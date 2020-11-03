// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/BifReturnVal.h"
#include "zeek/Val.h"

namespace zeek::detail {

BifReturnVal::BifReturnVal(std::nullptr_t) noexcept
	{}

BifReturnVal::BifReturnVal(Val* v) noexcept
	: rval(AdoptRef{}, v)
	{}

} // namespace zeek::detail

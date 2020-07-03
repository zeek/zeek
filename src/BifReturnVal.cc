// See the file "COPYING" in the main distribution directory for copyright.

#include "BifReturnVal.h"
#include "Val.h"

BifReturnVal::BifReturnVal(std::nullptr_t) noexcept
	{}

BifReturnVal::BifReturnVal(zeek::Val* v) noexcept
	: rval(zeek::AdoptRef{}, v)
	{}

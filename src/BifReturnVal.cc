// See the file "COPYING" in the main distribution directory for copyright.

#include "BifReturnVal.h"
#include "Val.h"

BifReturnVal::BifReturnVal(std::nullptr_t) noexcept
	{}

BifReturnVal::BifReturnVal(Val* v) noexcept
	: rval(AdoptRef{}, v)
	{}

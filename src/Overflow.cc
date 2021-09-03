// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Overflow.h"
#include "zeek/Val.h"

namespace zeek::detail {

bool would_overflow(const zeek::Type* from_type, const zeek::Type* to_type,
                    const Val* val)
	{
	if ( ! to_type || ! from_type )
		return true;

	if ( same_type(to_type, from_type) )
		return false;

	if ( to_type->InternalType() == TYPE_INTERNAL_DOUBLE )
		return false;

	if ( to_type->InternalType() == TYPE_INTERNAL_UNSIGNED )
		{
		if ( from_type->InternalType() == TYPE_INTERNAL_DOUBLE )
			return double_to_count_would_overflow(val->InternalDouble());
		if ( from_type->InternalType() == TYPE_INTERNAL_INT )
			return int_to_count_would_overflow(val->InternalInt());
		}

	if ( to_type->InternalType() == TYPE_INTERNAL_INT )
		{
		if ( from_type->InternalType() == TYPE_INTERNAL_DOUBLE )
			return double_to_int_would_overflow(val->InternalDouble());
		if ( from_type->InternalType() == TYPE_INTERNAL_UNSIGNED )
			return count_to_int_would_overflow(val->InternalUnsigned());
		}

	return false;
	}

}

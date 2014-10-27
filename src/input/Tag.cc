// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

input::Tag input::Tag::Error;

input::Tag::Tag(type_t type, subtype_t subtype)
	: ::Tag(input_mgr->GetTagEnumType(), type, subtype)
	{
	}

input::Tag& input::Tag::operator=(const input::Tag& other)
	{
	::Tag::operator=(other);
	return *this;
	}

EnumVal* input::Tag::AsEnumVal() const
	{
	return ::Tag::AsEnumVal(input_mgr->GetTagEnumType());
	}

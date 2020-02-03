// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

const logging::Tag logging::Tag::Error;

logging::Tag::Tag(type_t type, subtype_t subtype)
	: ::Tag(log_mgr->GetTagEnumType(), type, subtype)
	{
	}

logging::Tag& logging::Tag::operator=(const logging::Tag& other)
	{
	::Tag::operator=(other);
	return *this;
	}

logging::Tag& logging::Tag::operator=(const logging::Tag&& other) noexcept
	{
	::Tag::operator=(other);
	return *this;
	}

EnumVal* logging::Tag::AsEnumVal() const
	{
	return ::Tag::AsEnumVal(log_mgr->GetTagEnumType());
	}

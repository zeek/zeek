// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

analyzer::Tag analyzer::Tag::Error;

analyzer::Tag::Tag(type_t type, subtype_t subtype)
	: ::Tag(analyzer_mgr->GetTagEnumType(), type, subtype)
	{
	}

analyzer::Tag& analyzer::Tag::operator=(const analyzer::Tag& other)
	{
	::Tag::operator=(other);
	return *this;
	}

EnumVal* analyzer::Tag::AsEnumVal() const
	{
	return ::Tag::AsEnumVal(analyzer_mgr->GetTagEnumType());
	}

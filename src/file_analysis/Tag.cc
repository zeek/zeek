// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

using namespace file_analysis;

file_analysis::Tag file_analysis::Tag::Error;

file_analysis::Tag::Tag(type_t type, subtype_t subtype)
	: ::Tag(file_mgr->GetTagEnumType(), type, subtype)
	{
	}

file_analysis::Tag& file_analysis::Tag::operator=(const file_analysis::Tag& other)
	{
	::Tag::operator=(other);
	return *this;
	}

EnumVal* file_analysis::Tag::AsEnumVal() const
	{
	return ::Tag::AsEnumVal(file_mgr->GetTagEnumType());
	}

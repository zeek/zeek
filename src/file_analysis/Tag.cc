// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

using namespace file_analysis;

const file_analysis::Tag file_analysis::Tag::Error;

file_analysis::Tag::Tag(type_t type, subtype_t subtype)
	: ::Tag(file_mgr->GetTagType(), type, subtype)
	{
	}

file_analysis::Tag& file_analysis::Tag::operator=(const file_analysis::Tag& other)
	{
	::Tag::operator=(other);
	return *this;
	}

const zeek::IntrusivePtr<EnumVal>& file_analysis::Tag::AsVal() const
	{
	return ::Tag::AsVal(file_mgr->GetTagType());
	}

EnumVal* file_analysis::Tag::AsEnumVal() const
	{
	return AsVal().get();
	}

file_analysis::Tag::Tag(zeek::IntrusivePtr<EnumVal> val)
	: ::Tag(std::move(val))
	{ }

file_analysis::Tag::Tag(EnumVal* val)
	: ::Tag({zeek::NewRef{}, val})
	{ }

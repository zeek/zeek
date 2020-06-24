// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

const analyzer::Tag analyzer::Tag::Error;

analyzer::Tag::Tag(type_t type, subtype_t subtype)
	: ::Tag(analyzer_mgr->GetTagType(), type, subtype)
	{
	}

analyzer::Tag& analyzer::Tag::operator=(const analyzer::Tag& other)
	{
	::Tag::operator=(other);
	return *this;
	}

const zeek::EnumValPtr& analyzer::Tag::AsVal() const
	{
	return ::Tag::AsVal(analyzer_mgr->GetTagType());
	}

zeek::EnumVal* analyzer::Tag::AsEnumVal() const
	{
	return AsVal().get();
	}

analyzer::Tag::Tag(zeek::EnumValPtr val)
	: ::Tag(std::move(val))
	{ }

analyzer::Tag::Tag(zeek::EnumVal* val)
	: ::Tag({zeek::NewRef{}, val})
	{ }

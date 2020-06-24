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

const EnumValPtr& analyzer::Tag::AsVal() const
	{
	return ::Tag::AsVal(analyzer_mgr->GetTagType());
	}

EnumVal* analyzer::Tag::AsEnumVal() const
	{
	return AsVal().get();
	}

analyzer::Tag::Tag(EnumValPtr val)
	: ::Tag(std::move(val))
	{ }

analyzer::Tag::Tag(EnumVal* val)
	: ::Tag({zeek::NewRef{}, val})
	{ }

// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

const zeek::analyzer::Tag zeek::analyzer::Tag::Error;

zeek::analyzer::Tag::Tag(type_t type, subtype_t subtype)
	: zeek::Tag(zeek::analyzer_mgr->GetTagType(), type, subtype)
	{
	}

zeek::analyzer::Tag& zeek::analyzer::Tag::operator=(const zeek::analyzer::Tag& other)
	{
	zeek::Tag::operator=(other);
	return *this;
	}

const zeek::EnumValPtr& zeek::analyzer::Tag::AsVal() const
	{
	return zeek::Tag::AsVal(zeek::analyzer_mgr->GetTagType());
	}

zeek::EnumVal* zeek::analyzer::Tag::AsEnumVal() const
	{
	return AsVal().get();
	}

zeek::analyzer::Tag::Tag(zeek::EnumValPtr val)
	: zeek::Tag(std::move(val))
	{ }

zeek::analyzer::Tag::Tag(zeek::EnumVal* val)
	: zeek::Tag({zeek::NewRef{}, val})
	{ }

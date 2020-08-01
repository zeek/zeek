// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

const input::Tag input::Tag::Error;

input::Tag::Tag(type_t type, subtype_t subtype)
	: zeek::Tag(input_mgr->GetTagType(), type, subtype)
	{
	}

input::Tag& input::Tag::operator=(const input::Tag& other)
	{
	zeek::Tag::operator=(other);
	return *this;
	}

const zeek::EnumValPtr& input::Tag::AsVal() const
	{
	return zeek::Tag::AsVal(input_mgr->GetTagType());
	}

zeek::EnumVal* input::Tag::AsEnumVal() const
	{
	return AsVal().get();
	}

input::Tag::Tag(zeek::EnumValPtr val)
	: zeek::Tag(std::move(val))
	{ }

input::Tag::Tag(zeek::EnumVal* val)
	: zeek::Tag({zeek::NewRef{}, val})
	{ }

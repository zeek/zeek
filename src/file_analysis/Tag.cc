// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

namespace zeek::file_analysis {

const Tag Tag::Error;

Tag::Tag(type_t type, subtype_t subtype)
	: ::Tag(file_mgr->GetTagType(), type, subtype)
	{
	}

Tag& Tag::operator=(const Tag& other)
	{
	zeek::Tag::operator=(other);
	return *this;
	}

const zeek::EnumValPtr& Tag::AsVal() const
	{
	return zeek::Tag::AsVal(file_mgr->GetTagType());
	}

zeek::EnumVal* Tag::AsEnumVal() const
	{
	return AsVal().get();
	}

Tag::Tag(zeek::EnumValPtr val)
	: zeek::Tag(std::move(val))
	{ }

Tag::Tag(zeek::EnumVal* val)
	: zeek::Tag({zeek::NewRef{}, val})
	{ }

} // namespace zeek::file_analysis

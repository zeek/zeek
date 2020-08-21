// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

namespace zeek::logging {

const Tag Tag::Error;

Tag::Tag(type_t type, subtype_t subtype)
	: zeek::Tag(log_mgr->GetTagType(), type, subtype)
	{
	}

Tag& Tag::operator=(const Tag& other)
	{
	zeek::Tag::operator=(other);
	return *this;
	}

Tag& Tag::operator=(const Tag&& other) noexcept
	{
	zeek::Tag::operator=(other);
	return *this;
	}

const zeek::EnumValPtr& Tag::AsVal() const
	{
	return zeek::Tag::AsVal(log_mgr->GetTagType());
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

} // namespace zeek::logging

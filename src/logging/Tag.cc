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

const EnumValPtr& Tag::AsVal() const
	{
	return zeek::Tag::AsVal(log_mgr->GetTagType());
	}

EnumVal* Tag::AsEnumVal() const
	{
	return AsVal().get();
	}

Tag::Tag(EnumValPtr val)
	: zeek::Tag(std::move(val))
	{ }

Tag::Tag(EnumVal* val)
	: zeek::Tag({NewRef{}, val})
	{ }

} // namespace zeek::logging

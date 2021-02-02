// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/logging/Tag.h"
#include "zeek/logging/Manager.h"

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

Tag::Tag(EnumValPtr val)
	: zeek::Tag(std::move(val))
	{ }

} // namespace zeek::logging

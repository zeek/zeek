// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/input/Tag.h"
#include "zeek/input/Manager.h"

namespace zeek::input {

const Tag Tag::Error;

Tag::Tag(type_t type, subtype_t subtype)
	: zeek::Tag(input_mgr->GetTagType(), type, subtype)
	{
	}

Tag& Tag::operator=(const Tag& other)
	{
	zeek::Tag::operator=(other);
	return *this;
	}

const EnumValPtr& Tag::AsVal() const
	{
	return zeek::Tag::AsVal(input_mgr->GetTagType());
	}

Tag::Tag(EnumValPtr val)
	: zeek::Tag(std::move(val))
	{ }

} // namespace zeek::input

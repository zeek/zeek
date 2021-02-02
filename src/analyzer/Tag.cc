// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/Tag.h"
#include "zeek/analyzer/Manager.h"

namespace zeek::analyzer {

const Tag Tag::Error;

Tag::Tag(type_t type, subtype_t subtype)
	: zeek::Tag(analyzer_mgr->GetTagType(), type, subtype)
	{
	}

Tag& Tag::operator=(const Tag& other)
	{
	zeek::Tag::operator=(other);
	return *this;
	}

const EnumValPtr& Tag::AsVal() const
	{
	return zeek::Tag::AsVal(analyzer_mgr->GetTagType());
	}

Tag::Tag(EnumValPtr val)
	: zeek::Tag(std::move(val))
	{ }

} // namespace zeek::analyzer

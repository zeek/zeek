// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/Tag.h"
#include "zeek/file_analysis/Manager.h"

namespace zeek::file_analysis {

const Tag Tag::Error;

Tag::Tag(type_t type, subtype_t subtype)
	: zeek::Tag(file_mgr->GetTagType(), type, subtype)
	{
	}

Tag& Tag::operator=(const Tag& other)
	{
	zeek::Tag::operator=(other);
	return *this;
	}

const EnumValPtr& Tag::AsVal() const
	{
	return zeek::Tag::AsVal(file_mgr->GetTagType());
	}

Tag::Tag(EnumValPtr val)
	: zeek::Tag(std::move(val))
	{ }

} // namespace zeek::file_analysis

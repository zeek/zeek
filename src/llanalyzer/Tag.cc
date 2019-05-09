// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

namespace zeek::llanalyzer {

Tag Tag::Error;

Tag::Tag(type_t type, subtype_t subtype)
	: zeek::Tag(llanalyzer_mgr->GetTagType(), type, subtype)
	{
	}

Tag& Tag::operator=(const Tag& other)
	{
	zeek::Tag::operator=(other);
	return *this;
	}

const IntrusivePtr<EnumVal>& Tag::AsVal() const
	{
	return zeek::Tag::AsVal(llanalyzer_mgr->GetTagType());
	}

EnumVal* Tag::AsEnumVal() const
	{
	return AsVal().get();
	}

Tag::Tag(IntrusivePtr<EnumVal> val)
	: zeek::Tag(std::move(val))
	{
	}

Tag::Tag(EnumVal* val)
	: zeek::Tag({NewRef {}, val})
	{
	}

}

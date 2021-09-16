// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/Tag.h"

#include "zeek/packet_analysis/Manager.h"

namespace zeek::packet_analysis
	{

Tag Tag::Error;

Tag::Tag(type_t type, subtype_t subtype) : zeek::Tag(packet_mgr->GetTagType(), type, subtype) { }

Tag& Tag::operator=(const Tag& other)
	{
	zeek::Tag::operator=(other);
	return *this;
	}

const IntrusivePtr<EnumVal>& Tag::AsVal() const
	{
	return zeek::Tag::AsVal(packet_mgr->GetTagType());
	}

Tag::Tag(IntrusivePtr<EnumVal> val) : zeek::Tag(std::move(val)) { }

	}

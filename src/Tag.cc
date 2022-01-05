// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Tag.h"

#include "zeek/Val.h"

namespace zeek
	{

const Tag Tag::Error;

Tag::Tag(type_t arg_type, subtype_t arg_subtype) : Tag(nullptr, arg_type, arg_subtype) { }

Tag::Tag(const EnumTypePtr& etype, type_t arg_type, subtype_t arg_subtype)
	: type(arg_type), subtype(arg_subtype), etype(etype)
	{
	assert(arg_type > 0);

	int64_t i = (int64_t)(type) | ((int64_t)subtype << 31);

	if ( etype )
		val = etype->GetEnumVal(i);
	}

Tag::Tag(EnumValPtr arg_val)
	{
	assert(arg_val);

	val = std::move(arg_val);

	int64_t i = val->InternalInt();
	type = i & 0xffffffff;
	subtype = (i >> 31) & 0xffffffff;
	}

Tag::Tag(const Tag& other)
	{
	type = other.type;
	subtype = other.subtype;
	val = other.val;
	etype = other.etype;
	}

Tag::Tag()
	{
	val = nullptr;
	etype = nullptr;
	}

Tag::~Tag() = default;

Tag& Tag::operator=(const Tag& other)
	{
	if ( this != &other )
		{
		type = other.type;
		subtype = other.subtype;
		val = other.val;
		etype = other.etype;
		}

	return *this;
	}

Tag& Tag::operator=(Tag&& other) noexcept
	{
	if ( this != &other )
		{
		type = other.type;
		subtype = other.subtype;
		val = std::move(other.val);
		etype = std::move(other.etype);
		}

	return *this;
	}

std::string Tag::AsString() const
	{
	return util::fmt("%" PRIu32 "/%" PRIu32, type, subtype);
	}

	} // namespace zeek

// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Val.h"
#include "IntrusivePtr.h"

Tag::Tag(const IntrusivePtr<EnumType>& etype, type_t arg_type, subtype_t arg_subtype)
	{
	assert(arg_type > 0);

	type = arg_type;
	subtype = arg_subtype;
	int64_t i = (int64_t)(type) | ((int64_t)subtype << 31);
	val = etype->GetVal(i);
	}

Tag::Tag(EnumType* etype, type_t arg_type, subtype_t arg_subtype)
	: Tag({NewRef{}, etype}, arg_type, arg_subtype)
	{ }

Tag::Tag(IntrusivePtr<EnumVal> arg_val)
	{
	assert(arg_val);

	val = std::move(arg_val);

	int64_t i = val->InternalInt();
	type = i & 0xffffffff;
	subtype = (i >> 31) & 0xffffffff;
	}

Tag::Tag(EnumVal* arg_val)
	: Tag({NewRef{}, arg_val})
	{ }

Tag::Tag(const Tag& other)
	{
	type = other.type;
	subtype = other.subtype;
	val = other.val;
	}

Tag::Tag()
	{
	type = 0;
	subtype = 0;
	val = nullptr;
	}

Tag::~Tag() = default;

Tag& Tag::operator=(const Tag& other)
	{
	if ( this != &other )
		{
		type = other.type;
		subtype = other.subtype;
		val = other.val;
		}

	return *this;
	}

Tag& Tag::operator=(const Tag&& other) noexcept
	{
	if ( this != &other )
		{
		type = other.type;
		subtype = other.subtype;
		val = std::move(other.val);
		}

	return *this;
	}

const IntrusivePtr<EnumVal>& Tag::AsVal(const IntrusivePtr<EnumType>& etype) const
	{
	if ( ! val )
		{
		assert(type == 0 && subtype == 0);
		val = etype->GetVal(0);
		}

	return val;
	}

EnumVal* Tag::AsEnumVal(EnumType* etype) const
	{
	return AsVal({NewRef{}, etype}).get();
	}

std::string Tag::AsString() const
	{
	return fmt("%" PRIu32 "/%" PRIu32, type, subtype);
	}

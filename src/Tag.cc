// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Val.h"

Tag::Tag(EnumType* etype, type_t arg_type, subtype_t arg_subtype)
	{
	assert(arg_type > 0);

	type = arg_type;
	subtype = arg_subtype;
	int64_t i = (int64_t)(type) | ((int64_t)subtype << 31);
	Ref(etype);
	val = etype->GetVal(i);
	}

Tag::Tag(EnumVal* arg_val)
	{
	assert(arg_val);

	val = arg_val;
	Ref(val);

	int64_t i = val->InternalInt();
	type = i & 0xffffffff;
	subtype = (i >> 31) & 0xffffffff;
	}

Tag::Tag(const Tag& other)
	{
	type = other.type;
	subtype = other.subtype;
	val = other.val;

	if ( val )
		Ref(val);
	}

Tag::Tag()
	{
	type = 0;
	subtype = 0;
	val = 0;
	}

Tag::~Tag()
	{
	Unref(val);
	val = 0;
	}

Tag& Tag::operator=(const Tag& other)
	{
	if ( this != &other )
		{
		type = other.type;
		subtype = other.subtype;
		Unref(val);
		val = other.val;

		if ( val )
			Ref(val);
		}

	return *this;
	}

Tag& Tag::operator=(const Tag&& other) noexcept
	{
	if ( this != &other )
		{
		type = other.type;
		subtype = other.subtype;
		Unref(val);
		val = other.val;
		other.val = nullptr;
		}

	return *this;
	}

EnumVal* Tag::AsEnumVal(EnumType* etype) const
	{
	if ( ! val )
		{
		assert(type == 0 && subtype == 0);
		Ref(etype);
		val = etype->GetVal(0);
		}

	return val;
	}

std::string Tag::AsString() const
	{
	return fmt("%" PRIu32 "/%" PRIu32, type, subtype);
	}

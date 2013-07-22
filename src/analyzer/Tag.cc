// See the file "COPYING" in the main distribution directory for copyright.

#include "Tag.h"
#include "Manager.h"

#include "../NetVar.h"

using namespace analyzer;

Tag Tag::Error;

Tag::Tag(type_t arg_type, subtype_t arg_subtype)
	{
	assert(arg_type > 0);

	type = arg_type;
	subtype = arg_subtype;
	int64_t i = (int64)(type) | ((int64)subtype << 31);

	EnumType* etype = analyzer_mgr->GetTagEnumType();
	Ref(etype);
	val = new EnumVal(i, etype);
	}

Tag::Tag(EnumVal* arg_val)
	{
	assert(arg_val);

	val = arg_val;
	Ref(val);

	int64 i = val->InternalInt();
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
		val = other.val;

		if ( val )
			Ref(val);
		}

	return *this;
	}

EnumVal* Tag::AsEnumVal() const
	{
	if ( ! val )
		{
		assert(analyzer_mgr);
		assert(type == 0 && subtype == 0);
		EnumType* etype = analyzer_mgr->GetTagEnumType();
		Ref(etype);
		val = new EnumVal(0, etype);
		}

	return val;
	}

std::string Tag::AsString() const
	{
	return fmt("%" PRIu32 "/%" PRIu32, type, subtype);
	}

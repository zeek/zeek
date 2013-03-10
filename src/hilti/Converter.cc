
#include "../Obj.h"
#include "../Type.h"
#undef List

#include <hilti/builder/builder.h>
#include <binpac/type.h>

#include "Converter.h"

using namespace bro::hilti;

TypeConverter::TypeConverter()
	{
	}

BroType* TypeConverter::Convert(std::shared_ptr<::hilti::Type> type, std::shared_ptr<::binpac::Type> btype)
	{
	setArg1(btype);
	BroType* rtype;
	processOne(type, &rtype);
	return rtype;
	}

ValueConverter::ValueConverter(shared_ptr<::hilti::builder::ModuleBuilder> arg_mbuilder)
	{
	mbuilder = arg_mbuilder;
	}

bool ValueConverter::Convert(shared_ptr<::hilti::Expression> value, shared_ptr<::hilti::Expression> dst, std::shared_ptr<::binpac::Type> btype)
	{
	setArg1(value);
	setArg2(dst);
	_arg3 = btype;
	bool set = false;
	bool success = processOne(value->type(), &set);
	assert(set);
	_arg3 = nullptr;
	return success;
	}

shared_ptr<::hilti::builder::BlockBuilder> ValueConverter::Builder() const
	{
	return mbuilder->builder();
	}

shared_ptr<::binpac::Type> ValueConverter::arg3() const
	{
	return _arg3;
	}

void TypeConverter::visit(::hilti::type::Reference* b)
	{
	BroType* rtype;
	processOne(b->argType(), &rtype);
	setResult(rtype);
	}

void ValueConverter::visit(::hilti::type::Reference* b)
	{
	bool set = false;
	bool success = processOne(b->argType(), &set);
	assert(set);
	setResult(true);
	}

void TypeConverter::visit(::hilti::type::Integer* i)
	{
	auto itype = ast::checkedCast<binpac::type::Integer>(arg1());

	auto result = itype->signed_() ? base_type(TYPE_INT) : base_type(TYPE_COUNT);
	setResult(result);
	}

void TypeConverter::visit(::hilti::type::Bytes* b)
	{
	auto btype = arg1();

	auto result = base_type(TYPE_STRING);
	setResult(result);
	}

void ValueConverter::visit(::hilti::type::Integer* i)
	{
	auto val = arg1();
	auto dst = arg2();
	auto itype = ast::checkedCast<binpac::type::Integer>(arg3());

	const char* func = "";
	shared_ptr<::hilti::Instruction> ext = 0;

	if ( itype->signed_() )
		{
		func = "LibBro::h2b_integer_signed";
		ext = ::hilti::instruction::integer::SExt;
		}

	else
		{
		func = "LibBro::h2b_integer_unsigned";
		ext = ::hilti::instruction::integer::ZExt;
		}

	if ( itype->width() != 64 )
		{
		auto tmp = Builder()->addTmp("ext", ::hilti::builder::integer::type(64));
		Builder()->addInstruction(tmp, ext, val);
		val = tmp;
		}

	auto args = ::hilti::builder::tuple::create( { val } );
	Builder()->addInstruction(dst, ::hilti::instruction::flow::CallResult,
				  ::hilti::builder::id::create(func), args);
	setResult(true);
	}

void ValueConverter::visit(::hilti::type::Bytes* b)
	{
	auto val = arg1();
	auto dst = arg2();
	auto btype = arg3();

	auto args = ::hilti::builder::tuple::create( { val } );
	Builder()->addInstruction(dst, ::hilti::instruction::flow::CallResult,
				  ::hilti::builder::id::create("LibBro::h2b_bytes"), args);
	setResult(true);
	}



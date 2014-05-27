// See the file "COPYING" in the main distribution directory for copyright.

#include "CounterVector.h"

#include <limits>
#include "BitVector.h"
#include "Serializer.h"

using namespace probabilistic;

CounterVector::CounterVector(size_t arg_width, size_t cells)
	{
	bits = new BitVector(arg_width * cells);
	width = arg_width;
	}

CounterVector::CounterVector(const CounterVector& other)
	{
	bits = new BitVector(*other.bits);
	width = other.width;
	}

CounterVector::~CounterVector()
	{
	delete bits;
	}

bool CounterVector::Increment(size_type cell, count_type value)
	{
	assert(cell < Size());
	assert(value != 0);

	size_t lsb = cell * width;
	bool carry = false;

	for ( size_t i = 0; i < width; ++i )
		{
		bool b1 = (*bits)[lsb + i];
		bool b2 = value & (1 << i);
		(*bits)[lsb + i] = b1 ^ b2 ^ carry;
		carry = ( b1 && b2 ) || ( carry && ( b1 != b2 ) );
		}

	if ( carry )
		{
		for ( size_t i = 0; i < width; ++i )
			bits->Set(lsb + i);
		}

	return ! carry;
	}

bool CounterVector::Decrement(size_type cell, count_type value)
	{
	assert(cell < Size());
	assert(value != 0);

	value = ~value + 1; // A - B := A + ~B + 1
	bool carry = false;
	size_t lsb = cell * width;

	for ( size_t i = 0; i < width; ++i )
		{
		bool b1 = (*bits)[lsb + i];
		bool b2 = value & (1 << i);
		(*bits)[lsb + i] = b1 ^ b2 ^ carry;
		carry = ( b1 && b2 ) || ( carry && ( b1 != b2 ) );
		}

	return carry;
	}

bool CounterVector::AllZero() const
	{
	return bits->AllZero();
	}

void CounterVector::Reset()
	{
	bits->Reset();
	}

CounterVector::count_type CounterVector::Count(size_type cell) const
	{
	assert(cell < Size());

	size_t cnt = 0, order = 1;
	size_t lsb = cell * width;

	for ( size_t i = lsb; i < lsb + width; ++i, order <<= 1 )
		if ( (*bits)[i] )
			cnt |= order;

	return cnt;
	}

CounterVector::size_type CounterVector::Size() const
	{
	return bits->Size() / width;
	}

size_t CounterVector::Width() const
	{
	return width;
	}

size_t CounterVector::Max() const
	{
	return std::numeric_limits<size_t>::max()
		>> (std::numeric_limits<size_t>::digits - width);
	}

CounterVector& CounterVector::Merge(const CounterVector& other)
	{
	assert(Size() == other.Size());
	assert(Width() == other.Width());

	for ( size_t cell = 0; cell < Size(); ++cell )
		{
		size_t lsb = cell * width;
		bool carry = false;

		for ( size_t i = 0; i < width; ++i )
			{
			bool b1 = (*bits)[lsb + i];
			bool b2 = (*other.bits)[lsb + i];
			(*bits)[lsb + i] = b1 ^ b2 ^ carry;
			carry = ( b1 && b2 ) || ( carry && ( b1 != b2 ) );
			}

		if ( carry )
			{
			for ( size_t i = 0; i < width; ++i )
				bits->Set(lsb + i);
			}
		}

	return *this;
	}

namespace probabilistic {

CounterVector& CounterVector::operator|=(const CounterVector& other)
	{
	return Merge(other);
	}

CounterVector operator|(const CounterVector& x, const CounterVector& y)
	{
	CounterVector cv(x);
	return cv |= y;
	}

}

uint64 CounterVector::Hash() const
	{
	return bits->Hash();
	}

bool CounterVector::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

CounterVector* CounterVector::Unserialize(UnserialInfo* info)
	{
	return reinterpret_cast<CounterVector*>(SerialObj::Unserialize(info, SER_COUNTERVECTOR));
	}

IMPLEMENT_SERIAL(CounterVector, SER_COUNTERVECTOR)

bool CounterVector::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COUNTERVECTOR, SerialObj);

	if ( ! bits->Serialize(info) )
		return false;

	return SERIALIZE(static_cast<uint64>(width));
	}

bool CounterVector::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);

	bits = BitVector::Unserialize(info);
	if ( ! bits )
		return false;

	uint64 w;
	if ( ! UNSERIALIZE(&w) )
		return false;

	width = static_cast<size_t>(w);

	return true;
	}

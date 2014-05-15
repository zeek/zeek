// See the file "COPYING" in the main distribution directory for copyright.

#include <typeinfo>
#include <cmath>
#include <limits>

#include "BloomFilter.h"

#include "CounterVector.h"
#include "Serializer.h"

#include "../util.h"

using namespace probabilistic;

BloomFilter::BloomFilter()
	{
	hasher = 0;
	}

BloomFilter::BloomFilter(const Hasher* arg_hasher)
	{
	hasher = arg_hasher;
	}

BloomFilter::~BloomFilter()
	{
	delete hasher;
	}

bool BloomFilter::Serialize(SerialInfo* info) const
	{
	return SerialObj::Serialize(info);
	}

BloomFilter* BloomFilter::Unserialize(UnserialInfo* info)
	{
	return reinterpret_cast<BloomFilter*>(SerialObj::Unserialize(info, SER_BLOOMFILTER));
	}

bool BloomFilter::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BLOOMFILTER, SerialObj);

	return hasher->Serialize(info);
	}

bool BloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);

	hasher = Hasher::Unserialize(info);
	return hasher != 0;
	}

size_t BasicBloomFilter::M(double fp, size_t capacity)
	{
	double ln2 = std::log(2);
	return std::ceil(-(capacity * std::log(fp) / ln2 / ln2));
	}

size_t BasicBloomFilter::K(size_t cells, size_t capacity)
	{
	double frac = static_cast<double>(cells) / static_cast<double>(capacity);
	return std::ceil(frac * std::log(2));
	}

bool BasicBloomFilter::Empty() const
	{
	return bits->AllZero();
	}

void BasicBloomFilter::Clear()
	{
	bits->Reset();
	}

bool BasicBloomFilter::Merge(const BloomFilter* other)
	{
	if ( typeid(*this) != typeid(*other) )
		return false;

	const BasicBloomFilter* o = static_cast<const BasicBloomFilter*>(other);

	if ( ! hasher->Equals(o->hasher) )
		{
		reporter->Error("incompatible hashers in BasicBloomFilter merge");
		return false;
		}

	else if ( bits->Size() != o->bits->Size() )
		{
		reporter->Error("different bitvector size in BasicBloomFilter merge");
		return false;
		}

	(*bits) |= *o->bits;

	return true;
	}

BasicBloomFilter* BasicBloomFilter::Clone() const
	{
	BasicBloomFilter* copy = new BasicBloomFilter();

	copy->hasher = hasher->Clone();
	copy->bits = new BitVector(*bits);

	return copy;
	}

std::string BasicBloomFilter::InternalState() const
	{
	return fmt("%" PRIu64, bits->Hash());
	}

BasicBloomFilter::BasicBloomFilter()
	{
	bits = 0;
	}

BasicBloomFilter::BasicBloomFilter(const Hasher* hasher, size_t cells)
	: BloomFilter(hasher)
	{
	bits = new BitVector(cells);
	}

BasicBloomFilter::~BasicBloomFilter()
	{
	delete bits;
	}

IMPLEMENT_SERIAL(BasicBloomFilter, SER_BASICBLOOMFILTER)

bool BasicBloomFilter::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BASICBLOOMFILTER, BloomFilter);
	return bits->Serialize(info);
	}

bool BasicBloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BloomFilter);
	bits = BitVector::Unserialize(info);
	return (bits != 0);
	}

void BasicBloomFilter::Add(const HashKey* key)
	{
	Hasher::digest_vector h = hasher->Hash(key);

	for ( size_t i = 0; i < h.size(); ++i )
		bits->Set(h[i] % bits->Size());
	}

size_t BasicBloomFilter::Count(const HashKey* key) const
	{
	Hasher::digest_vector h = hasher->Hash(key);

	for ( size_t i = 0; i < h.size(); ++i )
		{
		if ( ! (*bits)[h[i] % bits->Size()] )
			return 0;
		}

	return 1;
	}

CountingBloomFilter::CountingBloomFilter()
	{
	cells = 0;
	}

CountingBloomFilter::CountingBloomFilter(const Hasher* hasher,
					 size_t arg_cells, size_t width)
	: BloomFilter(hasher)
	{
	cells = new CounterVector(width, arg_cells);
	}

CountingBloomFilter::~CountingBloomFilter()
	{
	delete cells;
	}

bool CountingBloomFilter::Empty() const
	{
	return cells->AllZero();
	}

void CountingBloomFilter::Clear()
	{
	cells->Reset();
	}

bool CountingBloomFilter::Merge(const BloomFilter* other)
	{
	if ( typeid(*this) != typeid(*other) )
		return false;

	const CountingBloomFilter* o = static_cast<const CountingBloomFilter*>(other);

	if ( ! hasher->Equals(o->hasher) )
		{
		reporter->Error("incompatible hashers in CountingBloomFilter merge");
		return false;
		}

	else if ( cells->Size() != o->cells->Size() )
		{
		reporter->Error("different bitvector size in CountingBloomFilter merge");
		return false;
		}

	(*cells) |= *o->cells;

	return true;
	}

CountingBloomFilter* CountingBloomFilter::Clone() const
	{
	CountingBloomFilter* copy = new CountingBloomFilter();

	copy->hasher = hasher->Clone();
	copy->cells = new CounterVector(*cells);

	return copy;
	}

string CountingBloomFilter::InternalState() const
	{
	return fmt("%" PRIu64, cells->Hash());
	}

IMPLEMENT_SERIAL(CountingBloomFilter, SER_COUNTINGBLOOMFILTER)

bool CountingBloomFilter::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COUNTINGBLOOMFILTER, BloomFilter);
	return cells->Serialize(info);
	}

bool CountingBloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BloomFilter);
	cells = CounterVector::Unserialize(info);
	return (cells != 0);
	}

// TODO: Use partitioning in add/count to allow for reusing CMS bounds.
void CountingBloomFilter::Add(const HashKey* key)
	{
	Hasher::digest_vector h = hasher->Hash(key);

	for ( size_t i = 0; i < h.size(); ++i )
		cells->Increment(h[i] % cells->Size());
	}

size_t CountingBloomFilter::Count(const HashKey* key) const
	{
	Hasher::digest_vector h = hasher->Hash(key);

	CounterVector::size_type min =
		std::numeric_limits<CounterVector::size_type>::max();

	for ( size_t i = 0; i < h.size(); ++i )
		{
		CounterVector::size_type cnt = cells->Count(h[i] % cells->Size());
		if ( cnt  < min )
			min = cnt;
		}

	return min;
	}

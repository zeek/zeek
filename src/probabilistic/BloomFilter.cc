// See the file "COPYING" in the main distribution directory for copyright.

#include "BloomFilter.h"

#include <cmath>
#include <limits>
#include "CounterVector.h"
#include "Serializer.h"

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

	if ( ! SERIALIZE(static_cast<uint16>(hasher->K())) )
		return false;

	return SERIALIZE_STR(hasher->Name().c_str(), hasher->Name().size());
	}

bool BloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);

	uint16 k;
	if ( ! UNSERIALIZE(&k) )
		return false;

	const char* name;
	if ( ! UNSERIALIZE_STR(&name, 0) )
		return false;

	hasher = Hasher::Create(k, name);

	delete [] name;
	return true;
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

void BasicBloomFilter::Clear()
	{
	bits->Clear();
	}

BasicBloomFilter* BasicBloomFilter::Merge(const BasicBloomFilter* x,
                                          const BasicBloomFilter* y)
	{
	if ( ! x->hasher->Equals(y->hasher) )
		reporter->InternalError("incompatible hashers during BasicBloomFilter merge");

	BasicBloomFilter* result = new BasicBloomFilter();
	result->hasher = x->hasher->Clone();
	result->bits = new BitVector(*x->bits | *y->bits);

	return result;
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

void BasicBloomFilter::AddImpl(const Hasher::digest_vector& h)
	{
	for ( size_t i = 0; i < h.size(); ++i )
		bits->Set(h[i] % bits->Size());
	}

size_t BasicBloomFilter::CountImpl(const Hasher::digest_vector& h) const
	{
	for ( size_t i = 0; i < h.size(); ++i )
		{
		if ( ! (*bits)[h[i] % bits->Size()] )
			return 0;
		}

	return 1;
	}

CountingBloomFilter* CountingBloomFilter::Merge(const CountingBloomFilter* x,
						const CountingBloomFilter* y)
	{
	if ( ! x->hasher->Equals(y->hasher) )
		reporter->InternalError("incompatible hashers during CountingBloomFilter merge");

	CountingBloomFilter* result = new CountingBloomFilter();
	result->hasher = x->hasher->Clone();
	result->cells = new CounterVector(*x->cells | *y->cells);

	return result;
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
void CountingBloomFilter::AddImpl(const Hasher::digest_vector& h)
	{
	for ( size_t i = 0; i < h.size(); ++i )
		cells->Increment(h[i] % cells->Size());
	}

size_t CountingBloomFilter::CountImpl(const Hasher::digest_vector& h) const
	{
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

void CountingBloomFilter::Clear()
	{
	cells->Clear();
	}

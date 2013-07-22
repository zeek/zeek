#include "BloomFilter.h"

#include <cmath>
#include <limits>
#include "CounterVector.h"
#include "Serializer.h"

BloomFilter::BloomFilter()
  : hasher_(NULL)
  {
  }

BloomFilter::BloomFilter(const Hasher* hasher)
  : hasher_(hasher)
  {
  }

BloomFilter::~BloomFilter()
  {
  if ( hasher_ )
    delete hasher_;
  }

bool BloomFilter::Serialize(SerialInfo* info) const
  {
  return SerialObj::Serialize(info);
  }

BloomFilter* BloomFilter::Unserialize(UnserialInfo* info)
  {
  return reinterpret_cast<BloomFilter*>(
      SerialObj::Unserialize(info, SER_BLOOMFILTER));
  }

bool BloomFilter::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BLOOMFILTER, SerialObj);
  if ( ! SERIALIZE(static_cast<uint16>(hasher_->K())) )
    return false;
  return SERIALIZE_STR(hasher_->Name().c_str(), hasher_->Name().size());
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
	hasher_ = Hasher::Create(k, name);
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

BasicBloomFilter* BasicBloomFilter::Merge(const BasicBloomFilter* x,
                                          const BasicBloomFilter* y)
  {
  // TODO: Ensure that x and y use the same Hasher before proceeding.
  BasicBloomFilter* result = new BasicBloomFilter();
  result->bits_ = new BitVector(*x->bits_ | *y->bits_);
  return result;
  }

BasicBloomFilter::BasicBloomFilter()
  : bits_(NULL)
  {
  }

BasicBloomFilter::BasicBloomFilter(const Hasher* hasher, size_t cells)
  : BloomFilter(hasher),
    bits_(new BitVector(cells))
  {
  }

IMPLEMENT_SERIAL(BasicBloomFilter, SER_BASICBLOOMFILTER)

bool BasicBloomFilter::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BASICBLOOMFILTER, BloomFilter);
  return bits_->Serialize(info);
  }

bool BasicBloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BloomFilter);
	bits_ = BitVector::Unserialize(info);
	return bits_ != NULL;
  }

void BasicBloomFilter::AddImpl(const Hasher::digest_vector& h)
  {
  for ( size_t i = 0; i < h.size(); ++i )
    bits_->Set(h[i] % bits_->Size());
  }

size_t BasicBloomFilter::CountImpl(const Hasher::digest_vector& h) const
  {
  for ( size_t i = 0; i < h.size(); ++i )
    if ( ! (*bits_)[h[i] % bits_->Size()] )
      return 0;
  return 1;
  }


CountingBloomFilter* CountingBloomFilter::Merge(const CountingBloomFilter* x,
                                                const CountingBloomFilter* y)
{
  assert(! "not yet implemented");
  return NULL;
}

CountingBloomFilter::CountingBloomFilter()
  : cells_(NULL)
  {
  }

CountingBloomFilter::CountingBloomFilter(const Hasher* hasher,
                                         size_t cells, size_t width)
  : BloomFilter(hasher),
    cells_(new CounterVector(width, cells))
  {
  }


IMPLEMENT_SERIAL(CountingBloomFilter, SER_COUNTINGBLOOMFILTER)

bool CountingBloomFilter::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COUNTINGBLOOMFILTER, BloomFilter);
  return cells_->Serialize(info);
  }

bool CountingBloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BloomFilter);
	cells_ = CounterVector::Unserialize(info);
	return cells_ != NULL;
  }

// TODO: Use partitioning in add/count to allow for reusing CMS bounds.

void CountingBloomFilter::AddImpl(const Hasher::digest_vector& h)
  {
  for ( size_t i = 0; i < h.size(); ++i )
    cells_->Increment(h[i] % cells_->Size());
  }

size_t CountingBloomFilter::CountImpl(const Hasher::digest_vector& h) const
  {
  CounterVector::size_type min =
    std::numeric_limits<CounterVector::size_type>::max();
  for ( size_t i = 0; i < h.size(); ++i )
    {
    CounterVector::size_type cnt = cells_->Count(h[i] % cells_->Size());
    if ( cnt  < min )
      min = cnt;
    }
  return min;
  }

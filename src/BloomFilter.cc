#include "BloomFilter.h"

#include <cmath>
#include "Serializer.h"

// Backport C++11's std::round().
namespace {
template <typename T>
T round(double x) { return (x > 0.0) ? (x + 0.5) : (x - 0.5); }
} // namespace <anonymous>


IMPLEMENT_SERIAL(CounterVector, SER_COUNTERVECTOR)

bool CounterVector::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COUNTERVECTOR, SerialObj);
  if ( ! SERIALIZE(&bits_) )
    return false;
	return SERIALIZE(static_cast<uint64>(width_));
  }

bool CounterVector::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);
	return false;
	// TODO: Ask Robin how to unserialize non-pointer members.
  //if ( ! UNSERIALIZE(&bits_) )
  //  return false;
  uint64 width;
  if ( ! UNSERIALIZE(&width) )
    return false;
	width_ = static_cast<unsigned>(width);
	return true;
  }


HashPolicy::HashVector DefaultHashing::Hash(const void* x, size_t n) const
  {
  HashVector h(K(), 0);
  for ( size_t i = 0; i < h.size(); ++i )
    h[i] = hashers_[i](x, n);
  return h;
  }


HashPolicy::HashVector DoubleHashing::Hash(const void* x, size_t n) const
  {
  HashType h1 = hasher1_(x);
  HashType h2 = hasher2_(x);
  HashVector h(K(), 0);
  for ( size_t i = 0; i < h.size(); ++i )
    h[i] = h1 + i * h2;
  return h;
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

// FIXME: should abstract base classes also have IMPLEMENT_SERIAL?
//IMPLEMENT_SERIAL(BloomFilter, SER_BLOOMFILTER)

bool BloomFilter::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BLOOMFILTER, SerialObj);
	// TODO: Make the hash policy serializable.
  //if ( ! SERIALIZE(hash_) )
  //  return false;
  return SERIALIZE(static_cast<uint64>(elements_));
  }

bool BloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);
	// TODO: Make the hash policy serializable.
  //if ( ! hash_ = HashPolicy::Unserialize(info) )
  //  return false;
	uint64 elements;
  if ( UNSERIALIZE(&elements) )
    return false;
  elements_ = static_cast<size_t>(elements);
	return true;
  }

size_t BasicBloomFilter::Cells(double fp, size_t capacity)
  {
  double ln2 = std::log(2);
  return std::ceil(-(capacity * std::log(fp) / ln2 / ln2));
  }

size_t BasicBloomFilter::K(size_t cells, size_t capacity)
  {
  double frac = static_cast<double>(cells) / static_cast<double>(capacity);
  return round<size_t>(frac * std::log(2));
  }

BasicBloomFilter::BasicBloomFilter(size_t cells, HashPolicy* hash)
  : BloomFilter(hash), bits_(cells)
  {
  }

IMPLEMENT_SERIAL(BasicBloomFilter, SER_BASICBLOOMFILTER)

bool BasicBloomFilter::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BASICBLOOMFILTER, BloomFilter);
	// TODO: Make the hash policy serializable.
  //if ( ! SERIALIZE(&bits_) )
  //  return false;
  return true;
  }

bool BasicBloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BloomFilter);
	// TODO: Non-pointer member deserialization?
	return true;
  }

void BasicBloomFilter::AddImpl(const HashPolicy::HashVector& h)
  {
  for ( size_t i = 0; i < h.size(); ++i )
    bits_.set(h[i] % h.size());
  }

size_t BasicBloomFilter::CountImpl(const HashPolicy::HashVector& h) const
  {
  for ( size_t i = 0; i < h.size(); ++i )
    if ( ! bits_[h[i] % h.size()] )
      return 0;
  return 1;
  }


void CountingBloomFilter::AddImpl(const HashPolicy::HashVector& h)
  {
  for ( size_t i = 0; i < h.size(); ++i )
    cells_.Increment(h[i] % h.size(), 1);
  }

size_t CountingBloomFilter::CountImpl(const HashPolicy::HashVector& h) const
  {
  CounterVector::size_type min =
    std::numeric_limits<CounterVector::size_type>::max();
  for ( size_t i = 0; i < h.size(); ++i )
    {
    CounterVector::size_type cnt = cells_.Count(h[i] % h.size());
    if ( cnt  < min )
      min = cnt;
    }
  return min;
  }

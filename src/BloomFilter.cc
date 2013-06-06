#include "BloomFilter.h"

#include <cmath>
#include "Serializer.h"

CounterVector::CounterVector(size_t width, size_t cells)
  : bits_(new BitVector(width * cells)), width_(width)
  {
  }

CounterVector::~CounterVector()
  {
  delete bits_;
  }

bool CounterVector::Increment(size_type cell, count_type value)
  {
  // TODO
  assert(! "not yet implemented");
  return false;
  }

bool CounterVector::Decrement(size_type cell, count_type value)
  {
  // TODO
  assert(! "not yet implemented");
  return false;
  }

CounterVector::count_type CounterVector::Count(size_type cell) const
  {
  // TODO
  assert(! "not yet implemented");
  return 0;
  }

CounterVector::size_type CounterVector::Size() const
  {
  return bits_->Blocks() / width_;
  }

bool CounterVector::Serialize(SerialInfo* info) const
  {
  return SerialObj::Serialize(info);
  }

CounterVector* CounterVector::Unserialize(UnserialInfo* info)
  {
  return reinterpret_cast<CounterVector*>(
      SerialObj::Unserialize(info, SER_COUNTERVECTOR));
  }

IMPLEMENT_SERIAL(CounterVector, SER_COUNTERVECTOR)

bool CounterVector::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_COUNTERVECTOR, SerialObj);
  if ( ! SERIALIZE(bits_) )
    return false;
	return SERIALIZE(static_cast<uint64>(width_));
  }

bool CounterVector::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);
	return false;
	bits_ = BitVector::Unserialize(info);
  if ( ! bits_ )
    return false;
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
  HashType h1 = hasher1_(x, n);
  HashType h2 = hasher2_(x, n);
  HashVector h(K(), 0);
  for ( size_t i = 0; i < h.size(); ++i )
    h[i] = h1 + i * h2;
  return h;
  }


BloomFilter::BloomFilter(size_t k)
  : hash_(new hash_policy(k))
  {
  }

BloomFilter::~BloomFilter()
  {
  if ( hash_ )
    delete hash_;
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
  if ( ! SERIALIZE(static_cast<uint16>(hash_->K())) )
    return false;
  return SERIALIZE(static_cast<uint16>(elements_));
  }

bool BloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(SerialObj);
	uint16 k;
	if ( ! UNSERIALIZE(&k) )
	  return false;
	hash_ = new hash_policy(static_cast<size_t>(k));
	uint64 elements;
  if ( ! UNSERIALIZE(&elements) )
    return false;
  elements_ = static_cast<size_t>(elements);
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

BasicBloomFilter::BasicBloomFilter(double fp, size_t capacity)
  : BloomFilter(K(M(fp, capacity), capacity))
  {
  bits_ = new BitVector(M(fp, capacity));
  }

BasicBloomFilter::BasicBloomFilter(size_t cells, size_t capacity)
  : BloomFilter(K(cells, capacity))
  {
  bits_ = new BitVector(cells);
  }

IMPLEMENT_SERIAL(BasicBloomFilter, SER_BASICBLOOMFILTER)

bool BasicBloomFilter::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BASICBLOOMFILTER, BloomFilter);
  return SERIALIZE(bits_);
  }

bool BasicBloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BloomFilter);
	bits_ = BitVector::Unserialize(info);
	return bits_ == NULL;
  }

void BasicBloomFilter::AddImpl(const HashPolicy::HashVector& h)
  {
  for ( size_t i = 0; i < h.size(); ++i )
    bits_->Set(h[i] % bits_->Size());
  }

size_t BasicBloomFilter::CountImpl(const HashPolicy::HashVector& h) const
  {
  for ( size_t i = 0; i < h.size(); ++i )
    if ( ! (*bits_)[h[i] % bits_->Size()] )
      return 0;
  return 1;
  }

CountingBloomFilter::CountingBloomFilter(double fp, size_t capacity,
                                         size_t width)
  : BloomFilter(BasicBloomFilter::K(BasicBloomFilter::M(fp, capacity),
                                    capacity))
  {
  cells_ = new CounterVector(width, BasicBloomFilter::M(fp, capacity));
  }

CountingBloomFilter::CountingBloomFilter(size_t cells, size_t capacity,
                                         size_t width)
  : BloomFilter(BasicBloomFilter::K(cells, capacity))
  {
  cells_ = new CounterVector(width, cells);
  }


IMPLEMENT_SERIAL(CountingBloomFilter, SER_COUNTINGBLOOMFILTER)

bool CountingBloomFilter::DoSerialize(SerialInfo* info) const
	{
	DO_SERIALIZE(SER_BASICBLOOMFILTER, BloomFilter);
  return SERIALIZE(cells_);
  }

bool CountingBloomFilter::DoUnserialize(UnserialInfo* info)
	{
	DO_UNSERIALIZE(BloomFilter);
	cells_ = CounterVector::Unserialize(info);
	return cells_ == NULL;
  }

void CountingBloomFilter::AddImpl(const HashPolicy::HashVector& h)
  {
  for ( size_t i = 0; i < h.size(); ++i )
    cells_->Increment(h[i] % cells_->Size(), 1);
  }

size_t CountingBloomFilter::CountImpl(const HashPolicy::HashVector& h) const
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

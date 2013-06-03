#include "BloomFilter.h"

HashPolicy::HashVector DefaultHashing::Hash(const void* x, size_t n) const
  {
  HashVector h(k(), 0);
  for ( size_t i = 0; i < h.size(); ++i )
    h[i] = hashers_[i](x, n);
  return h;
  }

HashPolicy::HashVector DoubleHashing::Hash(const void* x, size_t n) const
  {
  HashType h1 = hasher1_(x);
  HashType h2 = hasher2_(x);
  HashVector h(k(), 0);
  for ( size_t i = 0; i < h.size(); ++i )
    h[i] = h1 + i * h2;
  return h;
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

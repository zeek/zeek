#ifndef BloomFilter_h
#define BloomFilter_h

#include <vector>
#include "BitVector.h"
#include "Hash.h"
#include "H3.h"

/**
 * A vector of counters, each of which have a fixed number of bits.
 */
class CounterVector : SerialObj {
public:
  /**
   * Constructs a counter vector having cells of a given width.
   *
   * @param width The number of bits that each cell occupies.
   */
  explicit CounterVector(unsigned width);

  /**
   * Increments a given cell.
   *
   * @param cell The cell to increment.
   *
   * @param value The value to add to the current counter in *cell*.
   *
   * @return `true` if adding *value* to the counter in *cell* succeeded.
   */
  bool Increment(size_type cell, count_type value);

  /**
   * Decrements a given cell.
   *
   * @param cell The cell to decrement.
   *
   * @param value The value to subtract from the current counter in *cell*.
   *
   * @return `true` if subtracting *value* from the counter in *cell* succeeded.
   */
  bool Decrement(size_type cell, count_type value);

  /**
   * Retrieves the counter of a given cell.
   *
   * @param cell The cell index to retrieve the count for.
   *
   * @return The counter associated with *cell*.
   */
  count_type Count(size_type cell) const;

  /**
   * Retrieves the number of cells in the storage.
   *
   * @return The number of cells.
   */
  size_type Size() const;

  bool Serialize(SerialInfo* info) const;
  static CounterVector* Unserialize(UnserialInfo* info);

protected:
  DECLARE_SERIAL(CounterVector);

  CounterVector();

private:
  BitVector bits_;
  unsigned width_;
};

/**
 * The abstract base class for hash policies.
 * @tparam Codomain An integral type.
 */
class HashPolicy {
public:
  typedef hash_t hash_type;
  virtual ~HashPolicy() { }
  size_t k() const { return k; }
  virtual std::vector<hash_type> Hash(const void* x, size_t n) const = 0;
protected:
  /**
   * A functor that computes a universal hash function.
   * @tparam Codomain An integral type.
   */
  template <typename Codomain = hash_type>
  class Hasher {
  public:
    template <typename Domain>
    Codomain operator()(const Domain& x) const
      {
      return h3_(&x, sizeof(x));
      }
    Codomain operator()(const void* x, size_t n) const
      {
      return h3_(x, n);
      }
  private:
    // FIXME: The hardcoded value of 36 comes from UHASH_KEY_SIZE defined in
    // Hash.h. I do not know how this value impacts the hash function behavior
    // so I'll just copy it verbatim. (Matthias)
    H3<Codomain, 36> h3_;
  };

  HashPolicy(size_t k) : k_(k) { }
private:
  size_t k_;
};

/**
 * The *default* hashing policy. Performs *k* hash function computations.
 */
class DefaultHashing : public HashPolicy {
public:
  DefaultHashing(size_t k) : HashPolicy(k), hashers_(k) { }
  virtual ~DoubleHashing() { }

  virtual std::vector<hash_type> Hash(const void* x, size_t n) const
    {
    std::vector<hash_type> h(k(), 0);
    for (size_t i = 0; i < h.size(); ++i)
      h[i] = hashers_[i](x, n);
    return h;
    }

private:
  std::vector< Hasher<hash_type> > hashers_;
};

/**
 * The *double-hashing* policy. Uses a linear combination of 2 hash functions.
 */
class DoubleHashing : public HashPolicy {
public:
  DoubleHashing(size_t k) : HashPolicy(k), hashers_(k) { }
  virtual ~DoubleHashing() { }

  virtual std::vector<hash_type> Hash(const void* x, size_t n) const
    {
    Codomain h1 = hasher1_(x);
    Codomain h2 = hasher2_(x);
    std::vector<hash_type> h(k(), 0);
    for (size_t i = 0; i < h.size(); ++i)
      h[i] = h1 + i * h2;
    return h;
    }

private:
  Hasher<hash_type> hasher1_;
  Hasher<hash_type> hasher2_;
};

/**
 * The abstract base class for Bloom filters.
 */
class BloomFilter : SerialObj {
public:
  virtual ~BloomFilter() { delete hash_; }

  /**
   * Adds an element of type T to the Bloom filter.
   * @param x The element to add
   */
  template <typename T>
  void Add(const T& x)
    {
    ++elements_;
    AddImpl(hash_->Hash(x));
    }

  /**
   * Retrieves the associated count of a given value.
   *
   * @param x The value of type `T` to check.
   *
   * @return The counter associated with *x*.
   */
  template <typename T>
  size_t Count(const T& x) const
    {
    return CountImpl(hash_->Hash(x));
    }

  /**
   * Retrieves the number of elements added to the Bloom filter.
   *
   * @return The number of elements in this Bloom filter.
   */
  size_t Size() const
    {
    return elements_;
    }

protected:
  typedef std::vector<HashPolicy::hash_value> HashVector;

  /**
   * Default-constructs a Bloom filter.
   */
	BloomFilter();

  /**
   * Constructs a BloomFilter.
   * @param hash The hashing policy.
   */
  BloomFilter(HashPolicy* hash);

  virtual void AddImpl(const HashVector& hashes) = 0;

  virtual size_t CountImpl(const HashVector& hashes) const = 0;

  std::vector<HashPolicy::hash_value> Hash(const T& x) const
    {
    return hash_->Hash(&x, sizeof(x));
    }

private:
  HashPolicy<T>* hash_;  // Owned by *this.

  size_t elements_;
};

/**
 * A basic Bloom filter.
 */
class BasicBloomFilter : public BloomFilter {
public:
  BasicBloomFilter();
  BasicBloomFilter(HashPolicy* hash);

protected:
  virtual void AddImpl(const HashVector& h)
    {
    for ( size_t i = 0; i < h.size(); ++i )
      bits_.set(h[i] % h.size());
    }

  virtual size_t CountImpl(const HashVector& h) const
    {
    for ( size_t i = 0; i < h.size(); ++i )
      if ( ! bits_[h[i] % h.size()] )
        return 0;
    return 1;
    }

private:
  BitVector bits_;
};

/**
 * A counting Bloom filter.
 */
class CountingBloomFilter : public BloomFilter {
public:
  CountingBloomFilter(unsigned width);
  CountingBloomFilter(HashPolicy* hash);

protected:
  CountingBloomFilter();

private:
  CounterVector cells_;
};

#endif

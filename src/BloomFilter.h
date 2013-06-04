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
  typedef size_t size_type;
  typedef uint64 count_type;

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

  CounterVector() { }

private:
  BitVector bits_;
  unsigned width_;
};

/**
 * The abstract base class for hash policies that hash elements *k* times.
 * @tparam Codomain An integral type.
 */
class HashPolicy {
public:
  typedef hash_t HashType;
  typedef std::vector<HashType> HashVector;

  virtual ~HashPolicy() { }
  size_t K() const { return k_; }
  virtual HashVector Hash(const void* x, size_t n) const = 0;

protected:
  /**
   * A functor that computes a universal hash function.
   * @tparam Codomain An integral type.
   */
  template <typename Codomain = HashType>
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
  const size_t k_;
};

/**
 * The *default* hashing policy. Performs *k* hash function computations.
 */
class DefaultHashing : public HashPolicy {
public:
  DefaultHashing(size_t k) : HashPolicy(k), hashers_(k) { }
  virtual ~DefaultHashing() { }

  virtual HashVector Hash(const void* x, size_t n) const;

private:
  std::vector< Hasher<HashType> > hashers_;
};

/**
 * The *double-hashing* policy. Uses a linear combination of two hash functions.
 */
class DoubleHashing : public HashPolicy {
public:
  DoubleHashing(size_t k) : HashPolicy(k) { }
  virtual ~DoubleHashing() { }

  virtual HashVector Hash(const void* x, size_t n) const;

private:
  Hasher<HashType> hasher1_;
  Hasher<HashType> hasher2_;
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
    AddImpl(hash_->Hash(&x, sizeof(x)));
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
    return CountImpl(hash_->Hash(&x, sizeof(x)));
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

  bool Serialize(SerialInfo* info) const;
  static BloomFilter* Unserialize(UnserialInfo* info);

protected:
  DECLARE_SERIAL(BloomFilter);

	BloomFilter() { };
  BloomFilter(HashPolicy* hash) : hash_(hash) { }

  virtual void AddImpl(const HashPolicy::HashVector& hashes) = 0;
  virtual size_t CountImpl(const HashPolicy::HashVector& hashes) const = 0;

private:
  HashPolicy* hash_;
  size_t elements_;
};

/**
 * A basic Bloom filter.
 */
class BasicBloomFilter : public BloomFilter {
public:
  static size_t Cells(double fp, size_t capacity);
  static size_t K(size_t cells, size_t capacity);

  BasicBloomFilter(size_t cells, HashPolicy* hash);

protected:
  DECLARE_SERIAL(BasicBloomFilter);

  BasicBloomFilter() { }

  virtual void AddImpl(const HashPolicy::HashVector& h);
  virtual size_t CountImpl(const HashPolicy::HashVector& h) const;

private:
  BitVector bits_;
};

/**
 * A counting Bloom filter.
 */
class CountingBloomFilter : public BloomFilter {
public:
  CountingBloomFilter(unsigned width, HashPolicy* hash);

protected:
  DECLARE_SERIAL(CountingBloomFilter);

  CountingBloomFilter();

  virtual void AddImpl(const HashPolicy::HashVector& h);
  virtual size_t CountImpl(const HashPolicy::HashVector& h) const;

private:
  CounterVector cells_;
};

#endif

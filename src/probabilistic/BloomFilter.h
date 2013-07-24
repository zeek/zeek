// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PROBABILISTIC_BLOOMFILTER_H
#define PROBABILISTIC_BLOOMFILTER_H

#include <vector>
#include "BitVector.h"
#include "Hasher.h"

namespace probabilistic {

class CounterVector;

/**
 * The abstract base class for Bloom filters.
 *
 * At this point we won't let the user choose the hasher, but we might open
 * up the interface in the future.
 */
class BloomFilter : public SerialObj {
public:
	/**
	 * Destructor.
	 */
	virtual ~BloomFilter();

	/**
	 * Adds an element of type T to the Bloom filter.
	 * @param x The element to add
	 */
	template <typename T>
	void Add(const T& x)
		{
		AddImpl((*hasher)(x));
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
		return CountImpl((*hasher)(x));
		}

	/**
	 * Removes all elements, i.e., resets all bits in the underlying bit vector.
	 */
	virtual void Clear() = 0;

	/**
	 * Merges another Bloom filter into a copy of this one.
	 *
	 * @param other The other Bloom filter.
	 *
	 * @return `true` on success.
	 */
	virtual bool Merge(const BloomFilter* other) = 0;

	/**
	 * Constructs a copy of this Bloom filter.
	 *
	 * @return A copy of `*this`.
	 */
	virtual BloomFilter* Clone() const = 0;

	/**
	 * Serializes the Bloom filter.
	 *
	 * @param info The serializaton information to use.
	 *
	 * @return True if successful.
	 */
	bool Serialize(SerialInfo* info) const;

	/**
	 * Unserializes a Bloom filter.
	 *
	 * @param info The serializaton information to use.
	 *
	 * @return The unserialized Bloom filter, or null if an error
	 * occured.
	 */
	static BloomFilter* Unserialize(UnserialInfo* info);

protected:
	DECLARE_ABSTRACT_SERIAL(BloomFilter);

	/**
	 * Default constructor.
	 */
	BloomFilter();

	/**
	 * Constructs a Bloom filter.
	 *
	 * @param hasher The hasher to use for this Bloom filter.
	 */
	BloomFilter(const Hasher* hasher);

	/**
	 * Abstract method for implementinng the *Add* operation.
	 *
	 * @param hashes A set of *k* hashes for the item to add, computed by
	 * the internal hasher object.
	 *
	 */
	virtual void AddImpl(const Hasher::digest_vector& hashes) = 0;

	/**
	 * Abstract method for implementing the *Count* operation.
	 *
	 * @param hashes A set of *k* hashes for the item to add, computed by
	 * the internal hasher object.
	 *
	 * @return Returns the counter associated with the hashed element.
	 */
	virtual size_t CountImpl(const Hasher::digest_vector& hashes) const = 0;

	const Hasher* hasher;
};

/**
 * A basic Bloom filter.
 */
class BasicBloomFilter : public BloomFilter {
public:
	/**
	 * Constructs a basic Bloom filter with a given number of cells. The
	 * ideal number of cells can be computed with *M*.
	 *
	 * @param hasher The hasher to use. The ideal number of hash
	 * functions can be computed with *K*.
	 *
	 * @param cells The number of cells.
	 */
	BasicBloomFilter(const Hasher* hasher, size_t cells);

	/**
	 * Computes the number of cells based on a given false positive rate
	 * and capacity. In the literature, this parameter often has the name
	 * *M*.
	 *
	 * @param fp The false positive rate.
	 *
	 * @param capacity The expected number of elements that will be
	 * stored.
	 *
	 * Returns: The number cells needed to support a false positive rate
	 * of *fp* with at most *capacity* elements.
	 */
	static size_t M(double fp, size_t capacity);

	/**
	 * Computes the optimal number of hash functions based on the number cells
	 * and expected number of elements.
	 *
	 * @param cells The number of cells (*m*).
	 *
	 * @param capacity The maximum number of elements.
	 *
	 * Returns: the optimal number of hash functions for a false-positive
	 * rate of *fp* for at most *capacity* elements.
	 */
	static size_t K(size_t cells, size_t capacity);

	// Overridden from BloomFilter.
	virtual void Clear();
	virtual bool Merge(const BloomFilter* other);
	virtual BasicBloomFilter* Clone() const;

protected:
	DECLARE_SERIAL(BasicBloomFilter);

	/**
	 * Default constructor.
	 */
	BasicBloomFilter();

	// Overridden from BloomFilter.
	virtual void AddImpl(const Hasher::digest_vector& h);
	virtual size_t CountImpl(const Hasher::digest_vector& h) const;

private:
	BitVector* bits;
};

/**
 * A counting Bloom filter.
 */
class CountingBloomFilter : public BloomFilter {
public:
	/**
	 * Constructs a counting Bloom filter.
	 *
	 * @param hasher The hasher to use. The ideal number of hash
	 * functions can be computed with *K*.
	 *
	 * @param cells The number of cells to use.
	 *
	 * @param width The maximal bit-width of counter values.
	 */
	CountingBloomFilter(const Hasher* hasher, size_t cells, size_t width);

	// Overridden from BloomFilter.
	virtual void Clear();
	virtual bool Merge(const BloomFilter* other);
	virtual CountingBloomFilter* Clone() const;

protected:
	DECLARE_SERIAL(CountingBloomFilter);

	/**
	 * Default constructor.
	 */
	CountingBloomFilter();

	// Overridden from BloomFilter.
	virtual void AddImpl(const Hasher::digest_vector& h);
	virtual size_t CountImpl(const Hasher::digest_vector& h) const;

private:
	CounterVector* cells;
};

}

#endif

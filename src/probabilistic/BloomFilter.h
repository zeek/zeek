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
 */
class BloomFilter : public SerialObj {
public:
	/**
	 * Destructor.
	 */
	virtual ~BloomFilter();

	/**
	 * Adds an element to the Bloom filter.
	 *
	 * @param key The key associated with the element to add.
	 */
	virtual void Add(const HashKey* key) = 0;

	/**
	 * Retrieves the associated count of a given value.
	 *
	 * @param key The key associated with the element to check.
	 *
	 * @return The counter associated with *key*.
	 */
	virtual size_t Count(const HashKey* key) const = 0;

	/**
	 * Checks whether the Bloom filter is empty.
	 *
	 * @return `true` if the Bloom filter contains no elements.
	 */
	virtual bool Empty() const = 0;

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
	 * Returns a string with a representation of the Bloom filter's
	 * internal state. This is for debugging/testing purposes only.
	 */
	virtual string InternalState() const = 0;

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
	 * Destructor.
	 */
	~BasicBloomFilter();

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
	virtual bool Empty() const;
	virtual void Clear();
	virtual bool Merge(const BloomFilter* other);
	virtual BasicBloomFilter* Clone() const;
	virtual string InternalState() const;

protected:
	DECLARE_SERIAL(BasicBloomFilter);

	/**
	 * Default constructor.
	 */
	BasicBloomFilter();

	// Overridden from BloomFilter.
	virtual void Add(const HashKey* key);
	virtual size_t Count(const HashKey* key) const;

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

	/**
	 * Destructor.
	 */
	~CountingBloomFilter();

	// Overridden from BloomFilter.
	virtual bool Empty() const;
	virtual void Clear();
	virtual bool Merge(const BloomFilter* other);
	virtual CountingBloomFilter* Clone() const;
	virtual string InternalState() const;

protected:
	DECLARE_SERIAL(CountingBloomFilter);

	/**
	 * Default constructor.
	 */
	CountingBloomFilter();

	// Overridden from BloomFilter.
	virtual void Add(const HashKey* key);
	virtual size_t Count(const HashKey* key) const;

private:
	CounterVector* cells;
};

}

#endif

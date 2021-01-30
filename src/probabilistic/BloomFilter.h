// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <memory>
#include <vector>
#include <string>

#include <broker/expected.hh>

#include "zeek/probabilistic/BitVector.h"
#include "zeek/probabilistic/Hasher.h"

namespace broker { class data; }

ZEEK_FORWARD_DECLARE_NAMESPACED(CounterVector, zeek, probabilistic, detail);

namespace zeek::probabilistic {

/** Types of derived BloomFilter classes. */
enum BloomFilterType { Basic, Counting };

/**
 * The abstract base class for Bloom filters.
 */
class BloomFilter {
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
	virtual void Add(const zeek::detail::HashKey* key) = 0;

	/**
	 * Retrieves the associated count of a given value.
	 *
	 * @param key The key associated with the element to check.
	 *
	 * @return The counter associated with *key*.
	 */
	virtual size_t Count(const zeek::detail::HashKey* key) const = 0;

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
	virtual std::string InternalState() const = 0;

	broker::expected<broker::data> Serialize() const;
	static std::unique_ptr<BloomFilter> Unserialize(const broker::data& data);

protected:
	/**
	 * Default constructor.
	 */
	BloomFilter();

	/**
	 * Constructs a Bloom filter.
	 *
	 * @param hasher The hasher to use for this Bloom filter.
	 */
	explicit BloomFilter(const detail::Hasher* hasher);

	virtual broker::expected<broker::data> DoSerialize() const = 0;
	virtual bool DoUnserialize(const broker::data& data) = 0;
	virtual BloomFilterType Type() const = 0;

	const detail::Hasher* hasher;
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
	BasicBloomFilter(const detail::Hasher* hasher, size_t cells);

	/**
	 * Destructor.
	 */
	~BasicBloomFilter() override;

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
	bool Empty() const override;
	void Clear() override;
	bool Merge(const BloomFilter* other) override;
	BasicBloomFilter* Clone() const override;
	std::string InternalState() const override;

protected:
	friend class BloomFilter;

	/**
	 * Default constructor.
	 */
	BasicBloomFilter();

	// Overridden from BloomFilter.
	void Add(const zeek::detail::HashKey* key) override;
	size_t Count(const zeek::detail::HashKey* key) const override;
	broker::expected<broker::data> DoSerialize() const override;
	bool DoUnserialize(const broker::data& data) override;
	BloomFilterType Type() const override
		{ return BloomFilterType::Basic; }

private:
	detail::BitVector* bits;
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
	CountingBloomFilter(const detail::Hasher* hasher, size_t cells, size_t width);

	/**
	 * Destructor.
	 */
	~CountingBloomFilter() override;

	// Overridden from BloomFilter.
	bool Empty() const override;
	void Clear() override;
	bool Merge(const BloomFilter* other) override;
	CountingBloomFilter* Clone() const override;
	std::string InternalState() const override;

protected:
	friend class BloomFilter;

	/**
	 * Default constructor.
	 */
	CountingBloomFilter();

	// Overridden from BloomFilter.
	void Add(const zeek::detail::HashKey* key) override;
	size_t Count(const zeek::detail::HashKey* key) const override;
	broker::expected<broker::data> DoSerialize() const override;
	bool DoUnserialize(const broker::data& data) override;
	BloomFilterType Type() const override
		{ return BloomFilterType::Counting; }

private:
	detail::CounterVector* cells;
};

} // namespace zeek::probabilistic

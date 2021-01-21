// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <cstddef>
#include <cstdint>
#include <memory>

#include <broker/expected.hh>

namespace broker { class data; }

ZEEK_FORWARD_DECLARE_NAMESPACED(BitVector, zeek, probabilistic, detail);

namespace zeek::probabilistic::detail {

/**
 * A vector of counters, each of which has a fixed number of bits.
 */
class CounterVector {
public:
	typedef size_t size_type;
	typedef uint64_t count_type;

	/**
	 * Constructs a counter vector having cells of a given width.
	 *
	 * @param width The number of bits that each cell occupies.
	 *
	 * @param cells The number of cells in the bitvector.
	 *
	 * @pre `cells > 0 && width > 0`
	 */
	explicit CounterVector(size_t width, size_t cells = 1024);

	/**
	 * Copy-constructs a counter vector.
	 *
	 * @param other The counter vector to copy.
	 */
	CounterVector(const CounterVector& other);

	/**
	 * Destructor.
	 */
	virtual ~CounterVector();

	/**
	 * Increments a given cell.
	 *
	 * @param cell The cell to increment.
	 *
	 * @param value The value to add to the current counter in *cell*.
	 *
	 * @return `true` if adding *value* to the counter in *cell* succeeded.
	 *
	 * @pre `cell < Size()`
	 */
	bool Increment(size_type cell, count_type value = 1);

	/**
	 * Decrements a given cell.
	 *
	 * @param cell The cell to decrement.
	 *
	 * @param value The value to subtract from the current counter in *cell*.
	 *
	 * @return `true` if subtracting *value* from the counter in *cell* succeeded.
	 *
	 * @pre `cell < Size()`
	 */
	bool Decrement(size_type cell, count_type value = 1);

	/**
	 * Retrieves the counter of a given cell.
	 *
	 * @param cell The cell index to retrieve the count for.
	 *
	 * @return The counter associated with *cell*.
	 *
	 * @pre `cell < Size()`
	 */
	count_type Count(size_type cell) const;

	/**
	 * Checks whether all counters are 0.
	 * @return `true` iff all counters have the value 0.
	 */
	bool AllZero() const;

	/**
	 * Sets all counters to 0.
	 */
	void Reset();

	/**
	 * Retrieves the number of cells in the storage.
	 *
	 * @return The number of cells.
	 */
	size_type Size() const;

	/**
	 * Retrieves the counter width.
	 *
	 * @return The number of bits per counter.
	 */
	size_t Width() const;

	/**
	 * Computes the maximum counter value.
	 *
	 * @return The maximum counter value based on the width.
	 */
	size_t Max() const;

	/**
	 * Merges another counter vector into this instance by *adding* the
	 * counters of each cells.
	 *
	 * @param other The counter vector to merge into this instance.
	 *
	 * @return A reference to `*this`.
	 *
	 * @pre `Size() == other.Size() && Width() == other.Width()`
	 */
	CounterVector& Merge(const CounterVector& other);

	/**
	 * An alias for ::Merge.
	 */
	CounterVector& operator|=(const CounterVector& other);

	/** Computes a hash value of the internal representation.
	  * This is mainly for debugging/testing purposes.
	  *
	  * @return The hash.
	  */
	uint64_t Hash() const;

	broker::expected<broker::data> Serialize() const;
	static std::unique_ptr<CounterVector> Unserialize(const broker::data& data);

protected:
	friend CounterVector operator|(const CounterVector& x,
				       const CounterVector& y);

	CounterVector() { }

private:
	CounterVector& operator=(const CounterVector&); // Disable.

	BitVector* bits;
	size_t width;
};

} // namespace zeek::probabilistic::detail

#ifndef CounterVector_h
#define CounterVector_h

#include "SerialObj.h"

class BitVector;

/**
 * A vector of counters, each of which have a fixed number of bits.
 */
class CounterVector : public SerialObj {
public:
  typedef size_t size_type;
  typedef uint64 count_type;

  /**
   * Constructs a counter vector having cells of a given width.
   *
   * @param width The number of bits that each cell occupies.
   *
   * @param cells The number of cells in the bitvector.
   *
   * @pre `cells > 0 && width > 0`
   */
  CounterVector(size_t width, size_t cells = 1024);

  ~CounterVector();

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
   * Merges another counter vector into this instance by *adding* the counters
   * of each cells.
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

  friend CounterVector operator|(const CounterVector& x,
                                 const CounterVector& y);

  bool Serialize(SerialInfo* info) const;
  static CounterVector* Unserialize(UnserialInfo* info);

protected:
  DECLARE_SERIAL(CounterVector);

  CounterVector() { }

private:
  BitVector* bits_;
  size_t width_;
};

#endif

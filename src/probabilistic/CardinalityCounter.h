// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PROBABILISTIC_CARDINALITYCOUNTER_H
#define PROBABILISTIC_CARDINALITYCOUNTER_H

#include <stdint.h>
#include <OpaqueVal.h>

namespace probabilistic {

/**
 * A probabilistic cardinality counter using the HyperLogLog algorithm.
 */
class CardinalityCounter {
public:
	/**
	 * Constructor.
	 *
	 * The number of buckets of the data structure is determined using
	 * the error margin and the given confidence.
	 *
	 * For example, assume an error_margin of 2% and a confidence
	 * of 95%. If the Size function returns an estimate of 100, this
	 * means that we are 95% sure that the cardinality is between 98
	 * and 102.
	 *
	 * @param error_margin error margin
	 *
	 * @param confidence confidence of the error. Default: 0.95
	 */
	CardinalityCounter(double error_margin, double confidence = 0.95);

	/**
	 * Copy-Constructor
	 */
	CardinalityCounter(CardinalityCounter& other);

	/**
	 * Constructor for a known number of buckets.
	 *
	 * The error margin is 1.04/sqrt(size) with approximately 68%
	 * probability.
	 *
	 * @param size number of buckets to create
	 */
	CardinalityCounter(uint64 size);

	/**
	 * Destructor.
	 */
	~CardinalityCounter();

	/**
	 * Add a new element to the counter.
	 *
	 * The hash function generating the hashes needs to be uniformly
	 * distributed over 64 bits.
	 *
	 * @param hash 64-bit hash value of the element to be added
	 */
	void AddElement(uint64 hash);

	/**
	 * Get the current estimated number of elements in the data
	 * structure
	 *
	 * @return Estimated number of elements
	 **/
	double Size() const;

	/**
	 * Merges the argument cardinality counter with this one. The error
	 * margins of both counters have to be the same, otherwhise the merge
	 * operation will not be carried out.
	 *
	 * @param c Cardinality counter to merge into the current counter.
	 *
	 * @return True if successful
	 */
	bool Merge(CardinalityCounter* c);

	/**
	 * Serializes the cardinality counter.
	 *
	 * @param info The serializaton information to use.
	 *
	 * @return True if successful.
	 */
	bool Serialize(SerialInfo* info) const;

	/**
	 * Unserializes a cardinality counter.
	 *
	 * @param info The serializaton information to use.
	 *
	 * @return The unserialized cardinality counter, or null if an error
	 * 	   occured.
	 */
	static CardinalityCounter* Unserialize(UnserialInfo* info);

protected:
	/**
	 * Return the number of buckets.
	 *
	 * @return Number of buckets
	 */
	uint64 GetM() const;

	/**
	 * Returns the buckets array that holds all of the rough cardinality
	 * estimates.
	 *
	 * Use GetM() to determine the size.
	 *
	 * @return Array containing cardinality estimates
	 */
	uint8_t* GetBuckets();

private:
	/**
	 * Constructor used when unserializing, i.e., all parameters are
	 * known.
	 */
	CardinalityCounter(uint64 size, uint64 V, double alpha_m);

	/**
	 * Helper function with code used jointly by multiple constructors.
	 *
	 * @param arg_size: number of buckets that need to be kept
	 */
	void Init(uint64 arg_size);

	/**
	 * This function calculates the smallest value of b that will
	 * satisfy these the constraints of a specified error margin and
	 * confidence level.
	 *
	 * The exact expression for b is as follows:
	 * Define x = 2*(log(1.04*k/error)/log(2)). Then b is the ceiling of x.
	 *
	 * After that initial estimate, the value of b is increased until the
	 * standard deviation falls within the specified valud.
	 *
	 * @param error error margin
	 *
	 * @param confidence confidence of the error
	 *
	 * @return minimal B-value satisfying the error-rate under confidence.
	 */
	int OptimalB(double error, double confidence) const;

	/**
	 * Determines at which index (counted from the back) the first one-bit
	 * appears. The last b bits have to be 0 (the element has to be divisible
	 * by m), hence they are ignored.
	 *
	 * @param hash_modified hash value
	 *
	 * @returns index of first one-bit
	 */
	uint8_t Rank(uint64 hash_modified) const;

	/**
	 * This is the number of buckets that will be stored. The standard
	 * error is 1.04/sqrt(m), so the actual cardinality will be the
	 * estimate +/- 1.04/sqrt(m) with approximately 68% probability.
	 */
	uint64 m;

	/**
	 * These are the actual buckets that are storing an estimate of the
	 * cardinality. All these need to do is count when the first 1 bit
	 * appears in the bitstring and that location is at most 65, so not
	 * that many bits are needed to store it.
	 */
	uint8_t* buckets;

	/**
	 * There are some state constants that need to be kept track of to
	 * make the final estimate easier. V is the number of values in
	 * buckets that are 0 and this is used in the small error correction.
	 * alpha_m is a multiplicative constant used in the algorithm.
	 */
	uint64 V;
	double alpha_m;
};

}

#endif

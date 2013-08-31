// See the file "COPYING" in the main distribution directory for copyright.

#ifndef PROBABILISTIC_CARDINALITYCOUNTER_H
#define PROBABILISTIC_CARDINALITYCOUNTER_H

#include <stdint.h>
#include <OpaqueVal.h>

namespace probabilistic {

/**
 * A probabilisitc cardinality counter using the HyperLogLog algorithm.
 */
class CardinalityCounter {
public:
	/**
	 * Constructor.
	 *
	 * Based on the error_margin, the number of buckets that need to be
	 * kept will be determined. Based on the max_size, the number of bits
	 * that will be used from the hash function will be determined.
	 *
	 * We need the hash function to return integers that are uniformly
	 * distributed from 0 to 2^L-1. And if that happens, the maximum
	 * cardinality that this counter can handle is approximately 2^L. By
	 * default, we will assume a value of 64 bits.
	 *
	 * Confidence in the estimate given by a cardinality counter is.
	 *
	 * In other words, if the cardinality is estimated to be 100 with 2%
	 * error margin and HLL_CONFis 0.95, then we are 95% sure that the
	 * actual cardinality is between 98 and 102.
	 */
	CardinalityCounter(double error_margin, double confidence = 0.95);

	/**
	* Constructor used for cloning.
	*
	* The error margin will be 1.04/sqrt(m) with approximately 68%
	* probability.
	*/
	CardinalityCounter(uint64 size);

	/**
	* Deletes the class variables.
	*/
	~CardinalityCounter();

	/**
	* This will add an element to the counter. It's responsible for
	* adding an element and updating the value of V, if that applies.
	*/
	void AddElement(uint64 hash);

	/**
	* Returns the size estimate of the set. First, it has the "raw"
	* HyperLogLog estimate. And then, we check if it's too "large" or
	* "small" because the raw estimate doesn't do well in those cases.
	* Thus, we correct for those errors as specified in the paper.
	*/
	double Size();

	/**
	* Returns the buckets array that holds all of the rough cardinality
	* estimates.
	*/
	uint8_t* GetBuckets();

	/**
	* Merges the argument cardinality counter with this one. The error
	* margins are assumed to be the same, so they have the same number of
	* buckets. If any of the conditions are violated, then the return
	* value of size() is meaningless.
	*/
	void Merge(CardinalityCounter* c);

	/**
	* Returns the value of m. Should be used only for statistical
	* purposes.
	*/
	uint64 GetM();

	/**
c	 * Serializes the cardinality counter.
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
	 * occured.
	 */
	static CardinalityCounter* Unserialize(UnserialInfo* info);

private:
	/**
	* Constructor used when unserializing, i.e., all parameters are
	* known.
	*/
	CardinalityCounter(uint64 size, uint64 V, double alpha_m);

	/**
	 * Helper function with code used jointly by multiple constructors.
	 */
	void Init(uint64 arg_size);

	/**
	 * This function will calculate the smallest value of b that will
	 * satisfy these the constraints of a specified error margin and
	 * confidence level.
	 *
	 * The exact expression for b is as follows:
	 * Define x = 2*(log(1.04*k/error)/log(2)). Then b is the ceiling of x
	 *
	 * error is the error margin.
	 *
	 * k is the number of standard deviations that we have to go to have
	 * a confidence level of conf.
	 *
	 * confidence: TODO.
	 */
	int OptimalB(double error, double confidence);

	/**
	* Computes when the first one appears in the element. It looks at the
	* bitstring from the end though. A precondition is that the argument
	* is already divisible by m, so we just ignore the last b bits, since
	* m = 2^b and the last b bits will always be 0.
	*/
	uint8_t Rank(uint64 hash_modified);

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

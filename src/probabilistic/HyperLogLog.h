// See the file "COPYING" in the main distribution directory for copyright.

#ifndef hyperloglog_h
#define hyperloglog_h

#include <stdint.h>
#include <OpaqueVal.h>

namespace probabilistic {

/*
 *  "conf" is how confident the estimate given by the counter is.
 *  
 *  In other words, if the cardinality is estimated to be 100 with 2% error margin and HLL_CONFis
 *  0.95, then we are 95% sure that the actual cardinality is between 98 and 102.
 */
#define HLL_CONF .95


class CardinalityCounter {
 friend class CardinalityVal;

 private:
  /*
   *  This is the number of buckets that will be stored. The standard error is 1.04/sqrt(m), so the
   *  actual cardinality will be the estimate +/- 1.04/sqrt(m) with approximately 68% probability.
   */
  uint64_t m;

  /*
   *  These are the actual buckets that are storing an estimate of the cardinality. All these need to
   *  do is count when the first 1 bit appears in the bitstring and that location is at most 65, so
   *  not that many bits are needed to store it.
   */
  uint8_t* buckets;

  /*
   * There are some state constants that need to be kept track of to make the final estimate easier.
   * V is the number of values in buckets that are 0 and this is used in the small error correction.
   * alpha_m is a multiplicative constant used in the algorithm.
   */
  uint64_t V;
  double alpha_m;

  /* 
   * This function will calculate the smallest value of b that will satisfy these the constraints of
   * a specified error margin and confidence level.
   *
   * The exact expression for b is as follows:
   * Define x = 2*(log(1.04*k/error)/log(2)). Then b is the ceiling of x
   *
   * error is the error margin.
   * k is the number of standard deviations that we have to go to have a confidence level of conf.
   */

  int optimalB(double error);

  /*
   * Computes when the first one appears in the element. It looks at the bitstring from the end though.
   * A precondition is that the argument is already divisible by m, so we just ignore the last b bits,
   * since m = 2^b and the last b bits will always be 0.
   */
  uint8_t rank(uint64_t hash_modified);

 public:
  /*
   *  This will be used when cloning. The error margin will be 1.04/sqrt(m) with approximately 68%
   *  probability.
   */
  CardinalityCounter(uint64_t size);

  /*
   *  This will initialize the Cardinality counter.Based on the error_margin, the number of buckets 
   *  that need to be kept will be determined. Based on the max_size, the number of bits that will
   *  be used from the hash function will be determined.
   *
   *  We need the hash function to return integers that are uniformly distributed from 0 to 2^L-1.
   *  And if that happens, the maximum cardinality that this counter can handle is approximately 2^L.
   *  By default, we will assume a value of 64 bits.
   */
   
  CardinalityCounter(double error_margin);

  /*
   * Deletes the class variables.
   */

  ~CardinalityCounter();

  /*
   * This will add an element to the counter. It's responsible for adding an element and updating
   * the value of V, if that applies.
   */
  void addElement(uint64_t hash);
  
  /*
   * Returns the size estimate of the set. First, it has the "raw" HyperLogLog estimate. And then, we
   * check if it's too "large" or "small" because the raw estimate doesn't do well in those cases. 
   * Thus, we correct for those errors as specified in the paper.
   */

  double size();

  /*
   * Returns the buckets array that holds all of the rough cardinality estimates.
   */

  uint8_t* getBuckets();

  /*
   * Merges the argument cardinality counter with this one. The error margins are assumed to be the same,
   * so they have the same number of buckets. If any of the conditions are violated, then the return value
   * of size() is meaningless.
   */
  void merge(CardinalityCounter* c);

  /*
   * Returns the value of m. Should be used only for statistical purposes.
   */
  uint64_t getM();
};

}

#endif 

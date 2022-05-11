// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"
#include "zeek/Hash.h"

#include <stdint.h>
#include <utility>
#include <vector>

namespace zeek::probabilistic
	{

// Size of each element
using countms_data_t = uint32_t;
// prime value; please see paper for details. Note that this has to be larger
// than the maximum value representable in countms_data.
using countms_ab_t = uint64_t;
constexpr countms_ab_t p = 2305843009213693951; // 2^61-1

/**
 * The implementation of a basic Count-Min Sketch.
 *
 * This is a pretty straightforward implementation following the paper
 * "Approximating Data with the Count-Min Data Structure" by Cormode and Muthukrishnan
 * (http://dimacs.rutgers.edu/~graham/pubs/papers/cmsoft.pdf). Initialization from the full
 * paper "An Improved Data Stream Summary: The Count-Min Sketch and its Applications".
 **/
class CountMinSketch
	{
public:
	/**
	 * Constructs a Count-min sketch with witdh w and depth d. The width and depth for a specific
	 * error rate can be computed using *CalculateWD*
	 *
	 * @param w: width
	 *
	 * @param d: depth
	 **/
	explicit CountMinSketch(uint16_t w, uint16_t d);

	/**
	 * Calculates the parameters w (width) and d (depth) of the sketch, given epsilon and delta.
	 *
	 * Epsilon and delta are defined as follows. With a probability of 1 - delta, the error is at
	 * most epsilon * norm(count).
	 *
	 * @param epsilon: error factor
	 *
	 * @param delta: error probability
	 *
	 * Returns: w, d on success; -1, -1 when invalid parameters are given
	 **/
	static std::pair<int, int> CalculateWD(double epsilon, double delta);

	void Update(countms_data_t i, uint16_t c);
	void Update(const zeek::detail::HashKey* item, uint16_t c);
	uint32_t Estimate(countms_data_t i);
	uint32_t Estimate(const zeek::detail::HashKey* item);

private:
	std::vector<countms_data_t> content;
	std::vector<std::pair<countms_ab_t, countms_ab_t>> ab;
	uint64_t total = 0;
	uint16_t w;
	uint16_t d;
	};

	}

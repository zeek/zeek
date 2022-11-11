// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/probabilistic/CardinalityCounter.h"

#include <broker/data.hh>
#include <cmath>
#include <cstdint>
#include <utility>

#include "zeek/Reporter.h"

namespace zeek::probabilistic::detail
	{

int CardinalityCounter::OptimalB(double error, double confidence) const
	{
	double initial_estimate = 2 * (log(1.04) - log(error)) / log(2);
	int answer = (int)floor(initial_estimate);

	// k is the number of standard deviations that we have to go to have
	// a confidence level of conf.

	double k = 0;

	do
		{
		answer++;
		k = pow(2, (answer - initial_estimate) / 2);
		} while ( erf(k / sqrt(2)) < confidence );

	return answer;
	}

void CardinalityCounter::Init(uint64_t size)
	{
	m = size;

	// The following magic values are taken directly out of the
	// description of the HyperLogLog algorithm.

	if ( m == 16 )
		alpha_m = 0.673;

	else if ( m == 32 )
		alpha_m = 0.697;

	else if ( m == 64 )
		alpha_m = 0.709;

	else if ( m >= 128 )
		alpha_m = 0.7213 / (1 + 1.079 / m);

	else
		reporter->InternalError(
			"Invalid size %" PRIu64 ". Size either has to be 16, 32, 64 or bigger than 128", size);

	double calc_p = log2(m);
	if ( trunc(calc_p) != calc_p )
		reporter->InternalError("Invalid size %" PRIu64 ". Size either has to be a power of 2",
		                        size);

	p = calc_p;

	buckets.reserve(m);
	for ( uint64_t i = 0; i < m; i++ )
		buckets.push_back(0);

	assert(buckets.size() == m);

	V = m;
	}

CardinalityCounter::CardinalityCounter(CardinalityCounter& other) : buckets(other.buckets)
	{
	V = other.V;
	alpha_m = other.alpha_m;
	m = other.m;
	p = other.p;
	}

CardinalityCounter::CardinalityCounter(CardinalityCounter&& o) noexcept
	{
	V = o.V;
	alpha_m = o.alpha_m;
	m = o.m;
	p = o.p;

	o.m = 0;
	buckets = std::move(o.buckets);
	}

CardinalityCounter::CardinalityCounter(double error_margin, double confidence)
	{
	int b = OptimalB(error_margin, confidence);
	Init((uint64_t)pow(2, b));

	assert(b == p);
	}

CardinalityCounter::CardinalityCounter(uint64_t size)
	{
	Init(size);
	}

CardinalityCounter::CardinalityCounter(uint64_t arg_size, uint64_t arg_V, double arg_alpha_m)
	{
	m = arg_size;

	buckets.reserve(m);
	for ( uint64_t i = 0; i < m; i++ )
		buckets.push_back(0);

	alpha_m = arg_alpha_m;
	V = arg_V;
	p = log2(m);
	}

CardinalityCounter::~CardinalityCounter() { }

uint8_t CardinalityCounter::Rank(uint64_t hash_modified) const
	{
	hash_modified = hash_modified >> p;
	int answer = 64 - p - CardinalityCounter::flsll(hash_modified) + 1;
	assert(answer > 0 && answer < 64);

	return answer;
	}

void CardinalityCounter::AddElement(uint64_t hash)
	{
	uint64_t index = hash % m;
	hash = hash - index;

	if ( buckets[index] == 0 )
		V--;

	uint8_t temp = Rank(hash);

	if ( temp > buckets[index] )
		buckets[index] = temp;
	}

/**
 * Estimate the size by using the "raw" HyperLogLog estimate. Then,
 * check if it's too "large" or "small" because the raw estimate doesn't
 * do well in those cases.
 * Thus, we correct for those errors as specified in the paper.
 *
 * Note - we deviate from the HLL algorithm in the paper here, because
 * of our 64-bit hashes.
 **/
double CardinalityCounter::Size() const
	{
	double answer = 0;
	for ( unsigned int i = 0; i < m; i++ )
		answer += pow(2, -((int)buckets[i]));

	answer = 1 / answer;
	answer = (alpha_m * m * m * answer);

	if ( answer <= 5.0 * (m / 2) )
		return m * log(((double)m) / V);

	else if ( answer <= (pow(2, 64) / 30) )
		return answer;

	else
		return -pow(2, 64) * log(1 - (answer / pow(2, 64)));
	}

bool CardinalityCounter::Merge(CardinalityCounter* c)
	{
	if ( m != c->GetM() )
		return false;

	const std::vector<uint8_t>& temp = c->GetBuckets();

	V = 0;

	for ( size_t i = 0; i < m; i++ )
		{
		if ( temp[i] > buckets[i] )
			buckets[i] = temp[i];

		if ( buckets[i] == 0 )
			++V;
		}

	return true;
	}

const std::vector<uint8_t>& CardinalityCounter::GetBuckets() const
	{
	return buckets;
	}

uint64_t CardinalityCounter::GetM() const
	{
	return m;
	}

broker::expected<broker::data> CardinalityCounter::Serialize() const
	{
	broker::vector v = {m, V, alpha_m};
	v.reserve(3 + m);

	for ( size_t i = 0; i < m; ++i )
		v.emplace_back(static_cast<uint64_t>(buckets[i]));

	return {std::move(v)};
	}

std::unique_ptr<CardinalityCounter> CardinalityCounter::Unserialize(const broker::data& data)
	{
	auto v = broker::get_if<broker::vector>(&data);
	if ( ! (v && v->size() >= 3) )
		return nullptr;

	auto m = broker::get_if<uint64_t>(&(*v)[0]);
	auto V = broker::get_if<uint64_t>(&(*v)[1]);
	auto alpha_m = broker::get_if<double>(&(*v)[2]);

	if ( ! (m && V && alpha_m) )
		return nullptr;
	if ( v->size() != 3 + *m )
		return nullptr;

	auto cc = std::unique_ptr<CardinalityCounter>(new CardinalityCounter(*m, *V, *alpha_m));
	if ( *m != cc->m )
		return nullptr;
	if ( cc->buckets.size() != *m )
		return nullptr;

	for ( size_t i = 0; i < *m; ++i )
		{
		auto x = broker::get_if<uint64_t>(&(*v)[3 + i]);
		if ( ! x )
			return nullptr;

		cc->buckets[i] = *x;
		}

	return cc;
	}

/**
 * The following function is copied from libc/string/flsll.c from the FreeBSD source
 * tree. Original copyright message follows
 */
/*-
 * Copyright (c) 1990, 1993
 *      The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Find Last Set bit
 */
int CardinalityCounter::flsll(uint64_t mask)
	{
	int bit;

	if ( mask == 0 )
		return (0);
	for ( bit = 1; mask != 1; bit++ )
		mask = (uint64_t)mask >> 1;
	return (bit);
	}

	} // namespace zeek::probabilistic::detail

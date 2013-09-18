// See the file "COPYING" in the main distribution directory for copyright.

#include <math.h>
#include <stdint.h>
#include <iostream>

#include "CardinalityCounter.h"
#include "Reporter.h"
#include "Serializer.h"

using namespace probabilistic;

int CardinalityCounter::OptimalB(double error, double confidence) const
	{
	double initial_estimate = 2 * (log(1.04) - log(error)) / log(2);
	int answer = (int) floor(initial_estimate);

	// k is the number of standard deviations that we have to go to have
	// a confidence level of conf.

	double k = 0;

	do {
		answer++;
		k = pow(2, (answer - initial_estimate) / 2);
	} while ( erf(k / sqrt(2)) < confidence );

	return answer;
	}

void CardinalityCounter::Init(uint64 size)
	{
	m = size;
	buckets = new uint8_t[m];

	// The following magic values are taken directly out of the
	// description of the HyperLogLog algorithn.

	if ( m == 16 )
		alpha_m = 0.673;

	else if ( m == 32 )
		alpha_m = 0.697;

	else if ( m == 64 )
		alpha_m = 0.709;

	else if ( m >= 128 )
		alpha_m = 0.7213 / (1 + 1.079 / m);

	else
		reporter->InternalError("Invalid size %" PRIu64 ". Size either has to be 16, 32, 64 or bigger than 128", size);

	for ( uint64 i = 0; i < m; i++ )
		buckets[i] = 0;

	V = m;
	}

CardinalityCounter::CardinalityCounter(CardinalityCounter& other)
	{
	Init(other.GetM());
	Merge(&other);
	}

CardinalityCounter::CardinalityCounter(double error_margin, double confidence)
	{
	int b = OptimalB(error_margin, confidence);
	Init((uint64) pow(2, b));
	}

CardinalityCounter::CardinalityCounter(uint64 size)
	{
	Init(size);
	}

CardinalityCounter::CardinalityCounter(uint64 arg_size, uint64 arg_V, double arg_alpha_m)
	{
	m = arg_size;
	buckets = new uint8_t[m];
	alpha_m = arg_alpha_m;
	V = arg_V;
	}

CardinalityCounter::~CardinalityCounter()
	{
	delete [] buckets;
	}

uint8_t CardinalityCounter::Rank(uint64 hash_modified) const
	{
	uint8_t answer = 0;

	hash_modified = (uint64)(hash_modified / m);
	hash_modified *= 2;

	do {
		hash_modified = (uint64)(hash_modified / 2);
		answer++;
	} while ( hash_modified % 2 == 0);

	return answer;
	}

void CardinalityCounter::AddElement(uint64 hash)
	{
	uint64 index = hash % m;
	hash = hash-index;

	if( buckets[index] == 0 )
		V--;

	uint8_t temp = Rank(hash);

	if ( temp > buckets[index] )
		buckets[index] = temp;
	}

/**
 * Estimate the size by using the the "raw" HyperLogLog estimate. Then,
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

	if ( answer <= 5.0 * (m/2) )
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

	uint8_t* temp = c->GetBuckets();

	V = 0;

	for ( unsigned int i = 0; i < m; i++ )
		{
		if ( temp[i] > buckets[i] )
			buckets[i] = temp[i];

		if ( buckets[i] == 0 )
			++V;
		}

	return true;
	}

uint8_t* CardinalityCounter::GetBuckets()
	{
	return buckets;
	}

uint64 CardinalityCounter::GetM() const
	{
	return m;
	}

bool CardinalityCounter::Serialize(SerialInfo* info) const
	{
	bool valid = true;

	valid &= SERIALIZE(m);
	valid &= SERIALIZE(V);
	valid &= SERIALIZE(alpha_m);

	for ( unsigned int i = 0; i < m; i++ )
		valid &= SERIALIZE((char)buckets[i]);

	return valid;
	}

CardinalityCounter* CardinalityCounter::Unserialize(UnserialInfo* info)
	{
	uint64_t m;
	uint64 V;
	double alpha_m;

	bool valid = true;
	valid &= UNSERIALIZE(&m);
	valid &= UNSERIALIZE(&V);
	valid &= UNSERIALIZE(&alpha_m);

	CardinalityCounter* c = new CardinalityCounter(m, V, alpha_m);

	uint8_t* buckets = c->buckets;

	for ( unsigned int i = 0; i < m; i++ )
		{
		char c;
		valid &= UNSERIALIZE(&c);
		buckets[i] = (uint8)c;
		}

	if ( ! valid )
		{
		delete c;
		c = 0;
		}

	return c;
	}

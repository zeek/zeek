// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/probabilistic/CountMinSketch.h"

#include <algorithm>
#include <cmath>
#include <limits>
#include <random>

#include "zeek/Reporter.h"

namespace zeek::probabilistic
	{

CountMinSketch::CountMinSketch(uint16_t w, uint16_t d)
	{
	using namespace util::detail;
	uint32_t elements = w * d;
	content.resize(elements);

	this->d = d;
	this->w = w;

	// generate uniformly distributed aj, bj from [1..p]
	std::seed_seq seq{random_number(), random_number(), random_number(), random_number(), random_number(), random_number(), random_number(), random_number(), random_number(), random_number(), random_number(), random_number()};
	ab.resize(d);
	std::mt19937_64 gen(seq);
	std::uniform_int_distribution<countms_ab_t> distribution(1, p);
	for ( int i = 0; i < d; i++ )
		{
		ab[i] = {distribution(gen), distribution(gen)};
		}
	}

std::pair<int, int> CountMinSketch::CalculateWD(double epsilon, double delta)
	{
	if ( delta >= 1 || delta <= 0 )
		return {-1, -1};

	if ( epsilon >= 1 )
		return {-1, -1};

	double w = std::ceil(std::exp(1) / epsilon);
	double d = std::ceil(std::log(1 / delta));

	return {w, d};
	}

void CountMinSketch::Update(countms_data_t item, uint16_t c)
	{
	total += c;
	for ( int i = 0; i < d; i++ )
		{
		uint32_t hash = (ab[i].first * item + ab[i].second) % p % w;
		// depth times width + hash
		content[i*w + hash] += c;
		}
	}

void CountMinSketch::Update(const zeek::detail::HashKey* item, uint16_t c)
	{
	// we only use 32 bit of the hash key for now...
	auto hash = item->Hash();
	Update(hash, c);
	}

uint32_t CountMinSketch::Estimate(countms_data_t item)
	{
	uint32_t e = std::numeric_limits<uint32_t>::max();
	for ( int i = 0; i < d; i++ )
		{
		uint32_t hash = (ab[i].first * item + ab[i].second) % p % w;
		// depth times width + hash
		e = std::min(e, content[i * w + hash]);
		}
	return e;
	}

uint32_t CountMinSketch::Estimate(const zeek::detail::HashKey* item)
	{
	auto hash = item->Hash();
	return Estimate(hash);
	}
	}

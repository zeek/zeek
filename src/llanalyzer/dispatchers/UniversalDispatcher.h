// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <random>
#include "Dispatcher.h"

namespace zeek::llanalyzer {

class UniversalDispatcher : public Dispatcher {
public:
	UniversalDispatcher();
	~UniversalDispatcher() override;

	bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) override;
	void Register(const register_map& data) override;
	Value* Lookup(identifier_t identifier) const override;
	size_t Size() const override;
	void Clear() override;

	void DumpDebug() const override;
	size_t BucketCount();

	// Rehashes the hash table including re-randomization of the hash function.
	void Rehash();

private:
	using pair_t = std::pair<identifier_t, Value*>;
	static const uint64_t ONE = 1u;

	// Chosen random constants for the currently selected collision free random hash function
	uint64_t a = 0; // Needs to be a random odd positive value < 2^(sizeof(uint64_t) * 8)
	uint64_t b = 0; // Needs to be a random non-negative value < 2^(((sizeof(uint64_t) * 8) - M)

	// Current bits that define the number of bins. Initially 2 which means there are 2^2 = 4 bins.
	uint64_t m = 2;

	// Current shift value which is the number of bits that are "insignificant" because of the universe size.
	uint64_t w_minus_m = 0;

	// RNG
	std::random_device rd;
	std::mt19937_64 generator;
	std::uniform_int_distribution<uint64_t> distribution_a;
	std::uniform_int_distribution<uint64_t> distribution_b;

// Debug
#if DEBUG > 0
	size_t nptr_counter = 0;
	size_t mismatch_counter = 0;
	size_t all_counter = 0;
#endif

	std::vector<pair_t> table;

	void FreeValues();

	void Rehash(const std::vector<pair_t>& intermediate);

	/**
	 * Tries to find a collision free hash function with the current number of buckets.
	 *
	 * @param intermediate The key-value set to store in the hashtable.
	 * @return true, iff it found a collision-free hash function.
	 */
	bool FindCollisionFreeHashFunction(const std::vector<pair_t>& intermediate);

	[[nodiscard]] inline uint64_t Hash(const uint64_t value) const
		{
		return (a * value + b) >> w_minus_m;
		}

	inline void RandomizeAB()
		{
		do {
			a = distribution_a(generator);
			} while ( a % 2 == 0 );

		b = distribution_b(generator);
		}

	inline void SetBins(uint64_t new_m)
		{
		if ( new_m > (sizeof(uint64_t) * 8) )
			throw std::runtime_error("Number of bits for bin count too large.");

		m = new_m;
		w_minus_m = sizeof(uint64_t) * 8 - m;
		distribution_b = std::uniform_int_distribution<uint64_t>(0, ((uint64_t)(1u) << w_minus_m) - (uint64_t)(1u));
		}

	inline std::vector<pair_t> CreateIntermediate()
		{
		std::vector<pair_t> intermediate;
		for ( const auto& current : table )
			{
			if ( current.second != nullptr )
				{
				assert(current.second->analyzer != nullptr);
				intermediate.emplace_back(current.first, current.second);
				}
			}
		return intermediate;
		}

};

}

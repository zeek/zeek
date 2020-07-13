// See the file "COPYING" in the main distribution directory for copyright.

#include "UniversalDispatcher.h"

namespace zeek::packet_analysis {

UniversalDispatcher::UniversalDispatcher() : generator(rd())
	{
	SetBins(2);

	table = std::vector<pair_t>(ONE << m, {0, nullptr});

	// Initialize random engine
	distribution_a = std::uniform_int_distribution<uint64_t>(1, ~static_cast<uint64_t>(0));
	distribution_b = std::uniform_int_distribution<uint64_t>(0, (ONE << w_minus_m) - ONE);

	// Initialize random parameters
	RandomizeAB();
	}

UniversalDispatcher::~UniversalDispatcher()
	{
	FreeValues();
	}

bool UniversalDispatcher::Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher)
	{
#if DEBUG > 1
	std::shared_ptr<void> deferred(nullptr, [=](...) {
		                                        std::cout << "Inserted " << identifier << std::endl;
		                                        });
#endif

	uint64_t hashed_id = Hash(identifier);
	if ( table[hashed_id].second == nullptr )
		{
		// Free bin, insert the value
		table[hashed_id] = std::make_pair(identifier, new Value(analyzer, dispatcher));
		return true;
		}
	else if ( table[hashed_id].first != identifier )
		{
		// The bin is not empty, but the content isn't the to-be-inserted identifier --> resolve collision

		// Create intermediate representation with the new element in it, then rehash with that data
		std::vector<pair_t> intermediate = CreateIntermediate();
		intermediate.emplace_back(identifier, new Value(analyzer, dispatcher));

		// Try increasing the #bins until it works or it can't get any larger.
		Rehash(intermediate);
		return true;
		}

	// Analyzer with this ID is already registered.
	return false;
	}

void UniversalDispatcher::Register(const register_map& data)
	{
	// Analyzer already registered
	for ( const auto& current : data )
		{
		if ( table[Hash(current.first)].second != nullptr )
			throw std::invalid_argument("Analyzer " + std::to_string(current.first) + " already registered!");
		}

	// Create intermediate representation of current analyzer set, then add all new ones
	std::vector<pair_t> intermediate = CreateIntermediate();
	for ( const auto& current : data )
		intermediate.emplace_back(current.first, new Value(current.second.first, current.second.second));

	Rehash(intermediate);
	}

Value* UniversalDispatcher::Lookup(identifier_t identifier) const
	{
	uint64_t hashed_id = Hash(identifier);

	// The hashed_id can't be larger than the number of bins
	assert(hashed_id < table.size() && "Hashed ID is outside of the hash table range!");

	pair_t entry = table[hashed_id];
	if ( entry.second != nullptr && entry.first == identifier )
		return entry.second;

	return nullptr;
	}

size_t UniversalDispatcher::Size() const
	{
	size_t result = 0;
	for ( const auto& current : table )
		{
		if ( current.second != nullptr )
			result++;
		}
	return result;
	}

void UniversalDispatcher::Clear()
	{
	// Free all analyzers
	FreeValues();

	SetBins(2);
	table = std::vector<pair_t>(ONE << m, {0, nullptr});
	RandomizeAB();
	}

size_t UniversalDispatcher::BucketCount()
	{
	return table.size();
	}

void UniversalDispatcher::Rehash()
	{
	// Intermediate representation is just the current table without nulls
	Rehash(CreateIntermediate());
	}

void UniversalDispatcher::DumpDebug() const
	{
#ifdef DEBUG
	DBG_LOG(DBG_PACKET_ANALYSIS, "  Dispatcher elements (used/total): %lu/%lu", Size(), table.size());
	for ( size_t i = 0; i < table.size(); i++ )
		{
		if ( table[i].second != nullptr )
			DBG_LOG(DBG_PACKET_ANALYSIS, "    %#8x => %s, %p", table[i].first, table[i].second->analyzer->GetAnalyzerName(), table[i].second->dispatcher);
		}
#endif
	}

// #######################
// ####### PRIVATE #######
// #######################

void UniversalDispatcher::FreeValues()
	{
	for ( auto& current : table )
		{
		delete current.second;
		current.second = nullptr;
		}
	}

void UniversalDispatcher::Rehash(const std::vector<pair_t>& intermediate)
	{
	while ( ! FindCollisionFreeHashFunction(intermediate) )
		{
		DBG_LOG(DBG_PACKET_ANALYSIS, "Rehashing did not work. Increasing #bins to %" PRIu64 " (%" PRIu64 " bit).", (uint64_t)std::pow(2, m + 1), m + 1);
		SetBins(m + 1);
		}
	}

bool UniversalDispatcher::FindCollisionFreeHashFunction(const std::vector<pair_t>& intermediate)
	{
	// Don't even try if the number of values is larger than the number of buckets
	if ( ONE << m < intermediate.size() )
		return false;

	// Remember the hash function parameters to not break the table if rehashing doesn't work
	uint64_t stored_a = a;
	uint64_t stored_b = b;

	// Because the hash function hashes all values in the universe uniformly to m bins with probability 1/m
	// we should at least try a multiple of #bins times.
	for ( size_t i = 1; i <= (ONE << m); i++ )
		{
		// Step 1: Re-randomize hash function parameters
		RandomizeAB();

		// Step 2: Create new table
		std::vector<pair_t> new_table(ONE << m, {0, nullptr});

		// Step 3: Try to insert all elements into the new table with the new hash function
		bool finished = true;
		for ( const auto& current : intermediate )
			{
			uint64_t hashed_id = Hash(current.first);
			assert(hashed_id < new_table.size());
			if ( new_table[hashed_id].second == nullptr )
				{
				// Free bin, insert the value
				new_table[hashed_id] = current;
				}
			else
				{
				// The bin is not empty which means there is a collision
				// (there are no duplicates in the intermediate representation so that can't be the case)
				finished = false;
				break;
				}
			}

		// Step 4: If the inserting finished without collisions, overwrite the previous table and exit
		if ( finished )
			{
			DBG_LOG(DBG_PACKET_ANALYSIS, "Took %lu rehash(es) to resolve.", i);
			table = new_table;
			return true;
			}
		}

	// Finding a collision free hash function failed. Revert the hash function parameters.
	a = stored_a;
	b = stored_b;
	return false;
	}

}

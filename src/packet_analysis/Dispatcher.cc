// See the file "COPYING" in the main distribution directory for copyright.

#include <algorithm>

#include "Dispatcher.h"
#include "Analyzer.h"
#include "DebugLogger.h"

namespace zeek::packet_analysis {

Dispatcher::~Dispatcher()
	{
	FreeValues();
	}

bool Dispatcher::Register(uint32_t identifier, AnalyzerPtr analyzer)
	{
	// If the table has size 1 and the entry is nullptr, there was nothing added yet. Just add it.
	if ( table.size() == 1 && table[0] == nullptr )
		{
		table[0] = analyzer;
		lowest_identifier = identifier;
		return true;
		}

	// If highestIdentifier == identifier, overwrite would happen -> no check needed, will return false
	if ( GetHighestIdentifier() < identifier )
		{
		table.resize(table.size() + (identifier - GetHighestIdentifier()), nullptr);
		}
	else if ( identifier < lowest_identifier )
		{
		// Lower than the lowest registered identifier. Shift up by lowerBound - identifier
		uint32_t distance = lowest_identifier - identifier;
		table.resize(table.size() + distance, nullptr);

		// Shift values
		for ( ssize_t i = table.size() - 1; i >= 0; i-- )
			{
			if ( table[i] != nullptr )
				{
				table.at(i + distance) = table.at(i);
				table.at(i) = nullptr;
				}
			}

		lowest_identifier = identifier;
		}

	int64_t index = identifier - lowest_identifier;
	if ( table[index] == nullptr )
		{
		table[index] = analyzer;
		return true;
		}

	return false;
	}

void Dispatcher::Register(const register_map& data)
	{
	// Search smallest and largest identifier and resize vector
	const auto& lowest_new =
		std::min_element(data.begin(), data.end(),
		                 [](const register_pair& a, const register_pair& b) {
			                 return a.first < b.first;
			                 });

	// Register lowest first in order to do shifting only once
	Register(lowest_new->first, lowest_new->second);
	for ( auto i = data.begin(); i != data.end(); i++ )
		{
		// Already added if i == lowest_new
		if ( i == lowest_new )
			continue;

		if ( ! Register(i->first, i->second) )
			throw std::invalid_argument("Analyzer already registered!");
		}
	}

AnalyzerPtr Dispatcher::Lookup(uint32_t identifier) const
	{
	int64_t index = identifier - lowest_identifier;
	if ( index >= 0 && index < static_cast<int64_t>(table.size()) && table[index] != nullptr )
		return table[index];

	return nullptr;
	}

size_t Dispatcher::Size() const
	{
	return std::count_if(table.begin(), table.end(), [](AnalyzerPtr a) { return a != nullptr; });
	}

void Dispatcher::Clear()
	{
	FreeValues();
	table.clear();
	}

void Dispatcher::FreeValues()
	{
	for ( auto& current : table )
		current = nullptr;
	}

void Dispatcher::DumpDebug() const
	{
#ifdef DEBUG
	DBG_LOG(DBG_PACKET_ANALYSIS, "  Dispatcher elements (used/total): %lu/%lu", Size(), table.size());
	DBG_LOG(DBG_PACKET_ANALYSIS, "TABLE SIZE %lu", table.size());
	for ( size_t i = 0; i < table.size(); i++ )
		{
		if ( table[i] != nullptr )
			DBG_LOG(DBG_PACKET_ANALYSIS, "    %#8lx => %s", i+lowest_identifier, table[i]->GetAnalyzerName());
		}
#endif
	}

}

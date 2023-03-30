// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/Dispatcher.h"

#include <algorithm>

#include "zeek/DebugLogger.h"
#include "zeek/Reporter.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis
	{

Dispatcher::~Dispatcher()
	{
	FreeValues();
	}

void Dispatcher::Register(uint32_t identifier, AnalyzerPtr analyzer)
	{
	// If the table has size 1 and the entry is nullptr, there was nothing added yet. Just add it.
	if ( table.size() == 1 && table[0] == nullptr )
		{
		table[0] = std::move(analyzer);
		lowest_identifier = identifier;
		return;
		}

	// If highestIdentifier == identifier, overwrite would happen -> no check needed, will return
	// false
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
				table.at(i + distance) = std::move(table.at(i));
				table.at(i) = nullptr;
				}
			}

		lowest_identifier = identifier;
		}

	int64_t index = identifier - lowest_identifier;
	if ( table[index] != nullptr )
		reporter->Info("Overwriting packet analyzer mapping %#8" PRIx64 " => %s with %s",
		               index + lowest_identifier, table[index]->GetAnalyzerName(),
		               analyzer->GetAnalyzerName());
	table[index] = std::move(analyzer);
	}

AnalyzerPtr Dispatcher::Lookup(uint32_t identifier) const
	{
	int64_t index = identifier - lowest_identifier;
	if ( index >= 0 && index < static_cast<int64_t>(table.size()) && table[index] != nullptr )
		return table[index];

	return nullptr;
	}

size_t Dispatcher::Count() const
	{
	return std::count_if(table.begin(), table.end(),
	                     [](AnalyzerPtr a)
	                     {
							 return a != nullptr;
						 });
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
	DBG_LOG(DBG_PACKET_ANALYSIS, "Dispatcher elements (used/total): %lu/%lu", Count(),
	        table.size());
	for ( size_t i = 0; i < table.size(); i++ )
		{
		if ( table[i] != nullptr )
			DBG_LOG(DBG_PACKET_ANALYSIS, "%#8lx => %s", i + lowest_identifier,
			        table[i]->GetAnalyzerName());
		}
#endif
	}

	}

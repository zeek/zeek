// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <vector>

namespace zeek::packet_analysis
	{

class Analyzer; // Forward declaration for Value
using AnalyzerPtr = std::shared_ptr<zeek::packet_analysis::Analyzer>;

/**
 * The Dispatcher class manages identifier-to-analyzer mappings.
 */
class Dispatcher
	{
public:
	Dispatcher() : table(std::vector<AnalyzerPtr>(1, nullptr)){};
	~Dispatcher();

	/**
	 * Register an analyzer for a given identifier.
	 *
	 * @param identifier The identifier.
	 * @param analyzer The analyzer to register.
	 */
	void Register(uint32_t identifier, AnalyzerPtr analyzer);

	/**
	 * Looks up the analyzer for an identifier.
	 *
	 * @param identifier The identifier to look up.
	 * @return The analyzer registered for the given identifier. Returns a
	 * nullptr if no analyzer is registered.
	 */
	AnalyzerPtr Lookup(uint32_t identifier) const;

	/**
	 * Returns the number of registered analyzers.
	 * @return Number of registered analyzers.
	 */
	size_t Count() const;

	/**
	 * Removes all mappings from the dispatcher.
	 */
	void Clear();

	/**
	 * Dumps out the data structure to the \c analyzer debug stream.
	 */
	void DumpDebug() const;

private:
	uint32_t lowest_identifier = 0;
	std::vector<AnalyzerPtr> table;

	void FreeValues();

	inline uint32_t GetHighestIdentifier() const { return lowest_identifier + table.size() - 1; }
	};

	}

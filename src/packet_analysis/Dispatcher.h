// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <map>
#include <cstdint>
#include <vector>

namespace zeek::packet_analysis {

class Analyzer; // Forward declaration for Value
using AnalyzerPtr = std::shared_ptr<zeek::packet_analysis::Analyzer>;

using register_pair = std::pair<uint32_t, AnalyzerPtr>;
using register_map = std::map<uint32_t, AnalyzerPtr>;

class Dispatcher {
public:
	Dispatcher()
		: table(std::vector<AnalyzerPtr>(1, nullptr))
		{ }

	~Dispatcher();

	bool Register(uint32_t identifier, AnalyzerPtr analyzer);
	void Register(const register_map& data);

	AnalyzerPtr Lookup(uint32_t identifier) const;

	size_t Size() const;
	void Clear();
	void DumpDebug() const;

private:
	uint32_t lowest_identifier = 0;
	std::vector<AnalyzerPtr> table;

	void FreeValues();

	inline uint32_t GetHighestIdentifier() const
		{
		return lowest_identifier + table.size() - 1;
		}
};

}

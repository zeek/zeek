// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <utility>
#include <vector>
#include "Analyzer.h"

namespace zeek::packet_analysis {

class Dispatcher; // Forward decl for Value
using DispatcherPtr = std::shared_ptr<Dispatcher>;

using register_pair = std::pair<identifier_t, std::pair<AnalyzerPtr, DispatcherPtr>>;
using register_map = std::map<identifier_t, std::pair<AnalyzerPtr, DispatcherPtr>>;

class Value {
public:
	AnalyzerPtr analyzer;
	DispatcherPtr dispatcher;

	Value(AnalyzerPtr analyzer, DispatcherPtr dispatcher)
		: analyzer(analyzer), dispatcher(dispatcher)
		{
		}
};

using ValuePtr = std::shared_ptr<Value>;

class Dispatcher {
public:
	Dispatcher()
		: table(std::vector<ValuePtr>(1, nullptr))
		{ }

	~Dispatcher();

	bool Register(identifier_t identifier, AnalyzerPtr analyzer, DispatcherPtr dispatcher);
	void Register(const register_map& data);

	ValuePtr Lookup(identifier_t identifier) const;

	size_t Size() const;
	void Clear();
	void DumpDebug() const;

private:
	identifier_t lowest_identifier = 0;
	std::vector<ValuePtr> table;

	void FreeValues();

	inline identifier_t GetHighestIdentifier() const
		{
		return lowest_identifier + table.size() - 1;
		}
};

}

// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <utility>
#include "Dispatcher.h"

namespace zeek::packet_analysis {

class VectorDispatcher : public Dispatcher {
public:
	VectorDispatcher()
		: table(std::vector<ValuePtr>(1, nullptr))
		{ }

	~VectorDispatcher() override;

	bool Register(identifier_t identifier, AnalyzerPtr analyzer, DispatcherPtr dispatcher) override;
	void Register(const register_map& data) override;

	ValuePtr Lookup(identifier_t identifier) const override;

	size_t Size() const override;
	void Clear() override;

protected:
	void DumpDebug() const override;

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

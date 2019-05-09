// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <utility>
#include "Dispatcher.h"

namespace zeek::llanalyzer {

class VectorDispatcher : public Dispatcher {
public:
	VectorDispatcher()
		: table(std::vector<Value*>(1, nullptr))
		{ }

	~VectorDispatcher() override;

	bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) override;
	void Register(const register_map& data) override;

	const Value* Lookup(identifier_t identifier) const override;

	size_t Size() const override;
	void Clear() override;

protected:
	void DumpDebug() const override;

private:
	identifier_t lowest_identifier = 0;
	std::vector<Value*> table;

	void FreeValues();

	inline identifier_t GetHighestIdentifier() const
		{
		return lowest_identifier + table.size() - 1;
		}
};

}

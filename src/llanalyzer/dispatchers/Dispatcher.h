// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>
#include <utility>

#include "Analyzer.h"
#include "Defines.h"

namespace zeek::llanalyzer {

class Dispatcher; // Forward decl for Value
using register_pair = std::pair<identifier_t, std::pair<Analyzer*, Dispatcher*>>;
using register_map = std::map<identifier_t, std::pair<Analyzer*, Dispatcher*>>;

class Value {
public:
	Analyzer* analyzer;
	Dispatcher* dispatcher;

	Value(Analyzer* analyzer, Dispatcher* dispatcher)
		: analyzer(analyzer), dispatcher(dispatcher)
		{
		}
};

class Dispatcher {
public:
	virtual ~Dispatcher() = default;

	virtual bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) = 0;
	virtual void Register(const register_map& data)
		{
		for ( auto& current : data )
			Register(current.first, current.second.first, current.second.second);
		}

	virtual const Value* Lookup(identifier_t identifier) const = 0;

	virtual size_t Size() const = 0;
	virtual void Clear() = 0;

	virtual void DumpDebug() const = 0;
	};

}

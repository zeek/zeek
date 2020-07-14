// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <map>
#include <utility>

#include "Analyzer.h"
#include "Defines.h"

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
	virtual ~Dispatcher() = default;

	virtual bool Register(identifier_t identifier, AnalyzerPtr analyzer, DispatcherPtr dispatcher) = 0;
	virtual void Register(const register_map& data)
		{
		for ( auto& current : data )
			Register(current.first, current.second.first, current.second.second);
		}

	virtual ValuePtr Lookup(identifier_t identifier) const = 0;

	virtual size_t Size() const = 0;
	virtual void Clear() = 0;

	virtual void DumpDebug() const = 0;
	};

}

// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "Analyzer.h"
#include "Defines.h"

namespace zeek::llanalyzer {

class Analyzer;

class AnalyzerSet {
public:
	virtual ~AnalyzerSet() = default;
	virtual Analyzer* Dispatch(identifier_t identifier) = 0;
	virtual void Reset() = 0;

protected:
	friend class Manager;

	virtual void DumpDebug() const = 0;
};

}

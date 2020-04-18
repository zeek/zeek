#pragma once

class Connection;
class Val;
class PortVal;

namespace analyzer { class Analyzer; }

#include "util.h"
#include "Val.h"
#include "IntrusivePtr.h"
#include "event.bif.func_h"
#include "analyzer/Analyzer.h"
#include "file_analysis/Analyzer.h"

#include "binpac.h"

namespace binpac {

typedef analyzer::Analyzer* BroAnalyzer;
typedef file_analysis::Analyzer BroFileAnalyzer;
typedef Val* BroVal;
typedef PortVal* BroPortVal;
typedef StringVal* BroStringVal;

inline StringVal* string_to_val(string const &str)
	{
	return new StringVal(str.c_str());
	}

inline StringVal* bytestring_to_val(const_bytestring const &str)
	{
	return new StringVal(str.length(), (const char*) str.begin());
	}

inline IntrusivePtr<StringVal> to_stringval(const_bytestring const& str)
    {
	return make_intrusive<StringVal>(str.length(), (const char*) str.begin());
    }

} // namespace binpac

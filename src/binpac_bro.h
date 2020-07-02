#pragma once

#include "util.h"
#include "Val.h"
#include "IntrusivePtr.h"
#include "analyzer/Analyzer.h"
#include "file_analysis/Analyzer.h"
#include "event.bif.func_h"

#include "binpac.h"

namespace binpac {

using BroAnalyzer = zeek::analyzer::Analyzer*;
using BroFileAnalyzer = file_analysis::Analyzer;
using BroVal = zeek::Val*;
using BroPortVal = zeek::PortVal*;
using BroStringVal = zeek::StringVal*;

[[deprecated("Remove in v4.1.  Use StringVal constructor directly.")]]
inline zeek::StringVal* string_to_val(string const &str)
	{
	return new zeek::StringVal(str.c_str());
	}

[[deprecated("Remove in v4.1.  Use binpac::to_stringval() instead.")]]
inline zeek::StringVal* bytestring_to_val(const_bytestring const &str)
	{
	return new zeek::StringVal(str.length(), (const char*) str.begin());
	}

inline zeek::StringValPtr to_stringval(const_bytestring const& str)
    {
	return zeek::make_intrusive<zeek::StringVal>(str.length(), (const char*) str.begin());
    }

zeek::StringValPtr utf16_to_utf8_val(Connection* conn, const bytestring& utf16);

[[deprecated("Remove in v4.1.  Use utf16_to_utf8_val() instead.")]]
zeek::StringVal* utf16_bytestring_to_utf8_val(Connection* conn, const bytestring& utf16);

} // namespace binpac

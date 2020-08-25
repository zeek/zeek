#pragma once

#include "util.h"
#include "Val.h"
#include "IntrusivePtr.h"
#include "analyzer/Analyzer.h"
#include "file_analysis/Analyzer.h"
#include "event.bif.func_h"

#include "binpac.h"

namespace binpac {

using ZeekAnalyzer = zeek::analyzer::Analyzer*;
using ZeekFileAnalyzer = zeek::file_analysis::Analyzer;
using ZeekVal = zeek::Val*;
using ZeekPortVal = zeek::PortVal*;
using ZeekStringVal = zeek::StringVal*;

using BroAnalyzer [[deprecated("Remove in v4.1. Use ZeekAnalyzer.")]] = ZeekAnalyzer;
using BroFileAnalyzer [[deprecated("Remove in v4.1. Use ZeekFileAnalyzer.")]] = ZeekFileAnalyzer;
using BroVal [[deprecated("Remove in v4.1. Use ZeekVal.")]] = ZeekVal;
using BroPortVal [[deprecated("Remove in v4.1. Use ZeekPortVal.")]] = ZeekPortVal;
using BroStringVal [[deprecated("Remove in v4.1. Use ZeekStringVal.")]] = ZeekStringVal;

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

zeek::StringValPtr utf16_to_utf8_val(zeek::Connection* conn, const bytestring& utf16);

[[deprecated("Remove in v4.1.  Use utf16_to_utf8_val() instead.")]]
zeek::StringVal* utf16_bytestring_to_utf8_val(zeek::Connection* conn, const bytestring& utf16);

} // namespace binpac

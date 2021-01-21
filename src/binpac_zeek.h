#pragma once

#include <binpac.h>

#include "zeek/util.h"
#include "zeek/Val.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/file_analysis/Analyzer.h"
#include "event.bif.func_h"

namespace binpac {

using ZeekAnalyzer = zeek::analyzer::Analyzer*;
using ZeekFileAnalyzer = zeek::file_analysis::Analyzer;
using ZeekVal = zeek::Val*;
using ZeekPortVal = zeek::PortVal*;
using ZeekStringVal = zeek::StringVal*;

inline zeek::StringValPtr to_stringval(const_bytestring const& str)
    {
	return zeek::make_intrusive<zeek::StringVal>(str.length(), (const char*) str.begin());
    }

zeek::StringValPtr utf16_to_utf8_val(zeek::Connection* conn, const bytestring& utf16);

} // namespace binpac

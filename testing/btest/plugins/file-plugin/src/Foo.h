
#pragma once

#include <Val.h>
#include <file_analysis/Analyzer.h>

namespace btest::plugin::Demo_Foo
	{

class Foo : public zeek::file_analysis::Analyzer
	{
public:
	virtual bool DeliverStream(const u_char* data, uint64_t len);

	static zeek::file_analysis::Analyzer* Instantiate(zeek::RecordValPtr args,
	                                                  zeek::file_analysis::File* file);

protected:
	Foo(zeek::RecordValPtr args, zeek::file_analysis::File* file);
	};

	}

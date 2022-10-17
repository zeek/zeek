#include "Foo.h"

#include <zeek/file_analysis/File.h>
#include <zeek/file_analysis/Manager.h>
#include <algorithm>

#include "events.bif.h"

using namespace btest::plugin::Demo_Foo;

Foo::Foo(zeek::RecordValPtr args, zeek::file_analysis::File* file)
	: zeek::file_analysis::Analyzer(zeek::file_mgr->GetComponentTag("FOO"), std::move(args), file)
	{
	}

zeek::file_analysis::Analyzer* Foo::Instantiate(zeek::RecordValPtr args,
                                                zeek::file_analysis::File* file)
	{
	return new Foo(std::move(args), file);
	}

bool Foo::DeliverStream(const u_char* data, uint64_t len)
	{
	static int i = 0;
	AnalyzerConfirmation();
	zeek::event_mgr.Enqueue(foo_piece, GetFile()->ToVal(),
	                        zeek::make_intrusive<zeek::StringVal>(new zeek::String(data, len, 0)));
	if ( ++i % 3 == 0 )
		{
		uint64_t threshold = 16;
		AnalyzerViolation(zeek::util::fmt("test violation %d", i),
		                  reinterpret_cast<const char*>(data), std::min(len, threshold));
		}

	return true;
	}

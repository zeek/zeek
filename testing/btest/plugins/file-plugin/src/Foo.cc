
#include "Foo.h"
#include "file_analysis/File.h"

#include <events.bif.h>
#include <file_analysis/Manager.h>

using namespace btest::plugin::Demo_Foo;

Foo::Foo(zeek::RecordValPtr args, zeek::file_analysis::File* file)
	: zeek::file_analysis::Analyzer(zeek::file_mgr->GetComponentTag("FOO"), std::move(args), file)
	{
	}

zeek::file_analysis::Analyzer* Foo::Instantiate(zeek::RecordValPtr args, zeek::file_analysis::File* file)
	{
	return new Foo(std::move(args), file);
	}

bool Foo::DeliverStream(const u_char* data, uint64_t len)
	{
	zeek::event_mgr.Enqueue(foo_piece,
	                        GetFile()->ToVal(),
	                        zeek::make_intrusive<zeek::StringVal>(new zeek::String(data, len, 0)));
    return true;
    }

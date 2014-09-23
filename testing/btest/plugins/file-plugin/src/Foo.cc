
#include "Foo.h"
#include <events.bif.h>
#include <file_analysis/Manager.h>

using namespace plugin::Demo_Foo;

Foo::Foo(RecordVal* args, file_analysis::File* file)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("FOO"), args, file)
	{
	}

file_analysis::Analyzer* Foo::Instantiate(RecordVal* args, file_analysis::File* file)
	{
	return new Foo(args, file);
	}

bool Foo::DeliverStream(const u_char* data, uint64 len)
	{
	val_list* args = new val_list;
	args->append(GetFile()->GetVal()->Ref());
	args->append(new StringVal(new BroString(data, len, 0)));
	mgr.QueueEvent(foo_piece, args);
    return true;
    }


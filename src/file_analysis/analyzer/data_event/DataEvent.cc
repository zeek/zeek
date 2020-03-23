// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "DataEvent.h"
#include "EventRegistry.h"
#include "Event.h"
#include "Func.h"
#include "util.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

DataEvent::DataEvent(RecordVal* args, File* file,
                     EventHandlerPtr ce, EventHandlerPtr se)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("DATA_EVENT"),
	                          args, file),
	chunk_event(ce), stream_event(se)
	{
	}

file_analysis::Analyzer* DataEvent::Instantiate(RecordVal* args, File* file)
	{
	auto chunk_val = args->Lookup("chunk_event");
	auto stream_val = args->Lookup("stream_event");

	if ( ! chunk_val && ! stream_val ) return 0;

	EventHandlerPtr chunk;
	EventHandlerPtr stream;

	if ( chunk_val )
		chunk = event_registry->Lookup(chunk_val->AsFunc()->Name());

	if ( stream_val )
		stream = event_registry->Lookup(stream_val->AsFunc()->Name());

	return new DataEvent(args, file, chunk, stream);
	}

bool DataEvent::DeliverChunk(const u_char* data, uint64_t len, uint64_t offset)
	{
	if ( ! chunk_event ) return true;

	mgr.QueueEventFast(chunk_event, {
		GetFile()->GetVal()->Ref(),
		new StringVal(new BroString(data, len, 0)),
		val_mgr->GetCount(offset),
	});

	return true;
	}

bool DataEvent::DeliverStream(const u_char* data, uint64_t len)
	{
	if ( ! stream_event ) return true;

	mgr.QueueEventFast(stream_event, {
		GetFile()->GetVal()->Ref(),
		new StringVal(new BroString(data, len, 0)),
	});

	return true;
	}

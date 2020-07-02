// See the file "COPYING" in the main distribution directory for copyright.

#include <string>

#include "DataEvent.h"
#include "EventRegistry.h"
#include "Event.h"
#include "Func.h"
#include "util.h"
#include "file_analysis/Manager.h"

using namespace file_analysis;

DataEvent::DataEvent(zeek::RecordValPtr args, File* file,
                     EventHandlerPtr ce, EventHandlerPtr se)
    : file_analysis::Analyzer(file_mgr->GetComponentTag("DATA_EVENT"),
	                          std::move(args), file),
	chunk_event(ce), stream_event(se)
	{
	}

file_analysis::Analyzer* DataEvent::Instantiate(zeek::RecordValPtr args,
                                                File* file)
	{
	const auto& chunk_val = args->GetField("chunk_event");
	const auto& stream_val = args->GetField("stream_event");

	if ( ! chunk_val && ! stream_val ) return nullptr;

	EventHandlerPtr chunk;
	EventHandlerPtr stream;

	if ( chunk_val )
		chunk = event_registry->Lookup(chunk_val->AsFunc()->Name());

	if ( stream_val )
		stream = event_registry->Lookup(stream_val->AsFunc()->Name());

	return new DataEvent(std::move(args), file, chunk, stream);
	}

bool DataEvent::DeliverChunk(const u_char* data, uint64_t len, uint64_t offset)
	{
	if ( ! chunk_event ) return true;

	mgr.Enqueue(chunk_event,
	            GetFile()->ToVal(),
	            zeek::make_intrusive<zeek::StringVal>(new zeek::BroString(data, len, false)),
	            zeek::val_mgr->Count(offset)
	);

	return true;
	}

bool DataEvent::DeliverStream(const u_char* data, uint64_t len)
	{
	if ( ! stream_event ) return true;

	mgr.Enqueue(stream_event,
	            GetFile()->ToVal(),
	            zeek::make_intrusive<zeek::StringVal>(new zeek::BroString(data, len, false))
	);

	return true;
	}

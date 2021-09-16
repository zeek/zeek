// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/file_analysis/analyzer/data_event/DataEvent.h"

#include <string>

#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/file_analysis/Manager.h"
#include "zeek/util.h"

namespace zeek::file_analysis::detail
	{

DataEvent::DataEvent(RecordValPtr args, file_analysis::File* file, EventHandlerPtr ce,
                     EventHandlerPtr se)
	: file_analysis::Analyzer(file_mgr->GetComponentTag("DATA_EVENT"), std::move(args), file),
	  chunk_event(ce), stream_event(se)
	{
	}

file_analysis::Analyzer* DataEvent::Instantiate(RecordValPtr args, file_analysis::File* file)
	{
	const auto& chunk_val = args->GetField("chunk_event");
	const auto& stream_val = args->GetField("stream_event");

	if ( ! chunk_val && ! stream_val )
		return nullptr;

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
	if ( ! chunk_event )
		return true;

	event_mgr.Enqueue(chunk_event, GetFile()->ToVal(),
	                  make_intrusive<StringVal>(new String(data, len, false)),
	                  val_mgr->Count(offset));

	return true;
	}

bool DataEvent::DeliverStream(const u_char* data, uint64_t len)
	{
	if ( ! stream_event )
		return true;

	event_mgr.Enqueue(stream_event, GetFile()->ToVal(),
	                  make_intrusive<StringVal>(new String(data, len, false)));

	return true;
	}

	} // namespace zeek::file_analysis::detail

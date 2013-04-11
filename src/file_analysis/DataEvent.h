#ifndef FILE_ANALYSIS_DATAEVENT_H
#define FILE_ANALYSIS_DATAEVENT_H

#include <string>

#include "Val.h"
#include "File.h"
#include "Analyzer.h"

namespace file_analysis {

/**
 * An analyzer to send file data to script-layer events.
 */
class DataEvent : public file_analysis::Analyzer {
public:

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

	virtual bool DeliverChunk(const u_char* data, uint64 len, uint64 offset);

	virtual bool DeliverStream(const u_char* data, uint64 len);

protected:

	DataEvent(RecordVal* args, File* file,
	          EventHandlerPtr ce, EventHandlerPtr se);

	EventHandlerPtr chunk_event;
	EventHandlerPtr stream_event;
};

} // namespace file_analysis

#endif

// See the file "COPYING" in the main distribution directory for copyright.

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
	virtual bool DeliverChunk(const u_char* data, uint64 len, uint64 offset);

	virtual bool DeliverStream(const u_char* data, uint64 len);

	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

protected:
	DataEvent(RecordVal* args, File* file,
	          EventHandlerPtr ce, EventHandlerPtr se);

private:
	EventHandlerPtr chunk_event;
	EventHandlerPtr stream_event;
};

} // namespace file_analysis

#endif

#ifndef FILE_ANALYSIS_DATAEVENT_H
#define FILE_ANALYSIS_DATAEVENT_H

#include <string>

#include "Val.h"
#include "Info.h"
#include "Action.h"

namespace file_analysis {

/**
 * An action to send file data to script-layer events.
 */
class DataEvent : public Action {
public:

	static Action* Instantiate(const RecordVal* args, Info* info);

	virtual bool DeliverChunk(const u_char* data, uint64 len, uint64 offset);

	virtual bool DeliverStream(const u_char* data, uint64 len);

protected:

	DataEvent(Info* arg_info, EventHandlerPtr ce, EventHandlerPtr se);

	EventHandlerPtr chunk_event;
	EventHandlerPtr stream_event;
};

} // namespace file_analysis

#endif

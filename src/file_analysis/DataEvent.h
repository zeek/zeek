// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_DATAEVENT_H
#define FILE_ANALYSIS_DATAEVENT_H

#include <string>

#include "Val.h"
#include "File.h"
#include "Analyzer.h"

namespace file_analysis {

/**
 * An analyzer to send file data to script-layer via events.
 */
class DataEvent : public file_analysis::Analyzer {
public:

	/**
	 * Generates the event, if any, specified by the "chunk_event" field of this
	 * analyzer's \c AnalyzerArgs.  This is for non-sequential file data input.
	 * @param data pointer to start of file data chunk.
	 * @param len number of bytes in the data chunk.
	 * @param offset number of bytes from start of file at which chunk occurs.
	 * @return always true
	 */
	virtual bool DeliverChunk(const u_char* data, uint64 len, uint64 offset);

	/**
	 * Generates the event, if any, specified by the "stream_event" field of
	 * this analyzer's \c AnalyzerArgs.  This is for sequential file data input.
	 * @param data pointer to start of file data chunk.
	 * @param len number of bytes in the data chunk.
	 * @return always true
	 */
	virtual bool DeliverStream(const u_char* data, uint64 len);

	/**
	 * Create a new instance of a DataEvent analyzer.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @return the new DataEvent analyzer instance or a null pointer if
	 *         no "chunk_event" or "stream_event" field was specfied in \a args.
	 */
	static file_analysis::Analyzer* Instantiate(RecordVal* args, File* file);

protected:

	/**
	 * Constructor.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @param ce pointer to event handler which will be called to receive
	 *        non-sequential file data.
	 * @param se pointer to event handler which will be called to receive
	 *        sequential file data.
	 */
	DataEvent(RecordVal* args, File* file,
	          EventHandlerPtr ce, EventHandlerPtr se);

private:
	EventHandlerPtr chunk_event;
	EventHandlerPtr stream_event;
};

} // namespace file_analysis

#endif

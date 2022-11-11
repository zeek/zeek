// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/EventHandler.h"
#include "zeek/Val.h"
#include "zeek/file_analysis/Analyzer.h"
#include "zeek/file_analysis/File.h"

namespace zeek::file_analysis::detail
	{

/**
 * An analyzer to send file data to script-layer via events.
 */
class DataEvent : public file_analysis::Analyzer
	{
public:
	/**
	 * Generates the event, if any, specified by the "chunk_event" field of this
	 * analyzer's \c AnalyzerArgs.  This is for non-sequential file data input.
	 * @param data pointer to start of file data chunk.
	 * @param len number of bytes in the data chunk.
	 * @param offset number of bytes from start of file at which chunk occurs.
	 * @return always true
	 */
	bool DeliverChunk(const u_char* data, uint64_t len, uint64_t offset) override;

	/**
	 * Generates the event, if any, specified by the "stream_event" field of
	 * this analyzer's \c AnalyzerArgs.  This is for sequential file data input.
	 * @param data pointer to start of file data chunk.
	 * @param len number of bytes in the data chunk.
	 * @return always true
	 */
	bool DeliverStream(const u_char* data, uint64_t len) override;

	/**
	 * Create a new instance of a DataEvent analyzer.
	 * @param args the \c AnalyzerArgs value which represents the analyzer.
	 * @param file the file to which the analyzer will be attached.
	 * @return the new DataEvent analyzer instance or a null pointer if
	 *         no "chunk_event" or "stream_event" field was specified in \a args.
	 */
	static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file);

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
	DataEvent(RecordValPtr args, file_analysis::File* file, EventHandlerPtr ce, EventHandlerPtr se);

private:
	EventHandlerPtr chunk_event;
	EventHandlerPtr stream_event;
	};

	} // namespace zeek::file_analysis::detail

// See the file "COPYING" in the main distribution directory for copyright.
//
// A class managing log writers and filters.

#ifndef LOGGING_MANAGER_H
#define LOGGING_MANAGER_H

#include "../Val.h"
#include "../EventHandler.h"
#include "../RemoteSerializer.h"

#include "WriterBackend.h"

class SerializationFormat;
class RemoteSerializer;
class RotationTimer;

namespace logging {

class WriterFrontend;
class RotationFinishedMessage;

/**
 * Singleton class for managing log streams.
 */
class Manager {
public:
	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	~Manager();

	/**
	 * Creates a new log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param stream A record of script type \c Log::Stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool CreateStream(EnumVal* id, RecordVal* stream);

	/**
	 * Remove a log stream, stopping all threads.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool RemoveStream(EnumVal* id);

	/**
	 * Enables a log log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This method corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool EnableStream(EnumVal* id);

	/**
	 * Disables a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool DisableStream(EnumVal* id);

	/**
	 * Adds a filter to a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param filter A record of script type \c Log::Filter.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool AddFilter(EnumVal* id, RecordVal* filter);

	/**
	 * Removes a filter from a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param name The name of the filter to remove.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool RemoveFilter(EnumVal* id, StringVal* name);

	/**
	 * Removes a filter from a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param name The name of the filter to remove.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool RemoveFilter(EnumVal* id, string name);

	/**
	 * Write a record to a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param colums A record of the type defined for the stream's
	 * columns.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool Write(EnumVal* id, RecordVal* columns);

	/**
	 * Sets log streams buffering state. This adjusts all associated
	 * writers to the new state.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param enabled False to disable buffering (default is enabled).
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool SetBuf(EnumVal* id, bool enabled);

	/**
	 * Flushes a log stream. This flushed all associated writers.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool Flush(EnumVal* id);

	/**
	 * Signals the manager to shutdown at Bro's termination.
	 */
	void Terminate();

	/**
	 * Returns a list of supported output formats.
	 */
	static list<string> SupportedFormats();

protected:
	friend class WriterFrontend;
	friend class RotationFinishedMessage;
	friend class RotationFailedMessage;
	friend class ::RemoteSerializer;
	friend class ::RotationTimer;

	// Instantiates a new WriterBackend of the given type (note that
	// doing so creates a new thread!).
	WriterBackend* CreateBackend(WriterFrontend* frontend, bro_int_t type);

	//// Function also used by the RemoteSerializer.

	// Takes ownership of fields and info.
	WriterFrontend* CreateWriter(EnumVal* id, EnumVal* writer, WriterBackend::WriterInfo* info,
				int num_fields, const threading::Field* const* fields,
				bool local, bool remote, bool from_remote, const string& instantiating_filter="");

	// Takes ownership of values..
	bool Write(EnumVal* id, EnumVal* writer, string path,
		   int num_fields, threading::Value** vals);

	// Announces all instantiated writers to peer.
	void SendAllWritersTo(RemoteSerializer::PeerID peer);

	// Signals that a file has been rotated.
	bool FinishedRotation(WriterFrontend* writer, const char* new_name, const char* old_name,
			      double open, double close, bool success, bool terminating);

	// Deletes the values as passed into Write().
	void DeleteVals(int num_fields, threading::Value** vals);

private:
	struct Filter;
	struct Stream;
	struct WriterInfo;

	bool TraverseRecord(Stream* stream, Filter* filter, RecordType* rt,
			    TableVal* include, TableVal* exclude, string path, list<int> indices);

	threading::Value** RecordToFilterVals(Stream* stream, Filter* filter,
				    RecordVal* columns);

	threading::Value* ValToLogVal(Val* val, BroType* ty = 0);
	Stream* FindStream(EnumVal* id);
	void RemoveDisabledWriters(Stream* stream);
	void InstallRotationTimer(WriterInfo* winfo);
	void Rotate(WriterInfo* info);
	Filter* FindFilter(EnumVal* id, StringVal* filter);
	WriterInfo* FindWriter(WriterFrontend* writer);
	bool CompareFields(const Filter* filter, const WriterFrontend* writer);
	bool CheckFilterWriterConflict(const WriterInfo* winfo, const Filter* filter);

	vector<Stream *> streams;	// Indexed by stream enum.
	int rotations_pending;	// Number of rotations not yet finished.
};

}

extern logging::Manager* log_mgr;

#endif

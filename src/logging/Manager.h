// See the file "COPYING" in the main distribution directory for copyright.
//
// A class managing log writers and filters.

#pragma once

#include <string_view>

#include "zeek/EventHandler.h"
#include "zeek/Tag.h"
#include "zeek/Val.h"
#include "zeek/logging/Component.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/plugin/ComponentManager.h"

namespace broker
	{
struct endpoint_info;
	}

namespace zeek
	{

namespace detail
	{
class SerializationFormat;
	}

namespace logging
	{

class WriterFrontend;
class RotationFinishedMessage;
class RotationTimer;

/**
 * Singleton class for managing log streams.
 */
class Manager : public plugin::ComponentManager<Component>
	{
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
	 * Called after scripts are parsed; obtains values of customizable options.
	 */
	void InitPostScript();

	/**
	 * Calls the Log::rotation_format_func script function, tries to create
	 * any directories (failure to falls back to using working dir for
	 * rotation) and returns the formatted rotation path string that
	 * will be sent along to writer threads to perform the actual rotation.
	 * @param rotation_info  The fields of a Log::RotationFmtInfo record
	 *                       to create and pass to Log::rotation_format_func.
	 */
	std::string FormatRotationPath(EnumValPtr writer, std::string_view path, double open,
	                               double close, bool terminating, FuncPtr postprocesor);

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
	bool RemoveFilter(EnumVal* id, const std::string& name);

	/**
	 * Write a record to a log stream.
	 *
	 * @param id  The enum value corresponding the log stream.
	 *
	 * @param columns A record of the type defined for the stream's
	 * columns.
	 *
	 * This methods corresponds directly to the internal BiF defined in
	 * logging.bif, which just forwards here.
	 */
	bool Write(EnumVal* id, RecordVal* columns);

	/**
	 * Create a new log writer frontend. This is exposed so that the
	 * communication system can recreate remote log streams locally.
	 *
	 * @param id The enum value corresponding to the log stream.
	 *
	 * @param writer The enum value corresponding to the desired log writer.
	 *
	 * @param info A fully initialized object defining the
	 * characteristics of the backend writer instance. The method takes
	 * ownership of this.
	 *
	 * @param num_fields The number of log fields to write.
	 *
	 * @param vals An array of log fields to write, of size num_fields.
	 * The method takes ownership of the array.
	 *
	 * @return Returns true if the writer was successfully created.
	 */
	bool CreateWriterForRemoteLog(EnumVal* id, EnumVal* writer, WriterBackend::WriterInfo* info,
	                              int num_fields, const threading::Field* const* fields);

	/**
	 * Writes out log entries that have already passed through all
	 * filters (and have raised any events). This is meant called for logs
	 * received already processed from remote.
	 *
	 * @param stream The enum value corresponding to the log stream.
	 *
	 * @param writer The enum value corresponding to the desired log writer.
	 *
	 * @param path The path of the target log stream to write to.
	 *
	 * @param num_fields The number of log values to write.
	 *
	 * @param vals An array of log values to write, of size num_fields.
	 * The method takes ownership of the array.
	 */
	bool WriteFromRemote(EnumVal* stream, EnumVal* writer, const std::string& path, int num_fields,
	                     threading::Value** vals);

	/**
	 * Announces all instantiated writers to a given Broker peer.
	 */
	void SendAllWritersTo(const broker::endpoint_info& ei);

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
	 * Signals the manager to shutdown at Zeek's termination.
	 */
	void Terminate();

	/**
	 * Enable remote logs for a given stream.
	 * @param stream_id the stream to enable remote logs for.
	 * @return true if remote logs are enabled.
	 */
	bool EnableRemoteLogs(EnumVal* stream_id);

	/**
	 * Disable remote logs for a given stream.
	 * @param stream_id the stream to disable remote logs for.
	 * @return true if remote logs are disabled.
	 */
	bool DisableRemoteLogs(EnumVal* stream_id);

	/**
	 * @return true if remote logs are enabled for a given stream.
	 */
	bool RemoteLogsAreEnabled(EnumVal* stream_id);

	/**
	 * @return the type which corresponds to the columns in a log entry for
	 * a given log stream.
	 */
	RecordType* StreamColumns(EnumVal* stream_id);

protected:
	friend class WriterFrontend;
	friend class RotationFinishedMessage;
	friend class RotationFailedMessage;
	friend class RotationTimer;

	// Instantiates a new WriterBackend of the given type (note that
	// doing so creates a new thread!).
	WriterBackend* CreateBackend(WriterFrontend* frontend, EnumVal* tag);

	//// Function also used by the RemoteSerializer.

	// Takes ownership of fields and info.
	WriterFrontend* CreateWriter(EnumVal* id, EnumVal* writer, WriterBackend::WriterInfo* info,
	                             int num_fields, const threading::Field* const* fields, bool local,
	                             bool remote, bool from_remote,
	                             const std::string& instantiating_filter = "");

	// Signals that a file has been rotated.
	bool FinishedRotation(WriterFrontend* writer, const char* new_name, const char* old_name,
	                      double open, double close, bool success, bool terminating);

	// Deletes the values as passed into Write().
	void DeleteVals(int num_fields, threading::Value** vals);

private:
	struct Filter;
	struct Stream;
	struct WriterInfo;

	bool TraverseRecord(Stream* stream, Filter* filter, RecordType* rt, TableVal* include,
	                    TableVal* exclude, const std::string& path, const std::list<int>& indices);

	threading::Value** RecordToFilterVals(Stream* stream, Filter* filter, RecordVal* columns);

	threading::Value* ValToLogVal(Val* val, Type* ty = nullptr);
	Stream* FindStream(EnumVal* id);
	void RemoveDisabledWriters(Stream* stream);
	void InstallRotationTimer(WriterInfo* winfo);
	void Rotate(WriterInfo* info);
	WriterInfo* FindWriter(WriterFrontend* writer);
	bool CompareFields(const Filter* filter, const WriterFrontend* writer);
	bool CheckFilterWriterConflict(const WriterInfo* winfo, const Filter* filter);

	bool RemoveStream(unsigned int idx);

	std::vector<Stream*> streams; // Indexed by stream enum.
	int rotations_pending; // Number of rotations not yet finished.
	FuncPtr rotation_format_func;
	FuncPtr log_stream_policy_hook;
	};

	} // namespace logging;

extern logging::Manager* log_mgr;

	} // namespace zeek

// See the file "COPYING" in the main distribution directory for copyright.
//
// A class managing log writers and filters.

#pragma once

#include <string_view>

#include "zeek/EventHandler.h"
#include "zeek/Tag.h"
#include "zeek/Val.h"
#include "zeek/logging/Component.h"
#include "zeek/logging/Types.h"
#include "zeek/logging/WriterBackend.h"
#include "zeek/plugin/ComponentManager.h"
#include "zeek/telemetry/Manager.h"

namespace broker {
struct endpoint_info;
}

namespace zeek {

namespace detail {
class SerializationFormat;
}

namespace logging {

class WriterFrontend;
class RotationFinishedMessage;
class RotationTimer;

namespace detail {

class LogFlushWriteBufferTimer;

class DelayInfo;

using WriteIdx = uint64_t;

/**
 * Information about a Log::write() call.
 */
struct WriteContext {
    EnumValPtr id = nullptr;
    RecordValPtr record = nullptr;
    WriteIdx idx = 0; // Ever increasing counter.

    bool operator<(const WriteContext& o) const {
        assert(id == o.id);
        return idx < o.idx;
    }

    bool operator==(const WriteContext& o) const {
        assert(id == o.id);
        return idx == o.idx;
    }
};

} // namespace detail

/**
 * Singleton class for managing log streams.
 */
class Manager : public plugin::ComponentManager<Component> {
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
    std::string FormatRotationPath(EnumValPtr writer, std::string_view path, double open, double close,
                                   bool terminating, FuncPtr postprocesor);

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
     * Enables a log stream.
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
     * Delay the currently active @ref Write operation.
     *
     * This method is only allowed to be called during the execution of the
     * Log::log_stream_policy Zeek script hook. This restriction may be
     * relaxed in the future.
     *
     * @param id  The enum value corresponding the log stream.
     *
     * @param record The log record to delay.
     *
     * @param post_delay_cb A callback function to invoke when the delay
     * has completed or nullptr.
     *
     * @return An opaque token that can be passed to DelayFinish() to
     * release a delayed Log::write() operation.
     */
    ValPtr Delay(const EnumValPtr& id, const RecordValPtr record, FuncPtr post_delay_cb);

    /**
     * Release reference for a delayed Log::write().
     *
     * @param id  The enum value corresponding the log stream.
     *
     * @param record The log record previously passed to Delay()
     *
     * @param token The token returned by the Delay() call.
     *
     * @return Returns true if the call was successful.
     */
    bool DelayFinish(const EnumValPtr& id, const RecordValPtr& record, const ValPtr& token);

    /**
     * Update the maximum delay interval of a given stream.
     *
     * Currently, it is only allowed to increase the maximum
     * delay of a stream.
     *
     * @param id The enum value corresponding to the log stream.
     *
     * @param max_delay  The new maximum delay, in seconds.
     *
     * @return Returns true if the call was successful, else false.
     */
    bool SetMaxDelayInterval(const EnumValPtr& id, double max_delay);

    /**
     * Set the maximum delay queue size for the given stream.
     *
     * @param id The enum value corresponding to the log stream.
     *
     * @param max_queue_length The new maximum queue length.
     *
     * @return Returns true if the call was successful, else false.
     */
    bool SetMaxDelayQueueSize(const EnumValPtr& id, zeek_uint_t max_queue_length);

    /**
     * Returns the current size for the delay queue for the stream identified by \a id.
     *
     * @param id The enum value corresponding to the log stream.
     *
     * @return The size of the delay queue or -1 on error.
     */
    zeek_int_t GetDelayQueueSize(const EnumValPtr& id);

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
    bool CreateWriterForRemoteLog(EnumVal* id, EnumVal* writer, WriterBackend::WriterInfo* info, int num_fields,
                                  const threading::Field* const* fields);

    /**
     * Writes out log entries received from remote nodes.
     *
     * The given record has passed through all policy filters and raised events
     * on the sending node. It's only meant to be written out.
     *
     * @param stream The enum value corresponding to the log stream.
     *
     * @param writer The enum value corresponding to the desired log writer.
     *
     * @param path The path of the target log stream to write to.
     *
     * @param rec Representation of the log record to write.
     *
     * @return Returns true if the record was processed successfully.
     */
    bool WriteFromRemote(EnumVal* id, EnumVal* writer, const std::string& path, detail::LogRecord&& rec);

    /**
     * Writes out a batch of log entries received from remote nodes.
     *
     * The given records have passed through all policy filters and raised events
     * on the sending node. They are only meant to be written out.
     *
     * In contrast to WriteFromRemote(), this method works on a whole batch of log
     * records at once. As long as the the receiving node has a matching filter
     * attached to the stream and the fields within the header match the local
     * filter's fields, an appropriate writer is created. WriteFromRemote() instead
     * assumes the writer exists aprior.
     *
     * This method acts as a sink for \a records. A rvalue reference is used to
     * make this explicit and prevent callers from copying all records by mistake.
     *
     * @param header The header describing the log records as deserialized from a remote message.
     *
     * @param records Records to be written out, the manager takes ownership of these.
     *
     * @return Returns true if the records were processed successfully.
     */
    bool WriteBatchFromRemote(const detail::LogWriteHeader& header, std::vector<detail::LogRecord>&& records);

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
    friend class detail::LogFlushWriteBufferTimer;

    // Instantiates a new WriterBackend of the given type (note that
    // doing so creates a new thread!).
    WriterBackend* CreateBackend(WriterFrontend* frontend, EnumVal* tag);

    //// Function also used by the RemoteSerializer.

    // Takes ownership of fields and info.
    WriterFrontend* CreateWriter(EnumVal* id, EnumVal* writer, WriterBackend::WriterInfo* info, int num_fields,
                                 const threading::Field* const* fields, bool local, bool remote, bool from_remote,
                                 const std::string& instantiating_filter = "");

    // Signals that a file has been rotated.
    bool FinishedRotation(WriterFrontend* writer, const char* new_name, const char* old_name, double open, double close,
                          bool success, bool terminating);

    // Flush write buffers of all writers.
    void FlushAllWriteBuffers();

    // Start the regular log flushing timer.
    void StartLogFlushTimer();

private:
    struct Filter;
    struct Stream;
    struct WriterInfo;

    /**
     * Helper enum for CreateWriterForFilter to avoid bool params.
     */
    enum class WriterOrigin : uint8_t {
        REMOTE,
        LOCAL,
    };

    /**
     * Helper to create a new writer for a filter with the given path.
     *
     * @param filter the filter for which to create the writer.
     * @param path the path for the new writer
     * @param from whether instantiated for a remote log, or locally created.
     */
    WriterFrontend* CreateWriterForFilter(Filter* filter, const std::string& path, WriterOrigin origin);

    bool TraverseRecord(Stream* stream, Filter* filter, RecordType* rt, TableVal* include, TableVal* exclude,
                        const std::string& path, const std::list<int>& indices);

    detail::LogRecord RecordToLogRecord(const Stream* stream, Filter* filter, RecordVal* columns);
    threading::Value ValToLogVal(std::optional<ZVal>& val, Type* ty);

    Stream* FindStream(EnumVal* id);
    void RemoveDisabledWriters(Stream* stream);
    void InstallRotationTimer(WriterInfo* winfo);
    void Rotate(WriterInfo* info);
    WriterInfo* FindWriter(WriterFrontend* writer);
    bool CompareFields(const Filter* filter, const WriterFrontend* writer);
    bool CheckFilterWriterConflict(const WriterInfo* winfo, const Filter* filter);

    // Verdict of a PolicyHook.
    enum class PolicyVerdict : uint8_t {
        PASS,
        VETO,
    };
    bool WriteToFilters(const Manager::Stream* stream, zeek::RecordValPtr columns, PolicyVerdict stream_verdict);

    bool RemoveStream(unsigned int idx);

    bool DelayCompleted(Manager::Stream* stream, detail::DelayInfo& delay_info);

    std::vector<Stream*> streams; // Indexed by stream enum.
    int rotations_pending;        // Number of rotations not yet finished.
    FuncPtr rotation_format_func;
    FuncPtr log_stream_policy_hook;

    std::shared_ptr<telemetry::CounterFamily> total_log_stream_writes_family;
    std::shared_ptr<telemetry::CounterFamily> total_log_writer_writes_family;

    zeek_uint_t last_delay_token = 0;
    std::vector<detail::WriteContext> active_writes;

    // Timer for flushing write buffers of frontends.
    detail::LogFlushWriteBufferTimer* log_flush_timer = nullptr;
};

} // namespace logging

extern logging::Manager* log_mgr;

} // namespace zeek

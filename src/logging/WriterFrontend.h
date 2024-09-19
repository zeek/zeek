// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/logging/WriterBackend.h"

namespace zeek::logging {

class Manager;


namespace detail {

/**
 * Implements a buffer accumulating log records in \a WriterFrontend instance
 * before passing them to \a WriterBackend instances.
 *
 * \see WriterFrontend::Write
 */
class WriteBuffer {
public:
    /**
     * Constructor.
     */
    explicit WriteBuffer(size_t buffer_size) : buffer_size(buffer_size) {}

    /**
     * Push a record to the buffer.
     *
     * @param record The records vals.
     */
    void WriteRecord(LogRecord&& record) { records.emplace_back(std::move(record)); }

    /**
     * Moves the records out of the buffer and resets it.
     *
     * @return The currently buffered log records.
     */
    std::vector<LogRecord> TakeRecords() && {
        auto tmp = std::move(records);

        // Re-initialize the buffer.
        records.clear();
        records.reserve(buffer_size);

        return tmp;
    }

    /**
     * @return The size of the buffer.
     */
    size_t Size() const { return records.size(); }

    /**
     * @return True if buffer is empty.
     */
    size_t Empty() const { return records.empty(); }

    /**
     * @return True if size equals or exceeds configured buffer size.
     */
    bool Full() const { return records.size() >= buffer_size; }

private:
    size_t buffer_size;
    std::vector<LogRecord> records;
};

} // namespace detail

/**
 * Bridge class between the logging::Manager and backend writer threads. The
 * Manager instantiates one \a WriterFrontend for each open logging filter.
 * Each frontend in turns instantiates a WriterBackend-derived class
 * internally that's specific to the particular output format. That backend
 * runs in a new thread, and it receives messages from the frontend that
 * correspond to method called by the manager.
 *
 */
class WriterFrontend {
public:
    /**
     * Constructor.
     *
     * stream: The logging stream.
     *
     * writer: The backend writer type, with the value corresponding to the
     * script-level \c Log::Writer enum (e.g., \a WRITER_ASCII). The
     * frontend will internally instantiate a WriterBackend of the
     * corresponding type.
     *
     * info: The meta information struct for the writer.
     *
     * local: If true, the writer will instantiate a local backend.
     *
     * remote: If true, the writer will forward logs to remote
     * clients.
     *
     * Frontends must only be instantiated by the main thread.
     */
    WriterFrontend(const WriterBackend::WriterInfo& info, EnumVal* stream, EnumVal* writer, bool local, bool remote);

    /**
     * Destructor.
     *
     * Frontends must only be destroyed by the main thread.
     */
    virtual ~WriterFrontend();

    /**
     * Stops all output to this writer. Calling this methods disables all
     * message forwarding to the backend and will eventually remove the
     * backend thread.
     *
     * This method must only be called from the main thread.
     */
    void Stop();

    /**
     * Initializes the writer.
     *
     * This method generates a message to the backend writer and triggers
     * the corresponding message there. If the backend method fails, it
     * sends a message back that will asynchronously call Disable().
     *
     * See WriterBackend::Init() for arguments. The method takes
     * ownership of \a fields.
     *
     * This method must only be called from the main thread.
     */
    void Init(int num_fields, const threading::Field* const* fields);

    /**
     * Write out a record.
     *
     * This method generates a message to the backend writer and triggers
     * the corresponding message there. If the backend method fails, it
     * sends a message back that will asynchronously call Disable().
     *
     * As an optimization, if buffering is enabled (which is the default)
     * this method may buffer several writes and send them over to the
     * backend in bulk with a single message. An explicit bulk write of
     * all currently buffered data can be triggered with
     * FlushWriteBuffer(). The backend writer triggers this with a
     * message at every heartbeat.
     *
     * If the frontend has remote logging enabled, the record is also
     * published to interested peers.
     *
     * @param rec Representation of the log record. Callee takes ownership.

     * This method must only be called from the main thread.
     */
    void Write(detail::LogRecord&& rec);

    /**
     * Sets the buffering state.
     *
     * This method generates a message to the backend writer and triggers
     * the corresponding message there. If the backend method fails, it
     * sends a message back that will asynchronously call Disable().
     *
     * See WriterBackend::SetBuf() for arguments.
     *
     * This method must only be called from the main thread.
     */
    void SetBuf(bool enabled);

    /**
     * Flushes the output.
     *
     * This method generates a message to the backend writer and triggers
     * the corresponding message there. In addition, it also triggers
     * FlushWriteBuffer(). If the backend method fails, it sends a
     * message back that will asynchronously call Disable().
     *
     * This method must only be called from the main thread.
     *
     * @param network_time The network time when the flush was triggered.
     */
    void Flush(double network_time);

    /**
     * Triggers log rotation.
     *
     * This method generates a message to the backend writer and triggers
     * the corresponding message there. If the backend method fails, it
     * sends a message back that will asynchronously call Disable().
     *
     * See WriterBackend::Rotate() for arguments.
     *
     * This method must only be called from the main thread.
     */
    void Rotate(const char* rotated_path, double open, double close, bool terminating);

    /**
     * Explicitly triggers a transfer of all potentially buffered Write()
     * operations over to the backend.
     *
     * This method must only be called from the main thread.
     */
    void FlushWriteBuffer();

    /**
     * Disables the writer frontend. From now on, all method calls that
     * would normally send message over to the backend, turn into no-ops.
     * Note though that it does not stop the backend itself, use Stop()
     * to do that as well (this method is primarily for use as callback
     * when the backend wants to disable the frontend).
     *
     * Disabled frontend will eventually be discarded by the
     * logging::Manager.
     *
     * This method must only be called from the main thread.
     */
    void SetDisable() { disabled = true; }

    /**
     * Returns true if the writer frontend has been disabled with SetDisable().
     */
    bool Disabled() { return disabled; }

    /**
     * Returns the additional writer information as passed into the constructor.
     */
    const WriterBackend::WriterInfo& Info() const { return *info; }

    /**
     * Returns the number of log fields as passed into the constructor.
     */
    int NumFields() const { return num_fields; }

    /**
     * Returns a descriptive name for the writer, including the type of
     * the backend and the path used.
     *
     * This method is safe to call from any thread.
     */
    const char* Name() const { return name; }

    /**
     * Returns the name of the filter that belongs to the frontend.
     */
    const std::string& GetFilterName() const { return info->filter_name; }

    /**
     * Returns the log fields as passed into the constructor.
     */
    const threading::Field* const* Fields() const { return fields; }

protected:
    friend class Manager;

    EnumVal* stream;
    EnumVal* writer;

    WriterBackend* backend; // The backend we have instantiated.
    bool disabled;          // True if disabled.
    bool initialized;       // True if initialized.
    bool buf;               // True if buffering is enabled (default).
    bool local;             // True if logging locally.
    bool remote;            // True if logging remotely.

    const char* name;                      // Descriptive name of the
    WriterBackend::WriterInfo* info;       // The writer information.
    int num_fields;                        // The number of log fields.
    const threading::Field* const* fields; // The log fields.

    // Buffer for bulk writes.
    detail::WriteBuffer write_buffer; // Buffer of size WRITER_BUFFER_SIZE.

    cluster::detail::LogWriteHeader header;
};

} // namespace zeek::logging

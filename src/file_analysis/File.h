// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <list>
#include <string>
#include <utility>

#include "zeek/Tag.h"
#include "zeek/WeirdState.h"
#include "zeek/ZeekArgs.h"
#include "zeek/ZeekList.h" // for ValPList
#include "zeek/ZeekString.h"
#include "zeek/file_analysis/AnalyzerSet.h"

namespace zeek
	{

class Connection;
class EventHandlerPtr;
class RecordVal;
class RecordType;
using RecordValPtr = IntrusivePtr<RecordVal>;
using RecordTypePtr = IntrusivePtr<RecordType>;

namespace file_analysis
	{

class FileReassembler;

/**
 * Wrapper class around \c fa_file record values from script layer.
 */
class File
	{
public:
	/**
	 * Destructor.  Nothing fancy, releases a reference to the wrapped
	 * \c fa_file value.
	 */
	~File();

	/**
	 * @return the wrapped \c fa_file record value, #val.
	 */
	const RecordValPtr& ToVal() const { return val; }

	/**
	 * @return the value of the "source" field from #val record or an empty
	 * string if it's not initialized.
	 */
	std::string GetSource() const;

	/**
	 * Set the "source" field from #val record to \a source.
	 * @param source the new value of the "source" field.
	 */
	void SetSource(const std::string& source);

	/**
	 * @return value (seconds) of the "timeout_interval" field from #val record.
	 */
	double GetTimeoutInterval() const;

	/**
	 * Set the "timeout_interval" field from #val record to \a interval seconds.
	 * @param interval the new value of the "timeout_interval" field.
	 */
	void SetTimeoutInterval(double interval);

	/**
	 * Change the maximum size that an attached extraction analyzer is allowed.
	 * @param args the file extraction analyzer whose limit needs changed.
	 * @param bytes new limit.
	 * @return false if no extraction analyzer is active, else true.
	 */
	bool SetExtractionLimit(RecordValPtr args, uint64_t bytes);

	/**
	 * @return value of the "id" field from #val record.
	 */
	const std::string& GetID() const { return id; }

	/**
	 * @return value of "last_active" field in #val record;
	 */
	double GetLastActivityTime() const;

	/**
	 * Refreshes "last_active" field of #val record with current network time.
	 */
	void UpdateLastActivityTime();

	/**
	 * Set "total_bytes" field of #val record to \a size.
	 * @param size the new value of the "total_bytes" field.
	 */
	void SetTotalBytes(uint64_t size);

	/**
	 * @return true if file analysis is complete for the file, else false.
	 * It is incomplete if the total size is unknown or if the number of bytes
	 * streamed to analyzers (either as data delivers or gap information)
	 * matches the known total size.
	 */
	bool IsComplete() const;

	/**
	 * Create a timer to be dispatched after the amount of time indicated by
	 * the "timeout_interval" field of the #val record in order to check if
	 * "last_active" field is old enough to timeout analysis of the file.
	 */
	void ScheduleInactivityTimer() const;

	/**
	 * Queues attaching an analyzer.  Only one analyzer per type can be attached
	 * at a time unless the arguments differ.
	 * @param tag the analyzer tag of the file analyzer to add.
	 * @param args an \c AnalyzerArgs value representing a file analyzer.
	 * @return false if analyzer can't be instantiated, else true.
	 */
	bool AddAnalyzer(zeek::Tag tag, RecordValPtr args);

	/**
	 * Queues removal of an analyzer.
	 * @param tag the analyzer tag of the file analyzer to remove.
	 * @param args an \c AnalyzerArgs value representing a file analyzer.
	 * @return true if analyzer was active at time of call, else false.
	 */
	bool RemoveAnalyzer(zeek::Tag tag, RecordValPtr args);

	/**
	 * Signal that this analyzer can be deleted once it's safe to do so.
	 */
	void DoneWithAnalyzer(Analyzer* analyzer);

	/**
	 * Pass in non-sequential data and deliver to attached analyzers.
	 * @param data pointer to start of a chunk of file data.
	 * @param len number of bytes in the data chunk.
	 * @param offset number of bytes from start of file at which chunk occurs.
	 */
	void DataIn(const u_char* data, uint64_t len, uint64_t offset);

	/**
	 * Pass in sequential data and deliver to attached analyzers.
	 * @param data pointer to start of a chunk of file data.
	 * @param len number of bytes in the data chunk.
	 */
	void DataIn(const u_char* data, uint64_t len);

	/**
	 * Inform attached analyzers about end of file being seen.
	 */
	void EndOfFile();

	/**
	 * Inform attached analyzers about a gap in file stream.
	 * @param offset number of bytes into file at which missing chunk starts.
	 * @param len length in bytes of the missing chunk of file data.
	 */
	void Gap(uint64_t offset, uint64_t len);

	/**
	 * @param h pointer to an event handler.
	 * @return true if event has a handler and the file isn't ignored.
	 */
	bool FileEventAvailable(EventHandlerPtr h);

	/**
	 * Raises an event related to the file's life-cycle, the only parameter
	 * to that event is the \c fa_file record..
	 * @param h pointer to an event handler.
	 */
	void FileEvent(EventHandlerPtr h);

	/**
	 * Raises an event related to the file's life-cycle.
	 * @param h pointer to an event handler.
	 * @param args list of argument values to pass to event call.
	 */
	void FileEvent(EventHandlerPtr h, Args args);

	/**
	 * Sets the MIME type for a file to a specific value.
	 *
	 * Setting the MIME type has to be done before the MIME type is
	 * inferred from the content, and before any data is passed to the
	 * analyzer (the beginning of file buffer has to be empty). After
	 * data has been sent or a MIME type has been set once, it cannot be
	 * changed.
	 *
	 * This function should only be called when it does not make sense
	 * to perform automated MIME type detections. This is e.g. the case
	 * in protocols where the file type is fixed in the protocol description.
	 * This is for example the case for TLS and X.509 certificates.
	 *
	 * @param mime_type mime type to set
	 * @return true if the mime type was set. False if it could not be set because
	 *         a mime type was already set or inferred.
	 */
	bool SetMime(const std::string& mime_type);

	/**
	 * Whether to permit a weird to carry on through the full reporter/weird
	 * framework.
	 */
	bool PermitWeird(const char* name, uint64_t threshold, uint64_t rate, double duration);

protected:
	friend class Manager;
	friend class FileReassembler;

	/**
	 * Constructor; only file_analysis::Manager should be creating these.
	 * @param file_id an identifier string for the file in pretty hash form
	 *        (similar to connection uids).
	 * @param source_name the value for the source field to fill in.
	 * @param conn a network connection over which the file is transferred.
	 * @param tag the network protocol over which the file is transferred.
	 * @param is_orig true if the file is being transferred from the originator
	 *        of the connection to the responder.  False indicates the other
	 *        direction.
	 */
	File(const std::string& file_id, const std::string& source_name, Connection* conn = nullptr,
	     zeek::Tag tag = zeek::Tag::Error, bool is_orig = false);

	/**
	 * Updates the "conn_ids" and "conn_uids" fields in #val record with the
	 * \c conn_id and UID taken from \a conn.
	 * @param conn the connection over which a part of the file has been seen.
	 * @param is_orig true if the connection originator is sending the file.
	 * @return true if the connection was previously unknown.
	 */
	bool UpdateConnectionFields(Connection* conn, bool is_orig);

	/**
	 * Raise the file_over_new_connection event with given arguments.
	 */
	void RaiseFileOverNewConnection(Connection* conn, bool is_orig);

	/**
	 * Increment a byte count field of #val record by \a size.
	 * @param size number of bytes by which to increment.
	 * @param field_idx the index of the field in \c fa_file to increment.
	 */
	void IncrementByteCount(uint64_t size, int field_idx);

	/**
	 * Wrapper to RecordVal::GetFieldOrDefault for the field in #val at index
	 * \a idx which automatically unrefs the Val and returns a converted value.
	 * @param idx the index of a field of type "count" in \c fa_file.
	 * @return the value of the field, which may be it &default.
	 */
	uint64_t LookupFieldDefaultCount(int idx) const;

	/**
	 * Wrapper to RecordVal::GetFieldOrDefault for the field in #val at index
	 * \a idx which automatically unrefs the Val and returns a converted value.
	 * @param idx the index of a field of type "interval" in \c fa_file.
	 * @return the value of the field, which may be it &default.
	 */
	double LookupFieldDefaultInterval(int idx) const;

	/**
	 * Buffers incoming data at the beginning of a file.
	 * @param data pointer to a data chunk to buffer.
	 * @param len number of bytes in the data chunk.
	 * @return true if buffering is still required, else false
	 */
	bool BufferBOF(const u_char* data, uint64_t len);

	/**
	 * Does metadata inference (e.g. mime type detection via file
	 * magic signatures) using data in the BOF (beginning-of-file) buffer
	 * and raises an event with the metadata.
	 */
	void InferMetadata();

	/**
	 * Enables reassembly on the file.
	 */
	void EnableReassembly();

	/**
	 * Disables reassembly on the file.  If there is an existing reassembler
	 * for the file, this will cause it to be deleted and won't allow a new
	 * one to be created until reassembly is reenabled.
	 */
	void DisableReassembly();

	/**
	 * Set a maximum allowed bytes of memory for file reassembly for this file.
	 */
	void SetReassemblyBuffer(uint64_t max);

	/**
	 * Perform stream-wise delivery for analyzers that need it.
	 */
	void DeliverStream(const u_char* data, uint64_t len);

	/**
	 * Perform chunk-wise delivery for analyzers that need it.
	 */
	void DeliverChunk(const u_char* data, uint64_t len, uint64_t offset);

	/**
	 * Lookup a record field index/offset by name.
	 * @param field_name the name of the record field.
	 * @param type the record type for which the field will be looked up.
	 * @return the field offset in #val record corresponding to \a field_name.
	 */
	static int Idx(const std::string& field_name, const RecordType* type);
	static int Idx(const std::string& field_name, const RecordTypePtr& type)
		{
		return Idx(field_name, type.get());
		}

	/**
	 * Initializes static member.
	 */
	static void StaticInit();

protected:
	std::string id; /**< A pretty hash that likely identifies file */
	RecordValPtr val; /**< \c fa_file from script layer. */
	FileReassembler* file_reassembler; /**< A reassembler for the file if it's needed. */
	uint64_t stream_offset; /**< The offset of the file which has been forwarded. */
	uint64_t reassembly_max_buffer; /**< Maximum allowed buffer for reassembly. */
	bool did_metadata_inference; /**< Whether the metadata inference has already been attempted. */
	bool reassembly_enabled; /**< Whether file stream reassembly is needed. */
	bool postpone_timeout; /**< Whether postponing timeout is requested. */
	bool done; /**< If this object is about to be deleted. */
	detail::AnalyzerSet analyzers; /**< A set of attached file analyzers. */
	std::list<Analyzer*> done_analyzers; /**< Analyzers we're done with, remembered here until they
	                                        can be safely deleted. */

	struct BOF_Buffer
		{
		BOF_Buffer() : full(false), size(0) { }
		~BOF_Buffer()
			{
			for ( size_t i = 0; i < chunks.size(); ++i )
				delete chunks[i];
			}

		bool full;
		uint64_t size;
		String::CVec chunks;
		} bof_buffer; /**< Beginning of file buffer. */

	zeek::detail::WeirdStateMap weird_state;

	static int id_idx;
	static int parent_id_idx;
	static int source_idx;
	static int is_orig_idx;
	static int conns_idx;
	static int last_active_idx;
	static int seen_bytes_idx;
	static int total_bytes_idx;
	static int missing_bytes_idx;
	static int overflow_bytes_idx;
	static int timeout_interval_idx;
	static int bof_buffer_size_idx;
	static int bof_buffer_idx;
	static int mime_type_idx;
	static int mime_types_idx;
	static int meta_inferred_idx;

	static int meta_mime_type_idx;
	static int meta_mime_types_idx;
	};

	} // namespace file_analysis
	} // namespace zeek

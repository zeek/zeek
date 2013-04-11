#ifndef FILE_ANALYSIS_FILE_H
#define FILE_ANALYSIS_FILE_H

#include <string>
#include <vector>
#include <magic.h>

#include "AnalyzerTags.h"
#include "Conn.h"
#include "Val.h"
#include "ActionSet.h"
#include "FileID.h"
#include "BroString.h"

namespace file_analysis {

/**
 * Wrapper class around \c fa_file record values from script layer.
 */
class File {
friend class Manager;

public:

	~File();

	/**
	 * @return the #val record.
	 */
	RecordVal* GetVal() const { return val; }

	/**
	 * @return value (seconds) of the "timeout_interval" field from #val record.
	 */
	double GetTimeoutInterval() const;

	/**
	 * Set the "timeout_interval" field from #val record to \a interval seconds.
	 */
	void SetTimeoutInterval(double interval);

	/**
	 * @return value of the "id" field from #val record.
	 */
	FileID GetID() const { return id; }

	/**
	 * @return the string which uniquely identifies the file.
	 */
	string GetUnique() const { return unique; }

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
	 */
	void SetTotalBytes(uint64 size);

	/**
	 * Compares "seen_bytes" field to "total_bytes" field of #val record
	 * and returns true if the comparison indicates the full file was seen.
	 * If "total_bytes" hasn't been set yet, it returns false.
	 */
	bool IsComplete() const;

	/**
	 * Create a timer to be dispatched after the amount of time indicated by
	 * the "timeout_interval" field of the #val record in order to check if
	 * "last_active" field is old enough to timeout analysis of the file.
	 */
	void ScheduleInactivityTimer() const;

	/**
	 * Queues attaching an action.  Only one action per type can be attached at
	 * a time unless the arguments differ.
	 * @return false if action can't be instantiated, else true.
	 */
	bool AddAction(RecordVal* args);

	/**
	 * Queues removal of an action.
	 * @return true if action was active at time of call, else false.
	 */
	bool RemoveAction(const RecordVal* args);

	/**
	 * Pass in non-sequential data and deliver to attached actions/analyzers.
	 */
	void DataIn(const u_char* data, uint64 len, uint64 offset);

	/**
	 * Pass in sequential data and deliver to attached actions/analyzers.
	 */
	void DataIn(const u_char* data, uint64 len);

	/**
	 * Inform attached actions/analyzers about end of file being seen.
	 */
	void EndOfFile();

	/**
	 * Inform attached actions/analyzers about a gap in file stream.
	 */
	void Gap(uint64 offset, uint64 len);

	/**
	 * @return true if event has a handler and the file isn't ignored.
	 */
	bool FileEventAvailable(EventHandlerPtr h);

	/**
	 * Raises an event related to the file's life-cycle, the only parameter
	 * to that event is the \c fa_file record..
	 */
	void FileEvent(EventHandlerPtr h);

	/**
	 * Raises an event related to the file's life-cycle.
	 */
	void FileEvent(EventHandlerPtr h, val_list* vl);

protected:

	/**
	 * Constructor; only file_analysis::Manager should be creating these.
	 */
	File(const string& unique, Connection* conn = 0,
	     AnalyzerTag::Tag tag = AnalyzerTag::Error);

	/**
	 * Updates the "conn_ids" and "conn_uids" fields in #val record with the
	 * \c conn_id and UID taken from \a conn.
	 */
	void UpdateConnectionFields(Connection* conn);

	/**
	 * Increment a byte count field of #val record by \a size.
	 */
	void IncrementByteCount(uint64 size, int field_idx);

	/**
	 * Wrapper to RecordVal::LookupWithDefault for the field in #val at index
	 * \a idx which automatically unrefs the Val and returns a converted value.
	 */
	uint64 LookupFieldDefaultCount(int idx) const;

	/**
	 * Wrapper to RecordVal::LookupWithDefault for the field in #val at index
	 * \a idx which automatically unrefs the Val and returns a converted value.
	 */
	double LookupFieldDefaultInterval(int idx) const;

	/**
	 * Buffers incoming data at the beginning of a file.
	 * @return true if buffering is still required, else false
	 */
	bool BufferBOF(const u_char* data, uint64 len);

	/**
	 * Forward any beginning-of-file buffered data on to DataIn stream.
	 */
	void ReplayBOF();

	/**
	 * Does file/mime type detection and assigns types (if available) to
	 * corresponding fields in #val.
	 * @return whether a file or mime type was available.
	 */
	bool DetectTypes(const u_char* data, uint64 len);

	FileID id;                 /**< A pretty hash that likely identifies file */
	string unique;             /**< A string that uniquely identifies file */
	RecordVal* val;            /**< \c fa_file from script layer. */
	bool postpone_timeout;     /**< Whether postponing timeout is requested. */
	bool first_chunk;          /**< Track first non-linear chunk. */
	bool missed_bof;           /**< Flags that we missed start of file. */
	bool need_reassembly;      /**< Whether file stream reassembly is needed. */
	bool done;                 /**< If this object is about to be deleted. */
	ActionSet actions;

	struct BOF_Buffer {
		BOF_Buffer() : full(false), replayed(false), size(0) {}
		~BOF_Buffer()
			{ for ( size_t i = 0; i < chunks.size(); ++i ) delete chunks[i]; }

		bool full;
		bool replayed;
		uint64 size;
		BroString::CVec chunks;
	} bof_buffer;              /**< Beginning of file buffer. */

	/**
	 * @return the field offset in #val record corresponding to \a field_name.
	 */
	static int Idx(const string& field_name);

	/**
	 * Initializes static member.
	 */
	static void StaticInit();

	static magic_t magic;
	static magic_t magic_mime;

	static string salt;

	static int id_idx;
	static int parent_id_idx;
	static int source_idx;
	static int conns_idx;
	static int last_active_idx;
	static int seen_bytes_idx;
	static int total_bytes_idx;
	static int missing_bytes_idx;
	static int overflow_bytes_idx;
	static int timeout_interval_idx;
	static int bof_buffer_size_idx;
	static int bof_buffer_idx;
	static int file_type_idx;
	static int mime_type_idx;
};

} // namespace file_analysis

#endif

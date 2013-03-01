#ifndef FILE_ANALYSIS_INFO_H
#define FILE_ANALYSIS_INFO_H

#include <string>
#include <vector>

#include "Conn.h"
#include "Val.h"
#include "ActionSet.h"
#include "FileID.h"
#include "BroString.h"

namespace file_analysis {

/**
 * Wrapper class around \c FileAnalysis::Info record values from script layer.
 */
class Info {
public:

	~Info();

	/**
	 * @return the #val record.
	 */
	RecordVal* GetVal() const { return val; }

	/**
	 * @return value (seconds) of the "timeout_interval" field from #val record.
	 */
	double GetTimeoutInterval() const;

	/**
	 * @return value of the "file_id" field from #val record.
	 */
	FileID GetFileID() const { return file_id; }

	/**
	 * @return looks up the value of the "actions" field in the #val record at
	 *         the index corresponding to \a args.  If there was no value at
	 *         the index, it is created.
	 */
	RecordVal* GetResults(RecordVal* args) const;

	/**
	 * @return the string which uniquely identifies the file.
	 */
	string GetUnique() const { return unique; }

	/**
	 * @return #last_activity_time
	 */
	double GetLastActivityTime() const { return last_activity_time; }

	/**
	 * Refreshes #last_activity_time with current network time.
	 */
	void UpdateLastActivityTime() { last_activity_time = network_time; }

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
	 * #last_activity_time is old enough to timeout analysis of the file.
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

protected:

	friend class Manager;

	/**
	 * Constructor; only file_analysis::Manager should be creating these.
	 */
	Info(const string& unique, Connection* conn = 0,
	     const string& protocol = "");

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

	FileID file_id;            /**< A pretty hash that likely identifies file*/
	string unique;             /**< A string that uniquely identifies file */
	RecordVal* val;            /**< \c FileAnalysis::Info from script layer. */
	double last_activity_time; /**< Time of last activity. */
	bool postpone_timeout;     /**< Whether postponing timeout is requested. */
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
	 * Initializes the index offsets for fields in \c FileAnalysis::info record.
	 */
	static void InitFieldIndices();

public:
	static int file_id_idx;
	static int parent_file_id_idx;
	static int protocol_idx;
	static int conn_uids_idx;
	static int conn_ids_idx;
	static int seen_bytes_idx;
	static int total_bytes_idx;
	static int missing_bytes_idx;
	static int overflow_bytes_idx;
	static int timeout_interval_idx;
	static int bof_buffer_size_idx;
	static int bof_buffer_idx;
	static int file_type_idx;
	static int mime_type_idx;
	static int actions_idx;
};

} // namespace file_analysis

#endif

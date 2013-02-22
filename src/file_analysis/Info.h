#ifndef FILE_ANALYSIS_INFO_H
#define FILE_ANALYSIS_INFO_H

#include <string>
#include <map>

#include "Conn.h"
#include "Val.h"
#include "Action.h"
#include "FileID.h"

namespace file_analysis {

/**
 * Wrapper class around \c FileAnalysis::Info record values from script layer.
 */
class Info {
public:

	~Info();

	/**
	 * @return value (seconds) of the "timeout_interval" field from #val record.
	 */
	double TimeoutInterval() const;

	/**
	 * @return value of the "file_id" field from #val record.
	 */
	FileID GetFileID() const { return file_id; }

	/**
	 * @return record val of the "action_results" field from #val record.
	 */
	RecordVal* Results() const;

	/**
	 * @return the string which uniquely identifies the file.
	 */
	string Unique() const { return unique; }

	/**
	 * @return #last_activity_time
	 */
	double LastActivityTime() const { return last_activity_time; }

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
	 * Attaches an action.  Only one action per type can be attached at a time.
	 * @return true if the action was attached, else false.
	 */
	bool AddAction(ActionTag act, RecordVal* args);

	/**
	 * Removes an action.
	 * @return true if the action was removed, else false.
	 */
	bool RemoveAction(ActionTag act);

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

	typedef map<ActionTag, Action*> ActionMap;

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
	 * Removes an action.
	 * @return true if the action was removed, else false.
	 */
	bool RemoveAction(const ActionMap::iterator& it);

	FileID file_id;            /**< A pretty hash that likely identifies file*/
	string unique;             /**< A string that uniquely identifies file */
	RecordVal* val;            /**< \c FileAnalysis::Info from script layer. */
	double last_activity_time; /**< Time of last activity. */
	bool postpone_timeout;     /**< Whether postponing timeout is requested. */
	bool need_reassembly;      /**< Whether file stream reassembly is needed. */
	ActionMap actions;         /**< Actions/analysis to perform on file. */

	/**
	 * @return the field offset in #val record corresponding to \a field_name.
	 */
	static int Idx(const string& field_name);

	/**
	 * Initializes the index offsets for fields in \c FileAnalysis::info record.
	 */
	static void InitFieldIndices();

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
	static int actions_idx;
	static int action_args_idx;
	static int action_results_idx;
};

} // namespace file_analysis

#endif

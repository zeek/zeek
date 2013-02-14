#ifndef FILE_ANALYSIS_MANAGER_H
#define FILE_ANALYSIS_MANAGER_H

#include <string>
#include <map>
#include <vector>

#include "Conn.h"
#include "Analyzer.h"
#include "Timer.h"
#include "Val.h"
#include "Reporter.h"

namespace file_analysis {

class Info;

/**
 * Base class for actions that can be attached to a file_analysis::Info object.
 */
class Action {
public:

	virtual ~Action() {}

	/**
	 * Subclasses may override this to receive file data non-sequentially.
	 */
	virtual void DeliverChunk(const u_char* data, uint64 len, uint64 offset) {}

	/**
	 * Subclasses may override this to receive file sequentially.
	 */
	virtual void DeliverStream(const u_char* data, uint64 len) {}

	/**
	 * Subclasses may override this to specifically handle the end of a file.
	 */
	virtual void EndOfFile() {}

	/**
	 * Subclasses may override this to handle missing data in a file stream.
	 */
	virtual void Undelivered(uint64 offset, uint64 len) {}

protected:

	Action(Info* arg_info);

	Info* info;
};

typedef Action* (*ActionInstantiator)(const RecordVal* args, Info* info);

/**
 * An action to simply extract files to disk.
 */
class Extract : Action {
public:

	static Action* Instantiate(const RecordVal* args, Info* info);

	~Extract();

	virtual void DeliverChunk(const u_char* data, uint64 len, uint64 offset);

protected:

	Extract(Info* arg_info, const string& arg_filename);

	string filename;
	int fd;
};

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
	string FileID() const;

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
	bool AddAction(EnumVal* act, RecordVal* args);

	/**
	 * Removes an action.
	 * @return true if the action was removed, else false.
	 */
	bool RemoveAction(EnumVal* act);

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
	Info(const string& file_id, Connection* conn = 0,
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

	RecordVal* val;            /**< \c FileAnalysis::Info from script layer. */
	double last_activity_time; /**< Time of last activity. */
	bool postpone_timeout;     /**< Whether postponing timeout is requested. */
	bool need_reassembly;      /**< Whether file stream reassembly is needed. */

	typedef map<int, Action*> ActionMap;

	ActionMap actions;

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
};

/**
 * Timer to periodically check if file analysis for a given file is inactive.
 */
class InfoTimer : public Timer {
public:

	InfoTimer(double t, const string& id, double interval)
	    : Timer(t + interval, TIMER_FILE_ANALYSIS_INACTIVITY), file_id(id) { }

	~InfoTimer() { }

	/**
	 * Check inactivity of file_analysis::Info corresponding to #file_id,
	 * reschedule if active, else call file_analysis::Manager::Timeout.
	 */
	void Dispatch(double t, int is_expire);

protected:

	string file_id;
};

/**
 * Main entry point for interacting with file analysis.
 */
class Manager {
public:

	Manager();

	~Manager();

	/**
	 * Times out any active file analysis to prepare for shutdown.
	 */
	void Terminate();

	/**
	 * Pass in non-sequential file data.
	 */
	void DataIn(const string& file_id, const u_char* data, uint64 len,
	            uint64 offset, Connection* conn = 0,
	            const string& protocol = "");

	/**
	 * Pass in sequential file data.
	 */
	void DataIn(const string& file_id, const u_char* data, uint64 len,
	            Connection* conn = 0, const string& protocol = "");

	/**
	 * Signal the end of file data.
	 */
	void EndOfFile(const string& file_id, Connection* conn = 0,
	               const string& protocol = "");

	/**
	 * Signal a gap in the file data stream.
	 */
	void Gap(const string& file_id, uint64 offset, uint64 len,
	         Connection* conn = 0, const string& protocol = "");

	/**
	 * Provide the expected number of bytes that comprise a file.
	 */
	void SetSize(const string& file_id, uint64 size, Connection* conn = 0,
	             const string& protocol = "");

	/**
	 * Discard the file_analysis::Info object associated with \a file_id.
	 * @return false if file identifier did not map to anything, else true.
	 */
	bool RemoveFile(const string& file_id);

	/**
	 * If called during \c FileAnalysis::policy evaluation for a
	 * \c FileAnalysis::TRIGGER_TIMEOUT, requests deferral of analysis timeout.
	 */
	bool PostponeTimeout(const string& file_id) const;

	/**
	 * Attaches an action to the file identifier.  Only one action of a given
	 * type can be attached per file identifier at a time.
	 * @return true if the action was attached, else false.
	 */
	bool AddAction(const string& file_id, EnumVal* act, RecordVal* args) const;

	/**
	 * Removes an action for a given file identifier.
	 * @return true if the action was removed, else false.
	 */
	bool RemoveAction(const string& file_id, EnumVal* act) const;

	/**
	 * Calls the \c FileAnalysis::policy hook.
	 */
	static void EvaluatePolicy(BifEnum::FileAnalysis::Trigger t, Info* info);

protected:

	friend class InfoTimer;

	typedef map<string, Info*> FileMap;

	/**
	 * @return the Info object mapped to \a file_id.  One is created if mapping
	 *         doesn't exist.  If it did exist, the activity time is refreshed
	 *         and connection-related fields of the record value may be updated.
	 */
	Info* IDtoInfo(const string& file_id, Connection* conn = 0,
	               const string& protocol = "");

	/**
	 * @return the Info object mapped to \a file_id, or a null pointer if no
	 *         mapping exists.
	 */
	Info* Lookup(const string& file_id) const;

	/**
	 * Evaluate timeout policy for a file and remove the Info object mapped to
	 * \a file_id if needed.
	 */
	void Timeout(const string& file_id, bool is_terminating = ::terminating);

	FileMap file_map; /**< Map strings to \c FileAnalysis::Info records. */
};

} // namespace file_analysis

extern file_analysis::Manager* file_mgr;

#endif

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

	Action(Info* arg_info);

	~Action() {}

	virtual void DeliverStream(const u_char* data, uint64 len) = 0;

protected:

	Info* info;
};

/**
 * An action to simply extract files to disk.
 */
class Extract : Action {
public:

	Extract(Info* arg_info, const string& arg_filename);

	~Extract() {}

	virtual void DeliverStream(const u_char* data, uint64 len);

protected:

	string filename;
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
	 * Increments the "seen_bytes" field of #val record by \a size.
	 */
	void IncrementSeenBytes(uint64 size);

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
	 * Wrapper to RecordVal::LookupWithDefault for the field in #val at index
	 * \a idx which automatically unrefs the Val and returns a converted value.
	 */
	uint64 FieldDefaultCount(int idx) const;

	/**
	 * Wrapper to RecordVal::LookupWithDefault for the field in #val at index
	 * \a idx which automatically unrefs the Val and returns a converted value.
	 */
	double FieldDefaultInterval(int idx) const;

	RecordVal* val;            /**< \c FileAnalysis::Info from script layer. */
	double last_activity_time; /**< Time of last activity. */
	bool postpone_timeout;     /**< Whether postponing timeout is requested. */

	vector<Analyzer*> analyzers;

	/**
	 * @return the field offset in #val record corresponding to \a field_name.
	 */
	static int Idx(const string& field_name);

	static int file_id_idx;
	static int parent_file_id_idx;
	static int protocol_idx;
	static int conn_uids_idx;
	static int conn_ids_idx;
	static int seen_bytes_idx;
	static int total_bytes_idx;
	static int undelivered_idx;
	static int timeout_interval_idx;
};

/**
 * Timer to periodically check if file analysis for a given file is inative.
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
	 * Provide the expected number of bytes that comprise a file.
	 */
	void SetSize(const string& file_id, uint64 size, Connection* conn = 0,
	             const string& protocol = "");

	/**
	 * Discard the file_analysis::Info object associated with \a file_id.
	 */
	void Remove(const string& file_id);

	/**
	 * If called during \c FileAnalysis::policy evaluation for a
	 * \c FileAnalysis::TRIGGER_TIMEOUT, requests deferral of analysis timeout.
	 */
	bool PostponeTimeout(const string& file_id) const;

	/**
	 * Calls the \c FileAnalysis::policy hook.
	 */
	static void EvaluatePolicy(BifEnum::FileAnalysis::Trigger t, Info* info);

protected:

	friend class InfoTimer;

	typedef map<string, Info*> FileMap;

	/**
	 * @return the Info object mapped to \a file_id.  One is created if mapping
	 *         doesn't exist.
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

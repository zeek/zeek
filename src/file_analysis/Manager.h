#ifndef FILE_ANALYSIS_MANAGER_H
#define FILE_ANALYSIS_MANAGER_H

#include <string>
#include <map>

#include "Net.h"
#include "Conn.h"
#include "Val.h"

#include "Info.h"
#include "InfoTimer.h"

namespace file_analysis {

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

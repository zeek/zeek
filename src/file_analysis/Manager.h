#ifndef FILE_ANALYSIS_MANAGER_H
#define FILE_ANALYSIS_MANAGER_H

#include <string>
#include <map>
#include <set>
#include <vector>

#include "Net.h"
#include "Conn.h"
#include "Val.h"

#include "Info.h"
#include "InfoTimer.h"
#include "FileID.h"
#include "PendingFile.h"

namespace file_analysis {

/**
 * Main entry point for interacting with file analysis.
 */
class Manager {
public:

	Manager();

	~Manager();

	/**
	 * Attempts to forward the data from any pending file contents, i.e.
	 * those for which a unique file handle string could not immediately
	 * be determined.  If again a file handle can't be determined, give up.
	 * The assumption for this to work correctly is that the EventMgr would
	 * have always drained between packet boundaries, so calling this method
	 * at that time may mean the script-layer function for generating file
	 * handles can now come up with a result.
	 */
	void DrainPending();

	/**
	 * Times out any active file analysis to prepare for shutdown.
	 */
	void Terminate();

	/**
	 * Pass in non-sequential file data.
	 */
    void DataIn(const u_char* data, uint64 len, uint64 offset,
                Connection* conn, bool is_orig, bool allow_retry = true);
    void DataIn(const u_char* data, uint64 len, uint64 offset,
                const string& unique);
    void DataIn(const u_char* data, uint64 len, uint64 offset,
                Info* info);

	/**
	 * Pass in sequential file data.
	 */
	void DataIn(const u_char* data, uint64 len, Connection* conn, bool is_orig,
	            bool allow_retry = true);
	void DataIn(const u_char* data, uint64 len, const string& unique);
	void DataIn(const u_char* data, uint64 len, Info* info);

	/**
	 * Signal the end of file data.
	 */
	void EndOfFile(Connection* conn);
	void EndOfFile(Connection* conn, bool is_orig);
	void EndOfFile(const string& unique);

	/**
	 * Signal a gap in the file data stream.
	 */
	void Gap(uint64 offset, uint64 len, Connection* conn, bool is_orig);
	void Gap(uint64 offset, uint64 len, const string& unique);
	void Gap(uint64 offset, uint64 len, Info* info);

	/**
	 * Provide the expected number of bytes that comprise a file.
	 */
	void SetSize(uint64 size, Connection* conn, bool is_orig);
	void SetSize(uint64 size, const string& unique);
	void SetSize(uint64 size, Info* info);

	/**
	 * Starts ignoring a file, which will finally be removed from internal
	 * mappings on EOF or TIMEOUT.
	 * @return false if file identifier did not map to anything, else true.
	 */
	bool IgnoreFile(const FileID& file_id);

	/**
	 * If called during \c FileAnalysis::policy evaluation for a
	 * \c FileAnalysis::TRIGGER_TIMEOUT, requests deferral of analysis timeout.
	 */
	bool PostponeTimeout(const FileID& file_id) const;

	/**
	 * Queue attachment of an action to the file identifier.  Multiple actions
	 * of a given type can be attached per file identifier at a time as long as
	 * the arguments differ.
	 * @return false if the action failed to be instantiated, else true.
	 */
	bool AddAction(const FileID& file_id, RecordVal* args) const;

	/**
	 * Queue removal of an action for a given file identifier.
	 * @return true if the action is active at the time of call, else false.
	 */
	bool RemoveAction(const FileID& file_id, const RecordVal* args) const;

	/**
	 * Calls the \c FileAnalysis::policy hook.
	 */
	void EvaluatePolicy(BifEnum::FileAnalysis::Trigger t, Info* info);

protected:

	friend class InfoTimer;
	friend class PendingFile;

	typedef map<string, Info*> StrMap;
	typedef set<string> StrSet;
	typedef map<FileID, Info*> IDMap;
	typedef vector<PendingFile> PendingList;

	/**
	 * @return the Info object mapped to \a unique or a null pointer if analysis
	 *         is being ignored for the associated file.  An Info object may be
	 *         created if a mapping doesn't exist, and if it did exist, the
	 *         activity time is refreshed along with any connection-related
	 *         fields.
	 */
	Info* GetInfo(const string& unique, Connection* conn = 0);

	/**
	 * @return a string which can uniquely identify the file being transported
	 *         over the connection.  A script-layer function is evaluated in
	 *         order to determine the unique string.  An empty string means
	 *         a unique handle for the file couldn't be determined at the time
	 *         time the function was evaluated (possibly because some events
	 *         have not yet been drained from the queue).
	 */
	string GetFileHandle(Connection* conn, bool is_orig);

	/**
	 * @return the Info object mapped to \a file_id, or a null pointer if no
	 *         mapping exists.
	 */
	Info* Lookup(const FileID& file_id) const;

	/**
	 * Evaluate timeout policy for a file and remove the Info object mapped to
	 * \a file_id if needed.
	 */
	void Timeout(const FileID& file_id, bool is_terminating = ::terminating);

	/**
	 * Immediately remove file_analysis::Info object associated with \a unique.
	 * @return false if file string did not map to anything, else true.
	 */
	bool RemoveFile(const string& unique);

	/**
	 * @return whether the file mapped to \a unique is being ignored.
	 */
	bool IsIgnored(const string& unique);

	StrMap str_map; /**< Map unique strings to \c FileAnalysis::Info records. */
	IDMap id_map;   /**< Map file IDs to \c FileAnalysis::Info records. */
	StrSet ignored; /**< Ignored files.  Will be finally removed on EOF. */
	PendingList pending; /**< Files waiting for next Tick to return a handle */
};

} // namespace file_analysis

extern file_analysis::Manager* file_mgr;

#endif

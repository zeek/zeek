// See the file "COPYING" in the main distribution directory for copyright.

#ifndef FILE_ANALYSIS_MANAGER_H
#define FILE_ANALYSIS_MANAGER_H

#include <string>
#include <map>
#include <set>
#include <queue>

#include "Net.h"
#include "AnalyzerTags.h"
#include "Conn.h"
#include "Val.h"
#include "Analyzer.h"
#include "Timer.h"
#include "EventHandler.h"

#include "File.h"
#include "FileTimer.h"

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
	 * @return a prettified MD5 hash of \a handle, truncated to 64-bits.
	 */
	string HashHandle(const string& handle) const;

	/**
	 * Take in a unique file handle string to identify incoming file data.
	 */
	void SetHandle(const string& handle);

	/**
	 * Pass in non-sequential file data.
	 */
	void DataIn(const u_char* data, uint64 len, uint64 offset,
		    AnalyzerTag::Tag tag, Connection* conn, bool is_orig);

	/**
	 * Pass in sequential file data.
	 */
	void DataIn(const u_char* data, uint64 len, AnalyzerTag::Tag tag,
	            Connection* conn, bool is_orig);

	/**
	 * Pass in sequential file data from external source (e.g. input framework).
	 */
	void DataIn(const u_char* data, uint64 len, const string& file_id,
	            const string& source);

	/**
	 * Signal the end of file data.
	 */
	void EndOfFile(AnalyzerTag::Tag tag, Connection* conn);
	void EndOfFile(AnalyzerTag::Tag tag, Connection* conn, bool is_orig);
	void EndOfFile(const string& file_id);

	/**
	 * Signal a gap in the file data stream.
	 */
	void Gap(uint64 offset, uint64 len, AnalyzerTag::Tag tag, Connection* conn,
	         bool is_orig);

	/**
	 * Provide the expected number of bytes that comprise a file.
	 */
	void SetSize(uint64 size, AnalyzerTag::Tag tag, Connection* conn,
	             bool is_orig);

	/**
	 * Starts ignoring a file, which will finally be removed from internal
	 * mappings on EOF or TIMEOUT.
	 * @return false if file identifier did not map to anything, else true.
	 */
	bool IgnoreFile(const string& file_id);

	/**
	 * If called during a \c file_timeout event handler, requests deferral of
	 * analysis timeout.
	 */
	bool PostponeTimeout(const string& file_id) const;

	/**
	 * Set's an inactivity threshold for the file.
	 */
	bool SetTimeoutInterval(const string& file_id, double interval) const;

	/**
	 * Queue attachment of an analzer to the file identifier.  Multiple
	 * analyzers of a given type can be attached per file identifier at a time
	 * as long as the arguments differ.
	 * @return false if the analyzer failed to be instantiated, else true.
	 */
	bool AddAnalyzer(const string& file_id, RecordVal* args) const;

	/**
	 * Queue removal of an analyzer for a given file identifier.
	 * @return true if the analyzer is active at the time of call, else false.
	 */
	bool RemoveAnalyzer(const string& file_id, const RecordVal* args) const;

	/**
	 * @return whether the file mapped to \a file_id is being ignored.
	 */
	bool IsIgnored(const string& file_id);

protected:
	friend class FileTimer;

	typedef set<string> IDSet;
	typedef map<string, File*> IDMap;

	/**
	 * @return the File object mapped to \a file_id or a null pointer if
	 *         analysis is being ignored for the associated file.  An File
	 *         object may be created if a mapping doesn't exist, and if it did
	 *         exist, the activity time is refreshed along with any
	 *         connection-related fields.
	 */
	File* GetFile(const string& file_id, Connection* conn = 0,
	              AnalyzerTag::Tag tag = AnalyzerTag::Error,
	              bool is_orig = false, bool update_conn = true);

	/**
	 * @return the File object mapped to \a file_id, or a null pointer if no
	 *         mapping exists.
	 */
	File* Lookup(const string& file_id) const;

	/**
	 * Evaluate timeout policy for a file and remove the File object mapped to
	 * \a file_id if needed.
	 */
	void Timeout(const string& file_id, bool is_terminating = ::terminating);

	/**
	 * Immediately remove file_analysis::File object associated with \a file_id.
	 * @return false if file id string did not map to anything, else true.
	 */
	bool RemoveFile(const string& file_id);

	/**
	 * Sets #current_file_id to a hash of a unique file handle string based on
	 * what the \c get_file_handle event derives from the connection params.
	 * Event queue is flushed so that we can get the handle value immediately.
	 */
	void GetFileHandle(AnalyzerTag::Tag tag, Connection* c, bool is_orig);

	/**
	 * @return whether file analysis is disabled for the given analyzer.
	 */
	static bool IsDisabled(AnalyzerTag::Tag tag);

private:
	IDMap id_map;	/**< Map file ID to file_analysis::File records. */
	IDSet ignored;	/**< Ignored files.  Will be finally removed on EOF. */
	string current_file_id;	/**< Hash of what get_file_handle event sets.*/

	static TableVal* disabled;	/**< Table of disabled analyzers. */
};

} // namespace file_analysis

extern file_analysis::Manager* file_mgr;

#endif

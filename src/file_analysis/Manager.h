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
#include "FileID.h"

namespace file_analysis {

/**
 * Main entry point for interacting with file analysis.
 */
class Manager {
friend class FileTimer;

public:

	Manager();

	~Manager();

	/**
	 * Times out any active file analysis to prepare for shutdown.
	 */
	void Terminate();

	/**
	 * Take in a unique file handle string to identifiy incoming file data.
	 */
	void SetHandle(const string& handle);

	/**
	 * Pass in non-sequential file data.
	 */
    void DataIn(const u_char* data, uint64 len, uint64 offset,
                AnalyzerTag::Tag tag, Connection* conn, bool is_orig);
    void DataIn(const u_char* data, uint64 len, uint64 offset,
                const string& unique);
    void DataIn(const u_char* data, uint64 len, uint64 offset,
                File* file);

	/**
	 * Pass in sequential file data.
	 */
	void DataIn(const u_char* data, uint64 len, AnalyzerTag::Tag tag,
	            Connection* conn, bool is_orig);
	void DataIn(const u_char* data, uint64 len, const string& unique);
	void DataIn(const u_char* data, uint64 len, File* file);

	/**
	 * Signal the end of file data.
	 */
	void EndOfFile(AnalyzerTag::Tag tag, Connection* conn);
	void EndOfFile(AnalyzerTag::Tag tag, Connection* conn, bool is_orig);
	void EndOfFile(const string& unique);

	/**
	 * Signal a gap in the file data stream.
	 */
	void Gap(uint64 offset, uint64 len, AnalyzerTag::Tag tag, Connection* conn,
	         bool is_orig);
	void Gap(uint64 offset, uint64 len, const string& unique);
	void Gap(uint64 offset, uint64 len, File* file);

	/**
	 * Provide the expected number of bytes that comprise a file.
	 */
	void SetSize(uint64 size, AnalyzerTag::Tag tag, Connection* conn,
	             bool is_orig);
	void SetSize(uint64 size, const string& unique);
	void SetSize(uint64 size, File* file);

	/**
	 * Starts ignoring a file, which will finally be removed from internal
	 * mappings on EOF or TIMEOUT.
	 * @return false if file identifier did not map to anything, else true.
	 */
	bool IgnoreFile(const FileID& file_id);

	/**
	 * If called during a \c file_timeout event handler, requests deferral of
	 * analysis timeout.
	 */
	bool PostponeTimeout(const FileID& file_id) const;

	/**
	 * Set's an inactivity threshold for the file.
	 */
	bool SetTimeoutInterval(const FileID& file_id, double interval) const;

	/**
	 * Queue attachment of an analzer to the file identifier.  Multiple
	 * analyzers of a given type can be attached per file identifier at a time
	 * as long as the arguments differ.
	 * @return false if the analyzer failed to be instantiated, else true.
	 */
	bool AddAnalyzer(const FileID& file_id, RecordVal* args) const;

	/**
	 * Queue removal of an analyzer for a given file identifier.
	 * @return true if the analyzer is active at the time of call, else false.
	 */
	bool RemoveAnalyzer(const FileID& file_id, const RecordVal* args) const;

	/**
	 * @return whether the file mapped to \a unique is being ignored.
	 */
	bool IsIgnored(const string& unique);

protected:

	typedef map<string, File*> StrMap;
	typedef set<string> StrSet;
	typedef map<FileID, File*> IDMap;

	/**
	 * @return the File object mapped to \a unique or a null pointer if analysis
	 *         is being ignored for the associated file.  An File object may be
	 *         created if a mapping doesn't exist, and if it did exist, the
	 *         activity time is refreshed along with any connection-related
	 *         fields.
	 */
	File* GetFile(const string& unique, Connection* conn = 0,
	              AnalyzerTag::Tag tag = AnalyzerTag::Error);

	/**
	 * @return the File object mapped to \a file_id, or a null pointer if no
	 *         mapping exists.
	 */
	File* Lookup(const FileID& file_id) const;

	/**
	 * Evaluate timeout policy for a file and remove the File object mapped to
	 * \a file_id if needed.
	 */
	void Timeout(const FileID& file_id, bool is_terminating = ::terminating);

	/**
	 * Immediately remove file_analysis::File object associated with \a unique.
	 * @return false if file string did not map to anything, else true.
	 */
	bool RemoveFile(const string& unique);

	/**
	 * Sets #current_handle to a unique file handle string based on what the
	 * \c get_file_handle event derives from the connection params.  The
	 * event queue is flushed so that we can get the handle value immediately.
	 */
	void GetFileHandle(AnalyzerTag::Tag tag, Connection* c, bool is_orig);

	/**
	 * @return whether file analysis is disabled for the given analyzer.
	 */
	static bool IsDisabled(AnalyzerTag::Tag tag);

	StrMap str_map; /**< Map unique string to file_analysis::File. */
	IDMap id_map;   /**< Map file ID to file_analysis::File records. */
	StrSet ignored; /**< Ignored files.  Will be finally removed on EOF. */
	string current_handle; /**< Last file handle set by get_file_handle event.*/

	static TableVal* disabled; /**< Table of disabled analyzers. */
};

} // namespace file_analysis

extern file_analysis::Manager* file_mgr;

#endif

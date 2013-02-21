#ifndef FILE_ANALYSIS_FILEID_H
#define FILE_ANALYSIS_FILEID_H

namespace file_analysis {

/**
 * A simple string wrapper class to help enforce some type safety between
 * methods of FileAnalysis::Manager, some of which use a unique string to
 * identify files, and others which use a pretty hash (the FileID) to identify
 * files.  A FileID is primarily used in methods which interface with the
 * script-layer, while the unique strings are used for methods which interface
 * with protocol analyzers (to better accomodate the possibility that a file
 * can be distributed over different connections and thus analyzer instances).
 */
struct FileID {
	string id;

	explicit FileID(const string arg_id) : id(arg_id) {}
	FileID(const FileID& other) : id(other.id) {}

	const char* c_str() const { return id.c_str(); }

	bool operator==(const FileID& rhs) const { return id == rhs.id; }
	bool operator<(const FileID& rhs) const { return id < rhs.id; }

	FileID& operator=(const FileID& rhs) { id = rhs.id; return *this; }
	FileID& operator=(const string& rhs) { id = rhs; return *this; }
};

} // namespace file_analysis

#endif

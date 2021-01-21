// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>
#include <list>
#include <vector>

namespace zeek::detail {

// Script file we have already scanned (or are in the process of scanning).
// They are identified by normalized realpath.
class ScannedFile {

public:

	ScannedFile(int arg_include_level,
	            std::string arg_name, bool arg_skipped = false,
	            bool arg_prefixes_checked = false);

	/**
	 * Compares the canonical path of this file against every canonical path
	 * in files_scanned and returns whether there's any match.
	 */
	bool AlreadyScanned() const;

	int include_level;
	bool skipped;		// This ScannedFile was @unload'd.
	bool prefixes_checked;	// If loading prefixes for this file has been tried.
	std::string name;
	std::string canonical_path; // normalized, absolute path via realpath()

	static auto constexpr canonical_stdin_path = "<stdin>";
};

extern std::list<ScannedFile> files_scanned;
extern std::vector<std::string> sig_files;

} // namespace zeek::detail

// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <zeek/Obj.h>
#include <list>
#include <optional>
#include <string>
#include <vector>

namespace zeek::detail {

// Script file we have already scanned (or are in the process of scanning).
// They are identified by normalized canonical path.
//
// If arg_is_canonical is set to true, assume arg_name is canonicalized and
// skip resolving the canonical name.
class ScannedFile {
public:
    ScannedFile(int arg_include_level, std::string arg_name, bool arg_skipped = false,
                bool arg_prefixes_checked = false, bool arg_is_canonical = false);

    /**
     * Compares the canonical path of this file against every canonical path
     * in files_scanned and returns whether there's any match.
     */
    bool AlreadyScanned() const;

    int include_level;
    bool skipped;          // This ScannedFile was @unload'd.
    bool prefixes_checked; // If loading prefixes for this file has been tried.
    std::string name;
    std::string canonical_path; // normalized, absolute path via std::filesystem::canonical()

    static auto constexpr canonical_stdin_path = "<stdin>";
};

extern std::list<ScannedFile> files_scanned;

struct SignatureFile {
    std::string file;
    std::optional<std::string> full_path;
    Location load_location;

    SignatureFile(std::string file);
    SignatureFile(std::string file, std::string full_path, Location load_location);
};

extern std::vector<SignatureFile> sig_files;

} // namespace zeek::detail

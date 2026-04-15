// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/ScannedFile.h"

#include <cerrno>
#include <filesystem>

#ifdef _MSC_VER
#include <io.h> // _access
#else
#include <unistd.h> // access
#endif

#include "zeek/DebugLogger.h"
#include "zeek/Reporter.h"

namespace zeek::detail {

std::list<ScannedFile> files_scanned;
std::vector<SignatureFile> sig_files;

ScannedFile::ScannedFile(int arg_include_level, std::string arg_name, bool arg_skipped, bool arg_prefixes_checked,
                         bool arg_is_canonical)
    : include_level(arg_include_level),
      skipped(arg_skipped),
      prefixes_checked(arg_prefixes_checked),
      name(std::move(arg_name)) {
    if ( name == canonical_stdin_path )
        canonical_path = canonical_stdin_path;
    else if ( ! arg_is_canonical ) {
        std::error_code ec;
        auto canon = std::filesystem::canonical(name, ec);
        if ( ec ) {
            // canonical() failed — check if the file is actually accessible
            // (e.g. via a virtual/redirected filesystem that hooks access()
            // but not the Win32 APIs used by std::filesystem::canonical).
#ifdef _MSC_VER
            auto accessible = _access(name.data(), 0) == 0;
#else
            auto accessible = access(name.data(), F_OK) == 0;
#endif
            if ( accessible )
                canonical_path = std::filesystem::path(name).lexically_normal().string();
            else
                zeek::reporter->FatalError("failed to get canonical path of %s: %s", name.data(), ec.message().c_str());
        }
        else
            canonical_path = canon.string();
    }
    else {
        canonical_path = name;
    }
}

bool ScannedFile::AlreadyScanned() const {
    auto rval = false;

    for ( const auto& it : files_scanned )
        if ( it.canonical_path == canonical_path ) {
            rval = true;
            break;
        }

    DBG_LOG(zeek::DBG_SCRIPTS, "AlreadyScanned result (%d) %s", rval, canonical_path.data());
    return rval;
}

SignatureFile::SignatureFile(std::string file) : file(std::move(file)) {}

SignatureFile::SignatureFile(std::string file, std::string full_path, Location load_location)
    : file(std::move(file)), full_path(std::move(full_path)), load_location(load_location) {}

} // namespace zeek::detail

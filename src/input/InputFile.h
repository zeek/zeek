// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdio>
#include <fstream>
#include <string>

#ifdef _WIN32

#include <istream>
#include <memory>

namespace zeek::input::reader::detail {

class WinShareDeleteBuf;

/**
 * A file input stream that opens files with FILE_SHARE_DELETE on Windows.
 *
 * On POSIX, open file descriptors survive renames because they reference
 * inodes. On Windows, std::ifstream opens files without FILE_SHARE_DELETE,
 * which prevents external renames/moves while the file is open. This class
 * uses CreateFileA with FILE_SHARE_DELETE to match POSIX semantics.
 */
class InputFile : public std::istream {
public:
    InputFile();
    explicit InputFile(const std::string& path, std::ios_base::openmode mode = std::ios_base::in);
    ~InputFile();

    InputFile(const InputFile&) = delete;
    InputFile& operator=(const InputFile&) = delete;

    void open(const std::string& path, std::ios_base::openmode mode = std::ios_base::in);
    bool is_open() const;
    void close();

private:
    std::unique_ptr<WinShareDeleteBuf> buf_;
};

} // namespace zeek::input::reader::detail

#else

namespace zeek::input::reader::detail {

using InputFile = std::ifstream;

} // namespace zeek::input::reader::detail

#endif

namespace zeek::input::reader::detail {

/// Returns true if the path is absolute (starts with '/' on POSIX, or a
/// drive letter like 'C:/' or 'C:\' on Windows).
inline bool is_absolute_path(const std::string& p) {
    if ( p.empty() )
        return false;
    if ( p.front() == '/' )
        return true;
#ifdef _WIN32
    if ( p.size() >= 3 && std::isalpha(static_cast<unsigned char>(p[0])) && p[1] == ':' &&
         (p[2] == '/' || p[2] == '\\') )
        return true;
#endif
    return false;
}

/// Opens a file with FILE_SHARE_DELETE on Windows so that external
/// renames/moves succeed while the file is open. On other platforms
/// this is just fopen().
FILE* fopen_with_share_delete(const char* path, const char* mode);

/// Returns a reliable inode-like identifier for the file at the given path.
/// On Windows, stat().st_ino is always 0, so this uses GetFileInformationByHandle
/// to obtain the NTFS file index instead. On other platforms, returns stat_ino as-is.
uint64_t reliable_inode(const char* path, uint64_t stat_ino);

} // namespace zeek::input::reader::detail

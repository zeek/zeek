// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdio>
#include <string>

#ifdef _WIN32
#include <cstdint>
#include <istream>
#include <memory>
#else
#include <sys/types.h>
#include <fstream>
#endif

namespace zeek::input::reader::detail {

#ifdef _WIN32

/// MSVC defines ino_t as unsigned short (16-bit), too small for 64-bit NTFS
/// file indices from GetFileInformationByHandle.  Use uint64_t on Windows.
using file_ino_t = uint64_t;

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

#else

using InputFile = std::ifstream;

/// On POSIX, ino_t is already large enough for inodes.
using file_ino_t = ino_t;

#endif

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
file_ino_t reliable_inode(const char* path, file_ino_t stat_ino);

} // namespace zeek::input::reader::detail

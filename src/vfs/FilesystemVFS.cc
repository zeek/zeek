// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/vfs/FilesystemVFS.h"

#include <sys/stat.h>
#include <cerrno>
#include <cstring>
#include <filesystem>

#ifdef _MSC_VER
#include <io.h>
#define access _access
#define R_OK 4
#define stat _stat
#else
#include <unistd.h>
#endif

#include "zeek/Reporter.h"

namespace zeek::vfs {

bool FilesystemVFS::HasFile(const std::string& path) const {
    struct stat st;
    if ( stat(path.c_str(), &st) < 0 )
        return false;
    return S_ISREG(st.st_mode);
}

bool FilesystemVFS::HasDir(const std::string& path) const {
    struct stat st;
    if ( stat(path.c_str(), &st) < 0 )
        return false;
    return S_ISDIR(st.st_mode);
}

std::optional<VFSResult> FilesystemVFS::ReadFile(const std::string& path) const {
    FILE* f = fopen(path.c_str(), "rb");
    if ( ! f )
        return std::nullopt;

    fseek(f, 0, SEEK_END);
    auto size = ftell(f);
    fseek(f, 0, SEEK_SET);

    std::string content(size, '\0');
    if ( fread(content.data(), 1, size, f) != static_cast<size_t>(size) ) {
        fclose(f);
        return std::nullopt;
    }
    fclose(f);

    // Build a canonical identifier for deduplication.
    std::string identifier;
    std::error_code ec;
    auto canon = std::filesystem::canonical(path, ec);
    if ( ! ec )
        identifier = canon.string();
    else
        identifier = std::filesystem::path(path).lexically_normal().string();

    return VFSResult{std::move(content), std::move(identifier)};
}

} // namespace zeek::vfs

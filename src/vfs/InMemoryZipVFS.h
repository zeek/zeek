// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "zeek/vfs/VFS.h"

struct zip;
typedef struct zip zip_t;

namespace zeek::vfs {

/**
 * VFS provider backed by in-memory ZIP archives.
 *
 * ZIP archives are loaded from in-memory buffers and files are served
 * directly from the compressed data without extracting to disk.
 *
 * Path lookups normalize platform-specific separators to forward slashes
 * and collapse "." / ".." segments to match ZIP entry names.
 */
class InMemoryZipVFS : public VFS {
public:
    InMemoryZipVFS();
    ~InMemoryZipVFS() override;

    InMemoryZipVFS(const InMemoryZipVFS&) = delete;
    InMemoryZipVFS& operator=(const InMemoryZipVFS&) = delete;

    std::string Name() const override { return "InMemoryZipVFS"; }

    /**
     * Add a ZIP archive from an in-memory buffer. The provider copies the
     * buffer so the caller does not need to keep it alive.
     * @param data Pointer to the ZIP data in memory.
     * @param size Size of the ZIP data in bytes.
     * @param mount_root Filesystem path prefix that maps to the ZIP root.
     *   When Zeek resolves a script to e.g. "C:/zeek/scripts/ndr/main.zeek",
     *   and mount_root is "C:/zeek/scripts", the lookup strips the prefix
     *   and searches for "ndr/main.zeek" inside the archive.
     * @return true on success, false if the buffer is not a valid ZIP.
     */
    bool AddArchive(const void* data, size_t size, const std::string& mount_root = "");

    bool HasFile(const std::string& path) const override;
    bool HasDir(const std::string& path) const override;
    std::optional<VFSResult> ReadFile(const std::string& path) const override;

    /**
     * Normalize a filesystem path into ZIP-canonical form.
     * Converts backslashes to forward slashes, collapses . and ..,
     * removes leading "./" prefix.
     */
    static std::string NormalizePath(const std::string& path);

private:
    struct Archive {
        std::vector<uint8_t> data; // owned copy of ZIP bytes
        zip_t* handle = nullptr;
        std::string mount_root; // filesystem prefix to strip before lookup
    };

    /// Strip mount_root from the given normalized path. Returns the
    /// archive-relative path, or the input unchanged if mount_root
    /// does not match.
    static std::string StripMountRoot(const std::string& normalized, const Archive& archive);

    std::vector<Archive> archives_;
};

} // namespace zeek::vfs

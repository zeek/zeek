// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

struct zip;
typedef struct zip zip_t;

namespace zeek::util {

/**
 * Provides read-only access to Zeek script files stored in ZIP archives.
 * ZIP archives are loaded from in-memory buffers and files are served directly
 * from the compressed data without extracting to disk.
 *
 * Path lookups normalize platform-specific separators to forward slashes
 * and collapse "." / ".." segments to match ZIP entry names.
 */
class ZipScriptProvider {
public:
    ZipScriptProvider();
    ~ZipScriptProvider();

    ZipScriptProvider(const ZipScriptProvider&) = delete;
    ZipScriptProvider& operator=(const ZipScriptProvider&) = delete;

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

    /**
     * Check whether a file entry exists in any loaded archive.
     * @param path Virtual path, e.g. "ndr/main.zeek".
     */
    bool HasFile(const std::string& path) const;

    /**
     * Check whether a directory exists in any loaded archive.
     * Directories are detected even when the ZIP has no explicit directory
     * entries — any entry with the prefix "dir/" implies the directory exists.
     * @param path Virtual path, e.g. "ndr/protocols".
     */
    bool HasDir(const std::string& path) const;

    /**
     * Read the entire contents of a file from the first archive that
     * contains it.
     * @param path Virtual path.
     * @return File contents, or std::nullopt if not found.
     */
    std::optional<std::string> ReadFile(const std::string& path) const;

    /**
     * Normalize a filesystem path into ZIP-canonical form.
     * Converts backslashes to forward slashes, collapses . and ..,
     * removes leading "./" prefix.
     */
    static std::string NormalizePath(const std::string& path);

    /** Access the global singleton (may be nullptr). */
    static ZipScriptProvider* GetInstance();

    /** Install a global singleton. Pass nullptr to clear. */
    static void SetInstance(std::unique_ptr<ZipScriptProvider> provider);

private:
    struct Archive {
        std::vector<uint8_t> data; // owned copy of ZIP bytes
        zip_t* handle = nullptr;
        std::string mount_root; // filesystem prefix to strip before lookup
    };

    std::vector<Archive> archives;

    static std::unique_ptr<ZipScriptProvider> instance;
};

} // namespace zeek::util

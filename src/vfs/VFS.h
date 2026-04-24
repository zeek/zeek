// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <optional>
#include <string>

namespace zeek::vfs {

/**
 * Metadata and content returned by a VFS provider when reading a file.
 */
struct VFSResult {
    /// The content of the file.
    std::string content;

    /// A stable identifier for deduplication ("already-loaded" detection).
    /// For disk files this is the canonical/absolute path; for ZIP entries
    /// it might be "zip://<archive>#<entry>" or similar.
    std::string identifier;
};

/**
 * Abstract base class for virtual filesystem providers.
 *
 * Concrete implementations serve file content from the real filesystem,
 * in-memory ZIP archives, or any other source.  Providers are registered
 * with the global VFS Manager and queried in priority order.
 */
class VFS {
public:
    virtual ~VFS() = default;

    /// Human-readable name for logging / debugging.
    virtual std::string Name() const = 0;

    /// Return true if \a path names a readable file in this provider.
    virtual bool HasFile(const std::string& path) const = 0;

    /// Return true if \a path names a directory in this provider.
    virtual bool HasDir(const std::string& path) const = 0;

    /**
     * Read a file and return its content plus a stable identifier.
     * Returns std::nullopt if the file does not exist in this provider.
     */
    virtual std::optional<VFSResult> ReadFile(const std::string& path) const = 0;
};

} // namespace zeek::vfs

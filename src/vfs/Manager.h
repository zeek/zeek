// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "zeek/vfs/VFS.h"

namespace zeek::vfs {

/**
 * Global VFS manager that dispatches file queries to registered providers
 * in priority order (highest priority first).
 *
 * Providers are registered with RegisterProvider() and queried in
 * descending priority.  A FilesystemVFS is always present as the
 * lowest-priority fallback and does not need to be registered manually.
 *
 * Access via zeek::vfs_mgr (set up during zeek_init()).
 */
class Manager {
public:
    Manager();

    /**
     * Register a VFS provider with the given priority.
     * Higher priority providers are queried first.
     * The FilesystemVFS fallback has priority 0; use values > 0 for
     * providers that should override filesystem lookups.
     */
    void RegisterProvider(std::unique_ptr<VFS> provider, int priority);

    /// Check whether any provider considers \a path a readable file.
    bool HasFile(const std::string& path) const;

    /// Check whether any provider considers \a path a directory.
    bool HasDir(const std::string& path) const;

    /**
     * Read a file from the first provider that has it.
     * Returns std::nullopt if no provider can serve the file.
     */
    std::optional<VFSResult> ReadFile(const std::string& path) const;

    /// Check whether \a path is accessible (file or directory) in any provider.
    bool CanRead(const std::string& path) const;

private:
    struct Entry {
        std::unique_ptr<VFS> provider;
        int priority;
    };

    std::vector<Entry> providers_;
};

// Global VFS manager instance (set up by zeek-setup.cc).
extern Manager* vfs_mgr;

} // namespace zeek::vfs

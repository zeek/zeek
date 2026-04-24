// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <string>

#include "zeek/vfs/VFS.h"

namespace zeek::vfs {

/**
 * VFS provider backed by the real operating-system filesystem.
 *
 * HasFile/HasDir use stat(2) and access(2); ReadFile opens the file
 * with fopen and returns its content.  The identifier is the
 * canonical (absolute, symlink-resolved) path.
 */
class FilesystemVFS : public VFS {
public:
    std::string Name() const override { return "FilesystemVFS"; }

    bool HasFile(const std::string& path) const override;
    bool HasDir(const std::string& path) const override;
    std::optional<VFSResult> ReadFile(const std::string& path) const override;
};

} // namespace zeek::vfs

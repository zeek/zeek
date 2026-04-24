// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/vfs/Manager.h"

#include <algorithm>

#include "zeek/vfs/FilesystemVFS.h"

namespace zeek::vfs {

Manager* vfs_mgr = nullptr;

Manager::Manager() {
    // Always install the filesystem as the lowest-priority fallback.
    auto fs = std::make_unique<FilesystemVFS>();
    providers_.push_back({std::move(fs), 0});
}

void Manager::RegisterProvider(std::unique_ptr<VFS> provider, int priority) {
    providers_.push_back({std::move(provider), priority});

    // Keep sorted by descending priority so iteration is front-to-back.
    std::stable_sort(providers_.begin(), providers_.end(),
                     [](const Entry& a, const Entry& b) { return a.priority > b.priority; });
}

bool Manager::HasFile(const std::string& path) const {
    for ( const auto& e : providers_ )
        if ( e.provider->HasFile(path) )
            return true;
    return false;
}

bool Manager::HasDir(const std::string& path) const {
    for ( const auto& e : providers_ )
        if ( e.provider->HasDir(path) )
            return true;
    return false;
}

std::optional<VFSResult> Manager::ReadFile(const std::string& path) const {
    for ( const auto& e : providers_ ) {
        auto result = e.provider->ReadFile(path);
        if ( result )
            return result;
    }
    return std::nullopt;
}

bool Manager::CanRead(const std::string& path) const { return HasFile(path) || HasDir(path); }

} // namespace zeek::vfs

// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <mutex>

#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::detail::Zeek_RawReader {

class Plugin : public plugin::Plugin {
public:
    Plugin() = default;

    plugin::Configuration Configure() override;

    void InitPreScript() override;
    void Done() override;

    std::unique_lock<std::mutex> ForkMutex();

private:
    std::mutex fork_mutex;
};

extern Plugin plugin;

} // namespace zeek::plugin::detail::Zeek_RawReader

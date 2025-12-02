// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/plugin/Plugin.h"

namespace zeek::cluster::table {

class Plugin final : public plugin::Plugin {
public:
    plugin::Configuration Configure() override {
        plugin::Configuration config;
        config.name = "Zeek::Cluster_Table";
        config.description = "Supporting functions for table synchronization";
        return config;
    }
};

extern Plugin plugin;

} // namespace zeek::cluster::table

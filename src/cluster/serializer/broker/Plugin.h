// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::Zeek_Cluster_Serializer_Broker {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override;
} plugin;

} // namespace zeek::plugin::Zeek_Cluster_Serializer_Broker

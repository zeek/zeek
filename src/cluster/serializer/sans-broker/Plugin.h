// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/plugin/Plugin.h"

namespace zeek::plugin::Sans_Broker_Serializer {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override;
};

extern Plugin plugin;

} // namespace zeek::plugin::Sans_Broker_Serializer

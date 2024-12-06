// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"
#include "zeek/analyzer/protocol/stream_event/StreamEvent.h"

namespace zeek::plugin::detail::Zeek_StreamEvent {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(new zeek::analyzer::Component("STREAM_EVENT",
                                                   zeek::analyzer::stream_event::StreamEvent_Analyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::StreamEvent";
        config.description = "Delivers stream data as events";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_StreamEvent

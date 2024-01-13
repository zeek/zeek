// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/analyzer/Component.h"

#include "analyzer/protocol/websocket/WebSocket.h"

namespace zeek::plugin::detail::Zeek_WebSocket {

class Plugin : public zeek::plugin::Plugin {
public:
    zeek::plugin::Configuration Configure() override {
        AddComponent(
            new zeek::analyzer::Component("WebSocket", zeek::analyzer::websocket::WebSocket_Analyzer::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::WebSocket";
        config.description = "WebSocket analyzer";
        return config;
    }
} plugin;

} // namespace zeek::plugin::detail::Zeek_WebSocket

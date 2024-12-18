// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/websocket/Plugin.h"

#include "zeek/cluster/websocket/WebSocket.h"

namespace zeek::plugin::Cluster_WebSocket {
// Definition of plugin.
Plugin plugin;
}; // namespace zeek::plugin::Cluster_WebSocket

namespace zeek::plugin::Cluster_WebSocket {

zeek::plugin::Configuration Plugin::Configure() {
    zeek::plugin::Configuration config;
    config.name = "Zeek::Cluster_WebSocket";
    config.description = "Provides WebSocket access to a Zeek cluster";
    return config;
}

void Plugin::InitPostScript() {
    // Just delegate.
    zeek::cluster::websocket::InitPostScript();
}

void Plugin::Done() {
    // Just delegate.
    zeek::cluster::websocket::Done();
}

} // namespace zeek::plugin::Cluster_WebSocket

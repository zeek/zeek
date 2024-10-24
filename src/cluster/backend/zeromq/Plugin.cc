#include "Plugin.h"

#include "zeek/cluster/Component.h"

#include "ZeroMQ.h"


namespace zeek::plugin::Zeek_Cluster_Backend_ZeroMQ {

Plugin plugin;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(new cluster::BackendComponent("ZeroMQ", zeek::cluster::zeromq::ZeroMQBackend::Instantiate));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Cluster_Backend_ZeroMQ";
    config.description = "Cluster backend using ZeroMQ";
    return config;
}

} // namespace zeek::plugin::Zeek_Cluster_Backend_ZeroMQ

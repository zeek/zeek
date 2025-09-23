// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/plugin/Plugin.h"

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Component.h"
#include "zeek/cluster/Serializer.h"

namespace {

using namespace zeek::cluster;

/**
 * A backend that does nothing.
 */
class NoneBackend : public ThreadedBackend {
private:
    void DoInitPostScript() override {};
    bool DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header, const std::string& format,
                            zeek::byte_buffer& buf) override {
        return true;
    }
    bool DoPublishEvent(const std::string& topic, const std::string& format, const zeek::byte_buffer& buf) override {
        return true;
    };
    bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) override { return true; };
    bool DoUnsubscribe(const std::string& topic_prefix) override { return true; };

public:
    NoneBackend(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                std::unique_ptr<detail::EventHandlingStrategy> ehs)
        : ThreadedBackend("None", std::move(es), std::move(ls), std::move(ehs)) {}

    static std::unique_ptr<Backend> Instantiate(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                                                std::unique_ptr<detail::EventHandlingStrategy> ehs) {
        return std::make_unique<NoneBackend>(std::move(es), std::move(ls), std::move(ehs));
    }
};
} // namespace


namespace zeek::plugin::Zeek_Cluster_None {

class Plugin : public zeek::plugin::Plugin {
    zeek::plugin::Configuration Configure() override {
        AddComponent(new cluster::BackendComponent("None", NoneBackend::Instantiate));

        zeek::plugin::Configuration config;
        config.name = "Zeek::Cluster_Backend_None";
        config.description = "Cluster backend none";
        return config;
    }
} plugin;

} // namespace zeek::plugin::Zeek_Cluster_None

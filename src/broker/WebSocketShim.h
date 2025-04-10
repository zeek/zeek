// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <broker/endpoint.hh>
#include <broker/zeek.hh> // for ProcessMessage()
#include <memory>
#include <stdexcept>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/iosource/IOSource.h"

#include "Manager.h"

namespace zeek::Broker {

class WebSocketState;

/**
 * A cluster::Backend implementation used by WebSocket clients
 * when the actual cluster backend is Broker.
 *
 * The WebSocket client owns a "hub" instance that is attached to the
 * local endpoint.
 */
class WebSocketShim : public zeek::cluster::Backend, zeek::iosource::IOSource {
public:
    WebSocketShim(std::unique_ptr<zeek::cluster::EventSerializer> es, std::unique_ptr<zeek::cluster::LogSerializer> ls,
                  std::unique_ptr<zeek::cluster::detail::EventHandlingStrategy> ehs);
    ~WebSocketShim();

    /**
     * Component factory.
     */
    static std::unique_ptr<Backend> Instantiate(std::unique_ptr<zeek::cluster::EventSerializer> es,
                                                std::unique_ptr<zeek::cluster::LogSerializer> ls,
                                                std::unique_ptr<zeek::cluster::detail::EventHandlingStrategy> ehs) {
        return std::make_unique<WebSocketShim>(std::move(es), std::move(ls), std::move(ehs));
    }

    // IO source methods.
    const char* Tag() override { return "broker-ws-shim"; }
    void Process() override;
    double GetNextTimeout() override { return -1; }

private:
    // Cluster backend methods.
    void DoInitPostScript() override {}
    bool DoInit() override;
    void DoTerminate() override;
    bool DoPublishEvent(const std::string& topic, const zeek::cluster::detail::Event& event) override;
    bool DoPublishEvent(const std::string& topic, const std::string& format,
                        const zeek::cluster::detail::byte_buffer& buf) override {
        throw new std::logic_error("not implemented");
    }
    bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) override;
    bool DoUnsubscribe(const std::string& topic_prefix) override;
    bool DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header, const std::string& format,
                            zeek::cluster::detail::byte_buffer& buf) override {
        throw new std::logic_error("not implemented");
    }

    // visit_as_message received from broker::subscriber
    void ProcessMessage(std::string_view topic, broker::zeek::Batch& batch);
    void ProcessMessage(std::string_view topic, broker::zeek::Event& ev);
    void ProcessMessage(std::string_view topic, broker::zeek::Invalid& invalid);
    void ProcessMessage(std::string_view topic, broker::zeek::LogCreate& lc) {
        throw new std::logic_error("not implemented");
    }
    void ProcessMessage(std::string_view topic, broker::zeek::LogWrite& lw) {
        throw new std::logic_error("not implemented");
    }
    void ProcessMessage(std::string_view topic, broker::zeek::IdentifierUpdate& iu) {
        throw new std::logic_error("not implemented");
    }

    std::unique_ptr<WebSocketState> state;
};


} // namespace zeek::Broker

// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <broker/endpoint.hh>
#include <broker/zeek.hh> // for ProcessMessage()
#include <memory>
#include <stdexcept>

#include "zeek/cluster/Backend.h"
#include "zeek/cluster/Serializer.h"

namespace zeek::Broker {

class WebSocketState;

/**
 * A cluster::Backend implementation used by WebSocket clients
 * when the cluster backend is Broker.
 *
 * A WebSocketShim instance owns a broker hub instance that is attached
 * to the local broker endpoint. The hub is used for publish/subscribe
 * functionality for a given WebSocket client.
 */
class WebSocketShim : public zeek::cluster::Backend {
public:
    WebSocketShim(std::unique_ptr<zeek::cluster::EventSerializer> es, std::unique_ptr<zeek::cluster::LogSerializer> ls,
                  std::unique_ptr<zeek::cluster::detail::EventHandlingStrategy> ehs);
    ~WebSocketShim() override;

    /**
     * Component factory.
     */
    static std::unique_ptr<Backend> Instantiate(std::unique_ptr<zeek::cluster::EventSerializer> es,
                                                std::unique_ptr<zeek::cluster::LogSerializer> ls,
                                                std::unique_ptr<zeek::cluster::detail::EventHandlingStrategy> ehs) {
        return std::make_unique<WebSocketShim>(std::move(es), std::move(ls), std::move(ehs));
    }

    // Called by the IO source when the hub's fd is ready.
    void Process();

private:
    // Cluster backend methods.
    void DoInitPostScript() override {}
    bool DoInit() override;
    void DoTerminate() override;
    bool DoPublishEvent(const std::string& topic, zeek::cluster::Event& event) override;
    bool DoPublishEvent(const std::string& topic, const std::string& format, const zeek::byte_buffer& buf) override {
        throw new std::logic_error("not implemented");
    }
    bool DoSubscribe(const std::string& topic_prefix, SubscribeCallback cb) override;
    bool DoUnsubscribe(const std::string& topic_prefix) override;
    bool DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header, const std::string& format,
                            zeek::byte_buffer& buf) override {
        // WebSocket clients do not publish log writes.
        throw new std::logic_error("not implemented");
    }

    // Methods called by broker::zeek::visit_as_message() for messages received from hub::poll().
    void ProcessMessage(std::string_view topic, broker::zeek::Batch& batch);
    void ProcessMessage(std::string_view topic, broker::zeek::Event& ev);
    void ProcessMessage(std::string_view topic, broker::zeek::Invalid& invalid);
    void ProcessMessage(std::string_view topic, broker::zeek::LogCreate& lc) {
        // WebSocket clients should not receive log create messages.
        throw new std::logic_error("not implemented");
    }
    void ProcessMessage(std::string_view topic, broker::zeek::LogWrite& lw) {
        // WebSocket clients should not receive log writes.
        throw new std::logic_error("not implemented");
    }
    void ProcessMessage(std::string_view topic, broker::zeek::IdentifierUpdate& iu) {
        // WebSocket clients should not receive identifier updates.
        throw new std::logic_error("not implemented");
    }

    class IOSource;

    std::unique_ptr<WebSocketState> state;
    IOSource* iosrc = nullptr;
};

} // namespace zeek::Broker

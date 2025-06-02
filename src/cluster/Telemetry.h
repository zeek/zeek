// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstddef>
#include <memory>
#include <string_view>

#include "session/Manager.h"
#include "telemetry/Histogram.h"

namespace zeek::cluster {

class Backend;

namespace detail {

class Event;

class MessageInfo {
public:
    explicit MessageInfo(size_t size) : size(size) {}

    size_t Size() const { return size; }

private:
    size_t size;
};

using TopicNormalizer = std::function<std::string_view(std::string_view)>;

/**
 * A topic normalizer using the Cluster::Telemetry::topic_normalizations table.
 */
class TableTopicNormalizer {
public:
    TableTopicNormalizer();
    std::string_view operator()(std::string_view topic);

private:
    zeek::TableValPtr topic_normalizations;
};

class Telemetry {
public:
    virtual ~Telemetry() = default;

    virtual void OutgoingEvent(const std::string_view topic, const Event& e, const MessageInfo& info) = 0;
    virtual void IncomingEvent(const std::string_view topic, const Event& e, const MessageInfo& info) = 0;
};

using TelemetryPtr = std::unique_ptr<Telemetry>;

// Null telemetry used for WebSocket clients, or when metrics are
// explicitly disabled.
class NoneTelemetry : public Telemetry {
public:
    void OutgoingEvent(const std::string_view topic, const Event& e, const MessageInfo& info) override;
    void IncomingEvent(const std::string_view topic, const Event& e, const MessageInfo& info) override;
};

/**
 * A telemetry class producing metrics labeled with topics.
 *
 * Note that randomly generated topic names will cause unbounded
 * metrics growth. Should we do something or assume that only few
 * users will actually do this kind of stuff?
 */
class ProductionTelemetry : public Telemetry {
public:
    ProductionTelemetry(TopicNormalizer topic_normalizer);

    void OutgoingEvent(const std::string_view topic, const Event& e, const MessageInfo& info) override;
    void IncomingEvent(const std::string_view topic, const Event& e, const MessageInfo& info) override;

private:
    TopicNormalizer topic_normalizer;
    telemetry::CounterFamilyPtr in, out;
};

/**
 * A telemetry class producing metrics labeled with topics
 * and the script layer location for outgoing metrics.
 */
class DebugTelemetry : public Telemetry {
public:
    DebugTelemetry(TopicNormalizer topic_normalizer, std::vector<double> message_size_bounds);

    void OutgoingEvent(const std::string_view topic, const Event& e, const MessageInfo& info) override;
    void IncomingEvent(const std::string_view topic, const Event& e, const MessageInfo& info) override;

private:
    TopicNormalizer topic_normalizer;
    std::vector<double> message_size_bounds;
    telemetry::HistogramFamilyPtr in, out;
};

/**
 * Reads Cluster::Telemetry consts, instantiates and appropriate Telemetry instance
 * set it on the given backend.
 *
 * @param backend - The cluster backend to configure.
 */
void configure_backend_telemetry(Backend& backend);

} // namespace detail
} // namespace zeek::cluster

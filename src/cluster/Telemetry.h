// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstddef>
#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include "zeek/IntrusivePtr.h"


namespace zeek {

class TableVal;
using TableValPtr = zeek::IntrusivePtr<TableVal>;

namespace telemetry {
class Counter;
using CounterPtr = std::shared_ptr<Counter>;

class CounterFamily;
using CounterFamilyPtr = std::shared_ptr<CounterFamily>;

class HistogramFamily;
using HistogramFamilyPtr = std::shared_ptr<HistogramFamily>;

} // namespace telemetry

namespace cluster {

class Backend;

namespace detail {

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

    virtual void OnOutgoingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) = 0;
    virtual void OnIncomingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) = 0;
};

using TelemetryPtr = std::unique_ptr<Telemetry>;

// Reporting nothing.
class NullTelemetry : public Telemetry {
    void OnOutgoingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) override {}
    void OnIncomingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) override {}
};


// A container for telemetry instances, delegating to its children.
class CompositeTelemetry : public Telemetry {
public:
    void OnOutgoingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) override {
        for ( const auto& c : children )
            c->OnOutgoingEvent(topic, handler_name, info);
    }

    void OnIncomingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) override {
        for ( const auto& c : children )
            c->OnIncomingEvent(topic, handler_name, info);
    }

    void Add(TelemetryPtr child) { children.push_back(std::move(child)); }

private:
    std::vector<TelemetryPtr> children;
};

/**
 * Just one metric for incoming and one for outgoing metrics.
 */
class SimpleTelemetry : public Telemetry {
public:
    SimpleTelemetry();

    void OnOutgoingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) override;
    void OnIncomingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) override;

private:
    telemetry::CounterPtr in, out;
};

/**
 * A telemetry class producing metrics labeled with handler names and topics.
 *
 * Note that randomly generated topic names will cause unbounded
 * metrics growth. A topic_normalizer should be injected to normalize
 * topic names.
 */
class VerboseTelemetry : public Telemetry {
public:
    VerboseTelemetry(TopicNormalizer topic_normalizer);

    void OnOutgoingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) override;
    void OnIncomingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) override;

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
    DebugTelemetry(TopicNormalizer topic_normalizer, std::vector<double> bounds);

    void OnOutgoingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) override;
    void OnIncomingEvent(std::string_view topic, std::string_view handler_name, const MessageInfo& info) override;

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
} // namespace cluster
} // namespace zeek

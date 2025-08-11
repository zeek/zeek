// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/Backend.h"

#include <memory>
#include <optional>
#include <span>

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/cluster/Manager.h"
#include "zeek/cluster/OnLoop.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/cluster/Telemetry.h"
#include "zeek/cluster/cluster.bif.h"
#include "zeek/logging/Manager.h"
#include "zeek/plugin/Manager.h"
#include "zeek/plugin/Plugin.h"
#include "zeek/util.h"

#include "zeek/3rdparty/doctest.h"

using namespace zeek::cluster;

bool detail::LocalEventHandlingStrategy::DoProcessEvent(std::string_view topic, cluster::Event e) {
    auto [handler, args, meta] = std::move(e).Take();
    zeek::event_mgr.Enqueue(std::move(meta), handler, std::move(args), util::detail::SOURCE_BROKER);
    return true;
}

void detail::LocalEventHandlingStrategy::DoProcessLocalEvent(EventHandlerPtr h, zeek::Args args) {
    zeek::event_mgr.Enqueue(h, std::move(args));
}

// Backend errors are raised via a generic Cluster::Backend::error(tag, message) event.
void detail::LocalEventHandlingStrategy::DoProcessError(std::string_view tag, std::string_view message) {
    if ( Cluster::Backend::error )
        zeek::event_mgr.Enqueue(Cluster::Backend::error, zeek::make_intrusive<zeek::StringVal>(tag),
                                zeek::make_intrusive<zeek::StringVal>(message));
}

std::optional<zeek::Args> detail::check_args(const zeek::FuncValPtr& handler, zeek::ArgsSpan args) {
    const auto& func_type = handler->GetType<zeek::FuncType>();

    if ( func_type->Flavor() != zeek::FUNC_FLAVOR_EVENT ) {
        zeek::reporter->Error("unexpected function type for %s: %s", handler->AsFunc()->GetName().c_str(),
                              func_type->FlavorString().c_str());
        return std::nullopt;
    }

    const auto& types = func_type->ParamList()->GetTypes();
    if ( args.size() != types.size() ) {
        zeek::reporter->Error("bad number of arguments for %s: got %zu, expect %zu",
                              handler->AsFunc()->GetName().c_str(), args.size(), types.size());
        return std::nullopt;
    }

    zeek::Args result(args.size());

    for ( size_t i = 0; i < args.size(); i++ ) {
        const auto& a = args[i];
        auto got_type = a->GetType();
        const auto& expected_type = types[i];

        // If called with an unspecified table or set, adopt the expected type
        // as otherwise same_type() fails.
        if ( got_type->Tag() == TYPE_TABLE && got_type->AsTableType()->IsUnspecifiedTable() )
            if ( expected_type->Tag() == TYPE_TABLE && got_type->IsSet() == expected_type->IsSet() )
                got_type = expected_type;

        if ( ! same_type(got_type, expected_type) ) {
            zeek::reporter->Error("event parameter #%zu type mismatch, got %s, expecting %s", i + 1,
                                  zeek::obj_desc_short(got_type).c_str(), zeek::obj_desc_short(expected_type).c_str());
            return std::nullopt;
        }

        result[i] = args[i];
    }

    return result;
}

Backend::Backend(std::string_view arg_name, std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                 std::unique_ptr<detail::EventHandlingStrategy> ehs)
    : name(arg_name),
      event_serializer(std::move(es)),
      log_serializer(std::move(ls)),
      event_handling_strategy(std::move(ehs)) {
    tag = zeek::cluster::manager->Backends().GetComponentTag(name);
    if ( ! tag )
        reporter->InternalError("unknown cluster backend name '%s'; mismatch with tag component?", name.c_str());

    // No telemetry by default.
    telemetry = std::make_unique<detail::NullTelemetry>();
}

bool Backend::Init(std::string nid) {
    SetNodeId(std::move(nid));
    return DoInit();
}

std::optional<Event> Backend::MakeClusterEvent(FuncValPtr handler, ArgsSpan args) const {
    auto checked_args = detail::check_args(handler, args);
    if ( ! checked_args )
        return std::nullopt;


    const auto& eh = zeek::event_registry->Lookup(handler->AsFuncPtr()->GetName());
    if ( ! eh ) {
        zeek::reporter->Error("event registry lookup of '%s' failed", obj_desc_short(handler).c_str());
        return std::nullopt;
    }

    /**
     * If you ever stare at this and wonder: Currently, if someone calls
     * Cluster::publish() from within a remote event in script land, then
     * CurrentEventTime() below will yield the network timestamp of the
     * remote event. That means that the outgoing event from this node will
     * have the network timestamp of the originating node, which may be
     * different from what the local network time is.
     *
     * This could be confusing and another policy might be to always set
     * the network timestamp metadata for for outgoing events to the local
     * network time instead, even when currently handling a remote event.
     *
     * @J-Gras prefers the current behavior. @awelzel wonders if there should
     * be an opt-in/opt-out for this behavior. Procrastinating it for now.
     */
    zeek::detail::EventMetadataVectorPtr meta;
    if ( zeek::BifConst::EventMetadata::add_network_timestamp )
        meta = zeek::detail::MakeEventMetadataVector(zeek::event_mgr.CurrentEventTime());

    return Event{eh, std::move(*checked_args), std::move(meta)};
}

bool Backend::Subscribe(const std::string& topic_prefix, SubscribeCallback cb) {
    static const auto on_subscribe = zeek::id::find_func("Cluster::on_subscribe");
    assert(on_subscribe && on_subscribe->Flavor() == FUNC_FLAVOR_HOOK);

    if ( on_subscribe && on_subscribe->HasEnabledBodies() )
        on_subscribe->Invoke(zeek::make_intrusive<zeek::StringVal>(topic_prefix));

    return DoSubscribe(topic_prefix, std::move(cb));
}

bool Backend::Unsubscribe(const std::string& topic_prefix) {
    static const auto on_unsubscribe = zeek::id::find_func("Cluster::on_unsubscribe");
    assert(on_unsubscribe && on_unsubscribe->Flavor() == FUNC_FLAVOR_HOOK);

    if ( on_unsubscribe->HasEnabledBodies() )
        on_unsubscribe->Invoke(zeek::make_intrusive<zeek::StringVal>(topic_prefix));

    return DoUnsubscribe(topic_prefix);
}

void Backend::DoReadyToPublishCallback(Backend::ReadyCallback cb) {
    Backend::ReadyCallbackInfo info{Backend::CallbackStatus::Success};
    cb(info);
}

// Default implementation doing the serialization.
bool Backend::DoPublishEvent(const std::string& topic, cluster::Event& event) {
    byte_buffer buf;

    bool do_publish = PLUGIN_HOOK_WITH_RESULT(HOOK_PUBLISH_EVENT, HookPublishEvent(*this, topic, event), true);
    if ( ! do_publish )
        return true;

    if ( ! event_serializer->SerializeEvent(buf, event) )
        return false;

    Telemetry().OnOutgoingEvent(topic, event.HandlerName(), detail::SerializationInfo{buf.size()});

    return DoPublishEvent(topic, event_serializer->Name(), buf);
}

// Default implementation doing log record serialization.
bool Backend::DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header,
                                 std::span<zeek::logging::detail::LogRecord> records) {
    byte_buffer buf;

    if ( ! log_serializer->SerializeLogWrite(buf, header, records) )
        return false;

    return DoPublishLogWrites(header, log_serializer->Name(), buf);
}

void Backend::EnqueueEvent(EventHandlerPtr h, zeek::Args args) {
    event_handling_strategy->ProcessLocalEvent(h, std::move(args));
}

bool Backend::ProcessEvent(std::string_view topic, cluster::Event e) {
    return event_handling_strategy->ProcessEvent(topic, std::move(e));
}

void Backend::ProcessError(std::string_view tag, std::string_view message) {
    return event_handling_strategy->ProcessError(tag, message);
}

bool Backend::ProcessEventMessage(std::string_view topic, std::string_view format, byte_buffer_span payload) {
    if ( format != event_serializer->Name() ) {
        zeek::reporter->Error("ProcessEventMessage: Wrong format: %s vs %s", std::string{format}.c_str(),
                              event_serializer->Name().c_str());
        return false;
    }

    auto r = event_serializer->UnserializeEvent(payload);

    if ( ! r ) {
        auto escaped =
            util::get_escaped_string(std::string(reinterpret_cast<const char*>(payload.data()), payload.size()), false);
        zeek::reporter->Error("Failed to unserialize message: %s: %s", std::string{topic}.c_str(), escaped.c_str());
        return false;
    }

    Telemetry().OnIncomingEvent(topic, r->HandlerName(), detail::SerializationInfo{payload.size()});

    return ProcessEvent(topic, std::move(*r));
}

bool Backend::ProcessLogMessage(std::string_view format, byte_buffer_span payload) {
    // We could also dynamically lookup the right de-serializer, but
    // for now assume we just receive what is configured.
    if ( format != log_serializer->Name() ) {
        zeek::reporter->Error("Got log message in format '%s', but have deserializer '%s'", std::string{format}.c_str(),
                              log_serializer->Name().c_str());
        return false;
    }

    auto result = log_serializer->UnserializeLogWrite(payload);

    if ( ! result ) {
        zeek::reporter->Error("Failed to unserialize log message using '%s'", std::string{format}.c_str());
        return false;
    }

    return zeek::log_mgr->WriteBatchFromRemote(result->header, std::move(result->records));
}

void Backend::SetNodeId(std::string nid) { node_id = std::move(nid); }

bool ThreadedBackend::ProcessBackendMessage(int tag, byte_buffer_span payload) {
    return DoProcessBackendMessage(tag, payload);
}

ThreadedBackend::ThreadedBackend(std::string_view name, std::unique_ptr<EventSerializer> es,
                                 std::unique_ptr<LogSerializer> ls, std::unique_ptr<detail::EventHandlingStrategy> ehs,
                                 zeek::detail::OnLoopProcess<ThreadedBackend, QueueMessage>* onloop)
    : Backend(name, std::move(es), std::move(ls), std::move(ehs)), onloop(onloop) {
    onloop->Register(true); // Register as don't count first
}


ThreadedBackend::ThreadedBackend(std::string_view name, std::unique_ptr<EventSerializer> es,
                                 std::unique_ptr<LogSerializer> ls, std::unique_ptr<detail::EventHandlingStrategy> ehs)
    : ThreadedBackend(name, std::move(es), std::move(ls), std::move(ehs),
                      new zeek::detail::OnLoopProcess<ThreadedBackend, QueueMessage>(this, name)) {}

bool ThreadedBackend::DoInit() {
    // Have the onloop instance count so Zeek does not terminate.
    onloop->Register(/*dont_count=*/false);
    return true;
}

void ThreadedBackend::DoTerminate() {
    if ( onloop ) {
        onloop->Process();
        onloop->Close();
        onloop = nullptr;
    }
}

void ThreadedBackend::QueueForProcessing(QueueMessage&& qmessages) {
    if ( onloop )
        onloop->QueueForProcessing(std::move(qmessages));
}

void ThreadedBackend::Process(QueueMessage&& msg) {
    // sonarlint wants to use std::visit. not sure...
    if ( auto* emsg = std::get_if<EventMessage>(&msg) ) {
        ProcessEventMessage(emsg->topic, emsg->format, emsg->payload_span());
    }
    else if ( auto* lmsg = std::get_if<LogMessage>(&msg) ) {
        ProcessLogMessage(lmsg->format, lmsg->payload_span());
    }
    else if ( auto* bmsg = std::get_if<BackendMessage>(&msg) ) {
        ProcessBackendMessage(bmsg->tag, bmsg->payload_span());
    }
    else {
        zeek::reporter->FatalError("Unimplemented QueueMessage %zu", msg.index());
    }
}

TEST_SUITE_BEGIN("cluster event");

TEST_CASE("add metadata") {
    auto* handler = zeek::event_registry->Lookup("Supervisor::node_status");
    zeek::Args args{zeek::make_intrusive<zeek::StringVal>("TEST"), zeek::val_mgr->Count(42)};
    zeek::cluster::Event event{handler, std::move(args), nullptr};

    auto nts = zeek::id::find_val<zeek::EnumVal>("EventMetadata::NETWORK_TIMESTAMP");
    REQUIRE(nts);
    auto unk = zeek::id::find_val<zeek::EnumVal>("Log::UNKNOWN");
    REQUIRE(unk);

    bool registered = zeek::event_registry->RegisterMetadata(nts, zeek::base_type(zeek::TYPE_TIME));
    REQUIRE(registered);

    SUBCASE("valid") {
        CHECK_EQ(event.Timestamp(), -1.0);
        CHECK(event.AddMetadata(nts, zeek::make_intrusive<zeek::TimeVal>(42.0)));
        CHECK_EQ(event.Timestamp(), 42.0);
    }

    SUBCASE("valid-two-times") {
        CHECK_EQ(event.Timestamp(), -1.0);
        CHECK(event.AddMetadata(nts, zeek::make_intrusive<zeek::TimeVal>(42.0)));
        CHECK(event.AddMetadata(nts, zeek::make_intrusive<zeek::TimeVal>(43.0)));
        CHECK_EQ(event.Timestamp(), 42.0);     // finds the first one
        CHECK_EQ(event.Metadata()->size(), 2); // both are stored
    }

    SUBCASE("invalid-value-type") {
        CHECK_EQ(event.Timestamp(), -1.0);
        CHECK_FALSE(event.AddMetadata(nts, zeek::make_intrusive<zeek::DoubleVal>(42.0)));
        CHECK_EQ(event.Timestamp(), -1.0);
        CHECK_EQ(event.Metadata(), nullptr);
    }

    SUBCASE("unregistered-metadata-identifier") {
        CHECK_EQ(event.Timestamp(), -1.0);
        CHECK_FALSE(event.AddMetadata(unk, zeek::make_intrusive<zeek::DoubleVal>(42.0)));
        CHECK_EQ(event.Timestamp(), -1.0);
        CHECK_EQ(event.Metadata(), nullptr);
    }
}
TEST_SUITE_END();

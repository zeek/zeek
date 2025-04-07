// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/Backend.h"

#include <optional>

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/cluster/OnLoop.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/logging/Manager.h"
#include "zeek/util.h"

using namespace zeek::cluster;


bool detail::LocalEventHandlingStrategy::DoHandleRemoteEvent(std::string_view topic, detail::Event e) {
    zeek::event_mgr.Enqueue(e.Handler(), std::move(e.args), util::detail::SOURCE_BROKER, 0, nullptr, e.timestamp);
    return true;
}

void detail::LocalEventHandlingStrategy::DoEnqueueLocalEvent(EventHandlerPtr h, zeek::Args args) {
    zeek::event_mgr.Enqueue(h, std::move(args));
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
                                  zeek::obj_desc_short(got_type.get()).c_str(),
                                  zeek::obj_desc_short(expected_type.get()).c_str());
            return std::nullopt;
        }

        result[i] = args[i];
    }

    return result;
}

Backend::Backend(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                 std::unique_ptr<detail::EventHandlingStrategy> ehs)
    : event_serializer(std::move(es)), log_serializer(std::move(ls)), event_handling_strategy(std::move(ehs)) {}

std::optional<detail::Event> Backend::MakeClusterEvent(FuncValPtr handler, ArgsSpan args, double timestamp) const {
    auto checked_args = detail::check_args(handler, args);
    if ( ! checked_args )
        return std::nullopt;

    if ( timestamp == 0.0 )
        timestamp = zeek::event_mgr.CurrentEventTime();

    const auto& eh = zeek::event_registry->Lookup(handler->AsFuncPtr()->GetName());
    if ( ! eh ) {
        zeek::reporter->Error("event registry lookup of '%s' failed", obj_desc(handler.get()).c_str());
        return std::nullopt;
    }

    return zeek::cluster::detail::Event{eh, std::move(*checked_args), timestamp};
}

// Default implementation doing the serialization.
bool Backend::DoPublishEvent(const std::string& topic, cluster::detail::Event& event) {
    cluster::detail::byte_buffer buf;

    if ( ! event_serializer->SerializeEvent(buf, event) )
        return false;

    return DoPublishEvent(topic, event_serializer->Name(), buf);
}

// Default implementation doing log record serialization.
bool Backend::DoPublishLogWrites(const zeek::logging::detail::LogWriteHeader& header,
                                 zeek::Span<zeek::logging::detail::LogRecord> records) {
    cluster::detail::byte_buffer buf;

    if ( ! log_serializer->SerializeLogWrite(buf, header, records) )
        return false;

    return DoPublishLogWrites(header, log_serializer->Name(), buf);
}

void Backend::EnqueueEvent(EventHandlerPtr h, zeek::Args args) {
    event_handling_strategy->EnqueueLocalEvent(h, std::move(args));
}

bool Backend::ProcessEventMessage(std::string_view topic, std::string_view format,
                                  const detail::byte_buffer_span payload) {
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

    return event_handling_strategy->HandleRemoteEvent(topic, std::move(*r));
}

bool Backend::ProcessLogMessage(std::string_view format, detail::byte_buffer_span payload) {
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

bool ThreadedBackend::ProcessBackendMessage(int tag, detail::byte_buffer_span payload) {
    return DoProcessBackendMessage(tag, payload);
}

ThreadedBackend::ThreadedBackend(std::unique_ptr<EventSerializer> es, std::unique_ptr<LogSerializer> ls,
                                 std::unique_ptr<detail::EventHandlingStrategy> ehs)
    : Backend(std::move(es), std::move(ls), std::move(ehs)) {
    onloop = new zeek::detail::OnLoopProcess<ThreadedBackend, QueueMessage>(this, "ThreadedBackend");
    onloop->Register(true); // Register as don't count first
}

bool ThreadedBackend::DoInit() {
    // Have the backend count so Zeek does not terminate.
    onloop->Register(/*dont_count=*/false);
    return true;
}

void ThreadedBackend::DoTerminate() {
    if ( onloop ) {
        onloop->Close();
        onloop = nullptr;
    }
}

void ThreadedBackend::QueueForProcessing(QueueMessage&& qmessages) {
    if ( onloop )
        onloop->QueueForProcessing(std::move(qmessages));
}

void ThreadedBackend::Process() {
    if ( onloop )
        onloop->Process();
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

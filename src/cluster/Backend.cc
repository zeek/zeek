// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/Backend.h"

#include <optional>

#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/cluster/Serializer.h"
#include "zeek/iosource/Manager.h"

using namespace zeek::cluster;

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
        const auto& got_type = a->GetType();
        const auto& expected_type = types[i];

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
bool Backend::DoPublishEvent(const std::string& topic, const cluster::detail::Event& event) {
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

bool Backend::ProcessEventMessage(const std::string_view& topic, const std::string_view& format,
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

    auto& event = *r;
    zeek::event_mgr.Enqueue(event.Handler(), std::move(event.args), util::detail::SOURCE_BROKER, 0, nullptr,
                            event.timestamp);

    return true;
}

bool Backend::ProcessLogMessage(const std::string_view& format, detail::byte_buffer_span payload) {
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

    // TODO: Send the whole batch to the logging manager.
    // return zeek::log_mgr->WritesFromRemote(result->header, std::move(result->records));
    zeek::reporter->FatalError("not implemented");
    return false;
}

bool ThreadedBackend::ProcessBackendMessage(int tag, detail::byte_buffer_span payload) {
    return DoProcessBackendMessage(tag, payload);
}

namespace {

bool register_io_source(zeek::iosource::IOSource* src, int fd, bool dont_count) {
    constexpr bool manage_lifetime = true;

    zeek::iosource_mgr->Register(src, dont_count, manage_lifetime);

    if ( ! zeek::iosource_mgr->RegisterFd(fd, src) ) {
        zeek::reporter->Error("Failed to register messages_flare with IO manager");
        return false;
    }

    return true;
}
} // namespace

bool ThreadedBackend::DoInit() {
    // Register as counting during DoInit() to avoid Zeek from shutting down.
    return register_io_source(this, messages_flare.FD(), false);
}

void ThreadedBackend::DoInitPostScript() {
    // Register non-counting after parsing scripts.
    register_io_source(this, messages_flare.FD(), true);
}

void ThreadedBackend::QueueForProcessing(QueueMessages&& qmessages) {
    bool fire = false;

    // Enqueue under lock.
    {
        std::scoped_lock lock(messages_mtx);
        fire = messages.empty();

        if ( messages.empty() ) {
            messages = std::move(qmessages);
        }
        else {
            messages.reserve(messages.size() + qmessages.size());
            for ( auto& qmsg : qmessages )
                messages.emplace_back(std::move(qmsg));
        }
    }

    if ( fire )
        messages_flare.Fire();
}

void ThreadedBackend::Process() {
    QueueMessages to_process;
    {
        std::scoped_lock lock(messages_mtx);
        to_process = std::move(messages);
        messages_flare.Extinguish();
        messages.clear();
    }

    for ( const auto& msg : to_process ) {
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
}

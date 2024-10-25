#include "Serializer.h"

#include <optional>

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/broker/Data.h"
#include "zeek/cluster/Backend.h" // for cluster::detail::Event :-/

#include "broker/data_envelope.hh"
#include "broker/error.hh"
#include "broker/format/json.hh"
#include "broker/zeek.hh"

using namespace zeek::cluster;

namespace {

/**
 * Convert a cluster::detail::Event to a broker::zeek::Event.
 *
 * @param ev The cluster::detail::Event
 * @return A broker::zeek::Event to be serialized, or nullopt in case of errors.
 */
std::optional<broker::zeek::Event> to_broker_event(const detail::Event& ev) {
    broker::vector xs;
    xs.reserve(ev.args.size());
    for ( const auto& a : ev.args ) {
        if ( auto res = zeek::Broker::detail::val_to_data(a.get()) ) {
            xs.emplace_back(std::move(res.value()));
        }
        else {
            return std::nullopt;
        }
    }

    return broker::zeek::Event(ev.HandlerName(), xs, broker::to_timestamp(ev.timestamp));
}

/**
 * Convert a broker::zeek::Event to cluster::detail::Event by looking
 * it up in Zeek's event handler registry and converting event arguments
 * to the appropriate Val instances.
 *
 * @param broker_ev The broker side event.
 * @returns A zeek::cluster::detail::Event instance, or std::nullopt if the conversion failed.
 */
std::optional<detail::Event> to_zeek_event(const broker::zeek::Event& ev) {
    auto&& name = ev.name();
    auto&& args = ev.args();

    // Meh, technically need to convert ev.metadata() and
    // expose it to script land as `table[count] of any`
    // where consumers then know what to do with it.
    //
    // For now, handle the timestamp explicitly.
    double ts;
    if ( auto ev_ts = ev.ts() )
        broker::convert(*ev_ts, ts);
    else
        ts = zeek::run_state::network_time;

    zeek::Args vl;
    zeek::EventHandlerPtr handler = zeek::event_registry->Lookup(name);
    if ( ! handler ) {
        zeek::reporter->Error("Failed to lookup handler for '%s'", std::string(name).c_str());
        return std::nullopt;
    }

    const auto& arg_types = handler->GetFunc()->GetType()->ParamList()->GetTypes();

    if ( arg_types.size() != args.size() ) {
        std::string event_name(name);
        zeek::reporter->Error("Unserialize error '%s' arg_types.size()=%zu and args.size()=%zu", event_name.c_str(),
                              arg_types.size(), args.size());

        return std::nullopt;
    }

    for ( size_t i = 0; i < args.size(); ++i ) {
        const auto& expected_type = arg_types[i];
        auto arg = args[i].to_data();
        auto val = zeek::Broker::detail::data_to_val(arg, expected_type.get());
        if ( val )
            vl.emplace_back(std::move(val));
        else {
            std::string event_name(name);
            auto got_type = args[i].get_type_name();
            std::string argstr = broker::to_string(arg);
            zeek::reporter
                ->Error("Unserialize error for event '%s': broker value '%s' type '%s' to Zeek type '%s' failed",
                        event_name.c_str(), argstr.c_str(), got_type, obj_desc(expected_type.get()).c_str());

            return std::nullopt;
        }
    }

    return detail::Event{handler, std::move(vl), ts};
}

} // namespace

bool detail::BrokerBinV1_Serializer::SerializeEventInto(detail::byte_buffer& buf, const detail::Event& event) {
    auto ev = to_broker_event(event);
    if ( ! ev )
        return false;

    // The produced broker::zeek::Event is already in bin::v1 format after
    // constructing it, so we can take the raw bytes directly rather than
    // going through encode() again.
    //
    // broker::format::bin::v1::encode(ev->move_data(), std::back_inserter(buf));
    assert(ev->raw()->shared_envelope() != nullptr);
    auto [raw, size] = ev->raw().shared_envelope()->raw_bytes();
    buf.insert(buf.begin(), raw, raw + size);
    return true;
}

std::optional<detail::Event> detail::BrokerBinV1_Serializer::UnserializeEvent(const std::byte* payload,
                                                                              size_t payload_size) {
    auto r = broker::data_envelope::deserialize(broker::endpoint_id::nil(), broker::endpoint_id::nil(), 0, "", payload,
                                                payload_size);
    if ( ! r )
        return std::nullopt;

    broker::zeek::Event ev(*r);
    return to_zeek_event(ev);
}


// Convert char to std::byte during push_back() so that
// we don't need to copy from std::vector<char> to a
// std::vector<std::byte> when rendering JSON.
template<typename T>
struct PushBackAdaptor {
    explicit PushBackAdaptor(T& c) : container(&c) {}
    using value_type = char;

    void push_back(char c) { container->push_back(static_cast<std::byte>(c)); }

    T* container;
};


bool detail::BrokerJsonV1_Serializer::SerializeEventInto(byte_buffer& buf, const detail::Event& event) {
    auto ev = to_broker_event(event);
    if ( ! ev )
        return false;

    auto push_back_adaptor = PushBackAdaptor(buf);
    broker::format::json::v1::encode(ev->move_data(), std::back_inserter(push_back_adaptor));
    return true;
}

std::optional<detail::Event> detail::BrokerJsonV1_Serializer::UnserializeEvent(const std::byte* buf, size_t size) {
    broker::variant res;
    auto err = broker::format::json::v1::decode(std::string_view{reinterpret_cast<const char*>(buf), size}, res);
    if ( err ) {
        zeek::reporter->Error("Decode error for JSON payload: '%s'",
                              err.message() ? err.message()->c_str() : "unknown");
        return std::nullopt;
    }

    broker::zeek::Event ev(std::move(res));
    return to_zeek_event(ev);
}

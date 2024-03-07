#include "Plugin.h"

#include "zeek/Desc.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/broker/Data.h"
#include "zeek/cluster/Backend.h" // for cluster::detail::Event :-/
#include "zeek/cluster/Component.h"
#include "zeek/cluster/Serializer.h"

#include "broker/detail/monotonic_buffer_resource.hh"
#include "broker/format/bin.hh"
#include "broker/zeek.hh"

namespace {

using namespace zeek::cluster;

// Implementation of the EventSerializer that uses the existing using
// Broker::detail::val_to_data() and broker::format::bin::v1::encode()
class BrokerBinV1_Serializer : public Serializer {
    bool SerializeEventInto(detail::byte_buffer& buf, const detail::Event& event) override {
        broker::vector xs;
        xs.reserve(event.args.size());
        for ( const auto& a : event.args ) {
            if ( auto res = zeek::Broker::detail::val_to_data(a.get()) ) {
                xs.emplace_back(std::move(res.value()));
            }
            else {
                return false;
            }
        }

        auto ev = broker::zeek::Event(event.HandlerName(), std::move(xs), broker::to_timestamp(event.timestamp));
        broker::format::bin::v1::encode(ev.move_data(), std::back_inserter(buf));
        return true;
    }

    std::optional<detail::Event> UnserializeEvent(const std::byte* payload, size_t payload_size) override {
        auto r = broker::data_envelope::deserialize(broker::endpoint_id::nil(), broker::endpoint_id::nil(), 0, "",
                                                    payload, payload_size);
        if ( ! r )
            return std::nullopt;

        broker::zeek::Event ev(std::move(*r));

        auto&& name = ev.name();
        auto&& args = ev.args();

        // Meh, technically need to convert ev.metadata() and
        // expose it to script land as table[count] of any where
        // consumers then know what to do with it.
        double ts;
        if ( auto ev_ts = ev.ts() )
            broker::convert(*ev_ts, ts);
        else
            ts = zeek::run_state::network_time;

        // Copied from broker/Manager: Convert the zeek::Event broker
        // instancs into Vals.
        zeek::Args vl;

        zeek::EventHandlerPtr handler = zeek::event_registry->Lookup(name);
        if ( ! handler ) {
            zeek::reporter->Error("Failed to lookup handler for '%s'", std::string(name).c_str());
            return std::nullopt;
        }

        const auto& arg_types = handler->GetFunc()->GetType()->ParamList()->GetTypes();

        if ( arg_types.size() != args.size() ) {
            std::string event_name(name);
            zeek::reporter->Error("Unserialize error '%s' arg_types.size()=%" PRIu64 " and args.size()=%" PRIu64,
                                  event_name.c_str(), arg_types.size(), args.size());

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
                zeek::reporter->Error("Unserialize error for event '%s' broker value '%s' to Zeek type '%s' failed",
                                      event_name.c_str(), argstr.c_str(), obj_desc(expected_type.get()).c_str());

                return std::nullopt;
            }
        }

        return detail::Event(handler, std::move(vl), ts);
    }
};

} // namespace


using namespace zeek::plugin::Zeek_Cluster_Serializer_Broker;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(
        new SerializerComponent("BROKER_BIN_V1", []() -> Serializer* { return new BrokerBinV1_Serializer(); }));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Cluster_Serializer_Broker";
    config.description = "Event serialization using broker's binary v1 format";
    return config;
}

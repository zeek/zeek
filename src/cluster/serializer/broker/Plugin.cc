#include "Plugin.h"

#include <optional>
#include <string_view>

#include "zeek/3rdparty/doctest.h"
#include "zeek/Desc.h"
#include "zeek/EventHandler.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/broker/Data.h"
#include "zeek/cluster/Backend.h" // for cluster::detail::Event :-/
#include "zeek/cluster/Component.h"
#include "zeek/cluster/Serializer.h"

#include "broker/data_envelope.hh"
#include "broker/format/bin.hh"
#include "broker/format/json.hh"
#include "broker/zeek.hh"

namespace {

using namespace zeek::cluster;


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
 * Convert a broker::zeek::Event to a broker independent event by looking
 * looking it up in Zeek's event handler registry and converting event arguments
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
            zeek::reporter
                ->Error("Unserialize error for event '%s': broker value '%s' type '%s' to Zeek type '%s' failed",
                        event_name.c_str(), argstr.c_str(), got_type, obj_desc(expected_type.get()).c_str());

            return std::nullopt;
        }
    }

    return detail::Event{handler, std::move(vl), ts};
}

// Implementation of the EventSerializer that uses the existing broker::detail::val_to_data()
// and broker::format::bin::v1::encode()
class BrokerBinV1_Serializer : public Serializer {
public:
    BrokerBinV1_Serializer() : Serializer("broker-bin-v1") {}

    bool SerializeEventInto(detail::byte_buffer& buf, const detail::Event& event) override {
        auto ev = to_broker_event(event);
        if ( ! ev )
            return false;

        broker::format::bin::v1::encode(ev->move_data(), std::back_inserter(buf));
        return true;
    }

    std::optional<detail::Event> UnserializeEvent(const std::byte* payload, size_t payload_size) override {
        auto r = broker::data_envelope::deserialize(broker::endpoint_id::nil(), broker::endpoint_id::nil(), 0, "",
                                                    payload, payload_size);
        if ( ! r )
            return std::nullopt;

        broker::zeek::Event ev(*r);
        return to_zeek_event(ev);
    };

    bool SerializeValInto(detail::byte_buffer& buf, const zeek::ValPtr& v) override {
        auto res = zeek::Broker::detail::val_to_data(v.get());
        if ( ! res )
            return false;

        broker::format::bin::v1::encode(*res, std::back_inserter(buf));
        return true;
    }

    std::optional<zeek::ValPtr> UnserializeVal(const std::byte* buf, size_t size, const zeek::TypePtr& type) override {
        auto maybe_msg = broker::data_envelope::deserialize(broker::endpoint_id::nil(), broker::endpoint_id::nil(), 0,
                                                            "", buf, size);
        if ( ! maybe_msg )
            return std::nullopt;

        // data to val takes non-const broker::data&, need copy?
        auto data = (*maybe_msg)->value()->to_data();
        return zeek::Broker::detail::data_to_val(data, type.get());
    }
};

// Implementation of the EventSerializer that uses broker's JSON format
// for events as used by the WebSocket analyzer.
class BrokerJsonV1_Serializer : public Serializer {
public:
    BrokerJsonV1_Serializer() : Serializer("broker-json-v1") {}

    bool SerializeEventInto(zeek::cluster::detail::byte_buffer& buf, const detail::Event& event) override {
        // json::v1::encode() wants a back inserter for char, but buf is std::vector<byte>.
        // There's an extra memcpy() into buf below.
        //
        // XXX: Should we switch to char buffer?
        std::vector<char> cbuf;
        auto ev = to_broker_event(event);
        if ( ! ev )
            return false;

        broker::format::json::v1::encode(ev->move_data(), std::back_inserter(cbuf));
        buf.resize(cbuf.size());
        memcpy(buf.data(), cbuf.data(), buf.size());
        return true;
    }

    std::optional<detail::Event> UnserializeEvent(const std::byte* buf, size_t size) override {
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

    bool SerializeValInto(detail::byte_buffer& buf, const zeek::ValPtr& v) override {
        auto res = zeek::Broker::detail::val_to_data(v.get());
        if ( ! res )
            return false;

        // json::v1::encode() wants a back inserter for char, but buf is std::vector<byte>.
        // There's an extra memcpy() into buf below.
        //
        // XXX: Should we switch to char buffer? Or is it allowed to reinterpret that one? :-/
        std::vector<char> cbuf;
        broker::format::json::v1::encode(*res, std::back_inserter(cbuf));
        buf.resize(cbuf.size());
        memcpy(buf.data(), cbuf.data(), buf.size());
        return true;
    }

    std::optional<zeek::ValPtr> UnserializeVal(const std::byte* buf, size_t size, const zeek::TypePtr& type) override {
        broker::variant res;
        auto err = broker::format::json::v1::decode(std::string_view{reinterpret_cast<const char*>(buf), size}, res);
        if ( err )
            return std::nullopt;

        // data to val takes non-const broker::data&, need copy?
        auto data = res->to_data();
        return zeek::Broker::detail::data_to_val(data, type.get());
    }
};

} // namespace


using namespace zeek::plugin::Zeek_Cluster_Serializer_Broker;

zeek::plugin::Configuration Plugin::Configure() {
    AddComponent(
        new SerializerComponent("BROKER_BIN_V1", []() -> Serializer* { return new BrokerBinV1_Serializer(); }));
    AddComponent(
        new SerializerComponent("BROKER_JSON_V1", []() -> Serializer* { return new BrokerJsonV1_Serializer(); }));

    zeek::plugin::Configuration config;
    config.name = "Zeek::Cluster_Serializer_Broker";
    config.description = "Event serialization using broker's even formats (bin and json)";
    return config;
}


namespace {

TEST_SUITE_BEGIN("broker val serialization");

TEST_CASE("json v1 count") {
    BrokerJsonV1_Serializer s;
    detail::byte_buffer buf;

    auto c = zeek::val_mgr->Count(32);
    auto r = s.SerializeValInto(buf, c);

    REQUIRE(r);
    auto rval = s.UnserializeVal(buf.data(), buf.size(), zeek::base_type(zeek::TYPE_COUNT));

    REQUIRE(rval.has_value());

    auto val = rval.value();
    CHECK_EQ(val->GetType()->Tag(), zeek::TYPE_COUNT);
    CHECK_EQ(val->AsCount(), 32);
}

TEST_CASE("json v1 vector of count") {
    BrokerJsonV1_Serializer s;
    detail::byte_buffer buf;

    auto vv = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
    vv->Append(zeek::val_mgr->Count(32));
    vv->Append(zeek::val_mgr->Count(33));
    vv->Append(zeek::val_mgr->Count(34));
    vv->Append(zeek::val_mgr->Count(35));

    auto r = s.SerializeValInto(buf, vv);
    REQUIRE(r);
    auto rval = s.UnserializeVal(buf.data(), buf.size(), zeek::id::index_vec);

    REQUIRE(rval.has_value());

    auto val = rval.value();
    CHECK_EQ(val->GetType()->Tag(), zeek::TYPE_VECTOR);

    std::string val_str = zeek::obj_desc_short(val.get());
    CHECK_EQ(val_str, "[32, 33, 34, 35]");
}

TEST_CASE("bin v1 count") {
    BrokerBinV1_Serializer s;
    detail::byte_buffer buf;

    auto c = zeek::val_mgr->Count(32);
    auto r = s.SerializeValInto(buf, c);

    REQUIRE(r);
    auto rval = s.UnserializeVal(buf.data(), buf.size(), zeek::base_type(zeek::TYPE_COUNT));

    REQUIRE(rval.has_value());

    auto val = rval.value();
    CHECK_EQ(val->GetType()->Tag(), zeek::TYPE_COUNT);
    CHECK_EQ(val->AsCount(), 32);
}

TEST_CASE("bin v1 vector of count") {
    BrokerBinV1_Serializer s;
    detail::byte_buffer buf;

    auto vv = zeek::make_intrusive<zeek::VectorVal>(zeek::id::index_vec);
    vv->Append(zeek::val_mgr->Count(32));
    vv->Append(zeek::val_mgr->Count(33));
    vv->Append(zeek::val_mgr->Count(34));
    vv->Append(zeek::val_mgr->Count(35));

    auto r = s.SerializeValInto(buf, vv);
    REQUIRE(r);
    auto rval = s.UnserializeVal(buf.data(), buf.size(), zeek::id::index_vec);

    REQUIRE(rval.has_value());

    auto val = rval.value();
    CHECK_EQ(val->GetType()->Tag(), zeek::TYPE_VECTOR);

    std::string val_str = zeek::obj_desc_short(val.get());
    CHECK_EQ(val_str, "[32, 33, 34, 35]");
}

TEST_SUITE_END();

} // namespace

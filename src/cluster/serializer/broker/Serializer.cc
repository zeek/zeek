// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/cluster/serializer/broker/Serializer.h"

#include <optional>

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/Reporter.h"
#include "zeek/broker/Data.h"
#include "zeek/cluster/Backend.h"

#include "broker/data.bif.h"
#include "broker/data_envelope.hh"
#include "broker/error.hh"
#include "broker/format/json.hh"
#include "broker/zeek.hh"

#include "zeek/3rdparty/doctest.h"

using namespace zeek::cluster;

std::optional<broker::zeek::Event> detail::to_broker_event(const detail::Event& ev) {
    broker::vector xs;
    xs.reserve(ev.args.size());

    for ( const auto& a : ev.args ) {
        if ( a->GetType() == zeek::BifType::Record::Broker::Data ) {
            // When encountering a Broker::Data instance within args, pick out
            // the broker::data directly to avoid double encoding, Broker::Data.
            const auto& val = a->AsRecordVal()->GetField(0);
            auto* data_val = static_cast<zeek::Broker::detail::DataVal*>(val.get());
            xs.emplace_back(data_val->data);
        }
        else if ( auto res = zeek::Broker::detail::val_to_data(a.get()) ) {
            xs.emplace_back(std::move(res.value()));
        }
        else {
            return std::nullopt;
        }
    }

    return broker::zeek::Event(ev.HandlerName(), xs, broker::to_timestamp(ev.timestamp));
}

std::optional<detail::Event> detail::to_zeek_event(const broker::zeek::Event& ev) {
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
    if ( handler == nullptr ) {
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
        // XXX: data_to_val() uses Broker::Data for `any` type parameters, exposing
        //      Broker::Data to the script-layer even if Broker isn't used.
        //
        //      This might be part of the API, but seems we could also use the concrete
        //      Val type if the serializer encodes that information in the message.
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

bool detail::BrokerBinV1_Serializer::SerializeEvent(detail::byte_buffer& buf, const detail::Event& event) {
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

std::optional<detail::Event> detail::BrokerBinV1_Serializer::UnserializeEvent(detail::byte_buffer_span buf) {
    auto r = broker::data_envelope::deserialize(broker::endpoint_id::nil(), broker::endpoint_id::nil(), 0, "",
                                                buf.data(), buf.size());
    if ( ! r )
        return std::nullopt;

    broker::zeek::Event ev(*r);
    return to_zeek_event(ev);
}


// Convert char to std::byte during push_back() so that
// we don't need to copy from std::vector<char> to a
// std::vector<std::byte> when rendering JSON.
template<typename T>
struct PushBackAdapter {
    explicit PushBackAdapter(T& c) : container(&c) {}
    using value_type = char;

    void push_back(char c) { container->push_back(static_cast<std::byte>(c)); }

    T* container;
};


bool detail::BrokerJsonV1_Serializer::SerializeEvent(byte_buffer& buf, const detail::Event& event) {
    auto ev = to_broker_event(event);
    if ( ! ev )
        return false;

    auto push_back_adapter = PushBackAdapter(buf);
    broker::format::json::v1::encode(ev->move_data(), std::back_inserter(push_back_adapter));
    return true;
}

std::optional<detail::Event> detail::BrokerJsonV1_Serializer::UnserializeEvent(detail::byte_buffer_span buf) {
    broker::variant res;
    auto err =
        broker::format::json::v1::decode(std::string_view{reinterpret_cast<const char*>(buf.data()), buf.size()}, res);
    if ( err ) {
        zeek::reporter->Error("Decode error for JSON payload: '%s'",
                              err.message() ? err.message()->c_str() : "unknown");
        return std::nullopt;
    }

    broker::zeek::Event ev(std::move(res));
    return to_zeek_event(ev);
}

TEST_SUITE_BEGIN("cluster serializer broker");

#include "zeek/EventRegistry.h"

TEST_CASE("roundtrip") {
    auto* handler = zeek::event_registry->Lookup("Supervisor::node_status");
    detail::Event e{handler, zeek::Args{zeek::make_intrusive<zeek::StringVal>("TEST"), zeek::val_mgr->Count(42)}};
    detail::byte_buffer buf;

    SUBCASE("json") {
        detail::BrokerJsonV1_Serializer serializer;
        std::string expected =
            R"({"@data-type":"vector","data":[{"@data-type":"count","data":1},{"@data-type":"count","data":1},{"@data-type":"vector","data":[{"@data-type":"string","data":"Supervisor::node_status"},{"@data-type":"vector","data":[{"@data-type":"string","data":"TEST"},{"@data-type":"count","data":42}]},{"@data-type":"vector","data":[{"@data-type":"vector","data":[{"@data-type":"count","data":1},{"@data-type":"timestamp","data":"1970-01-01T00:00:00.000"}]}]}]}]})";

        serializer.SerializeEvent(buf, e);

        CHECK_EQ(expected, std::string{reinterpret_cast<char*>(buf.data()), buf.size()});

        auto result = serializer.UnserializeEvent(buf);
        REQUIRE(result);
        CHECK_EQ(result->Handler(), handler);
        CHECK_EQ(result->HandlerName(), "Supervisor::node_status");
        CHECK_EQ(result->args.size(), 2);
    }

    SUBCASE("binary") {
        detail::BrokerBinV1_Serializer serializer;
        unsigned char expected_bytes[] = {0x0e, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x0e, 0x03, 0x05, 0x17, 0x53, 0x75,
                                          0x70, 0x65, 0x72, 0x76, 0x69, 0x73, 0x6f, 0x72, 0x3a, 0x3a, 0x6e, 0x6f, 0x64,
                                          0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x0e, 0x02, 0x05, 0x04, 0x54,
                                          0x45, 0x53, 0x54, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x0e,
                                          0x01, 0x0e, 0x02, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x09,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        std::byte* p = reinterpret_cast<std::byte*>(&expected_bytes[0]);
        detail::byte_buffer expected{p, p + sizeof(expected_bytes)};

        serializer.SerializeEvent(buf, e);

        CHECK_EQ(expected, buf);

        auto result = serializer.UnserializeEvent(buf);
        REQUIRE(result);
        CHECK_EQ(result->Handler(), handler);
        CHECK_EQ(result->HandlerName(), "Supervisor::node_status");
        CHECK_EQ(result->args.size(), 2);
    }
}
TEST_SUITE_END();

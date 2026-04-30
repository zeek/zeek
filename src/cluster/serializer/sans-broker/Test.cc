// See the file "COPYING" in the main distribution directory for copyright.

#include <iterator>

#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/OpaqueVal.h"
#include "zeek/RE.h"
#include "zeek/Val.h"
#include "zeek/broker/Data.h"
#include "zeek/cluster/Event.h"
#include "zeek/cluster/serializer/sans-broker/Serializer.h"
#include "zeek/net_util.h"
#include "zeek/telemetry/Manager.h"
#include "zeek/telemetry/Opaques.h"
#include "zeek/util-types.h"
#include "zeek/util.h"

#include "broker/format/bin.hh"

#include "zeek/3rdparty/doctest.h"


// Just some code to compare behavior of broker and non-broker serialization.

using namespace zeek::cluster::format::broker::bin::v1;

namespace {
void print_hex(const char* what, const zeek::byte_buffer& b) {
    std::fprintf(stderr, "%-30s: ", what);
    for ( size_t i = 0; i < b.size(); i++ ) {
        std::fprintf(stderr, "%02x%s", static_cast<uint8_t>(b[i]), (i + 1 < b.size()) ? ":" : "");
    }

    std::fprintf(stderr, "\n");
}

zeek::byte_buffer from_hex(std::string_view hex) {
    zeek::byte_buffer result;

    size_t idx = 0;
    while ( idx < hex.size() ) {
        if ( idx + 1 == hex.size() )
            throw std::invalid_argument("invalid number of characters");

        int c1 = zeek::util::decode_hex(hex[idx]);
        int c2 = zeek::util::decode_hex(hex[idx + 1]);
        if ( c1 < 0 || c2 < 0 )
            throw std::invalid_argument("invalid hex char in string");

        result.push_back(static_cast<std::byte>(c1 << 4 | c2));

        if ( idx + 2 < hex.size() ) {
            // If something follows after two hex chars, it must be a ':'
            if ( hex[idx + 2] != ':' || idx + 3 == hex.size() )
                throw std::invalid_argument("invalid hex string");
        }

        idx += 3;
    }

    return result;
}

} // namespace

TEST_SUITE_BEGIN("cluster serializer compatible");

TEST_CASE("from_hex self test") {
    SUBCASE("empty") {
        auto r = from_hex("");
        CHECK(r.size() == 0);
    }
    SUBCASE("single byte") {
        auto r = from_hex("aa");
        REQUIRE(r.size() == 1);
        CHECK_EQ(r[0], std::byte{0xaa});
    }

    SUBCASE("two bytes") {
        auto r = from_hex("aa:bb");
        REQUIRE(r.size() == 2);
        CHECK_EQ(r[0], std::byte{0xaa});
        CHECK_EQ(r[1], std::byte{0xbb});
    }

    SUBCASE("two bytes upper") {
        auto r = from_hex("AA:BB");
        REQUIRE(r.size() == 2);
        CHECK_EQ(r[0], std::byte{0xaa});
        CHECK_EQ(r[1], std::byte{0xbb});
    }

    SUBCASE("errors") {
        CHECK_THROWS_AS(from_hex("aa:"), std::invalid_argument);
        CHECK_THROWS_AS(from_hex(":"), std::invalid_argument);
        CHECK_THROWS_AS(from_hex("zz"), std::invalid_argument);
    }
}

TEST_CASE("compare implementations") {
    zeek::byte_buffer buf;
    zeek::byte_buffer broker_buf;

    auto T = zeek::val_mgr->True();
    auto F = zeek::val_mgr->False();
    auto FORTY_TWO = zeek::val_mgr->Count(42);
    auto FORTY_TWO_STRING = zeek::make_intrusive<zeek::StringVal>("forty two");
    auto INT_FORTY_TWO = zeek::val_mgr->Int(42);
    auto INT_MINUS_FORTY_TWO = zeek::val_mgr->Int(-42);
    auto ANY_VEC = zeek::id::find_type<zeek::VectorType>("any_vec");
    auto TABLE_STRING_OF_STRING = zeek::id::find_type<zeek::TableType>("table_string_of_string");
    auto SUBNET_SET = zeek::id::find_type<zeek::TableType>("subnet_set");

    auto TCP_80 = zeek::val_mgr->Port(80, TRANSPORT_TCP);
    auto UDP_53 = zeek::val_mgr->Port(53, TRANSPORT_UDP);
    auto UDP_5353 = zeek::val_mgr->Port(5353, TRANSPORT_UDP);
    auto ICMP_42 = zeek::val_mgr->Port(42, TRANSPORT_ICMP);
    auto UNKNOWN_42 = zeek::val_mgr->Port(42, TRANSPORT_UNKNOWN);

    SUBCASE("bool true") {
        encode(*T, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(T.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("true non-broker", buf);
        print_hex("true broker", broker_buf);

        auto expected = from_hex("01:01");

        CHECK_EQ(buf, expected);
        CHECK_EQ(buf, broker_buf);
    }

    SUBCASE("bool false") {
        encode(*F, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(F.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("false non-broker", buf);
        print_hex("false broker", broker_buf);

        auto expected = from_hex("01:00");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("count") {
        encode(*FORTY_TWO, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(FORTY_TWO.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("count non-broker", buf);
        print_hex("count broker", broker_buf);

        auto expected = from_hex("02:00:00:00:00:00:00:00:2a");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("int") {
        encode(*INT_FORTY_TWO, std::back_inserter(buf));
        encode(*INT_MINUS_FORTY_TWO, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(INT_FORTY_TWO.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));
        auto bvalneg = zeek::Broker::detail::val_to_data(INT_MINUS_FORTY_TWO.get());
        broker::format::bin::v1::encode(*bvalneg, std::back_inserter(broker_buf));

        print_hex("int non-broker", buf);
        print_hex("int broker", broker_buf);

        auto expected = from_hex("03:00:00:00:00:00:00:00:2a:03:ff:ff:ff:ff:ff:ff:ff:d6");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("string") {
        encode(*FORTY_TWO_STRING, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(FORTY_TWO_STRING.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("string non-broker", buf);
        print_hex("string broker", broker_buf);

        auto expected = from_hex("05:09:66:6f:72:74:79:20:74:77:6f");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("long string") {
        constexpr int n = 2048 + 17;
        std::string s;
        for ( int i = 0; i < n; i++ ) {
            s.append(i % 2 == 0 ? "a" : "b");
        }

        auto sv = zeek::make_intrusive<zeek::StringVal>(s);

        encode(*sv, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(sv.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        // print_hex("long string non-broker", buf);
        // print_hex("long string broker", broker_buf);

        CHECK_EQ(buf, broker_buf);
    }

    SUBCASE("addr") {
        auto ipv4 = zeek::make_intrusive<zeek::AddrVal>("192.168.0.1");
        auto ipv6 = zeek::make_intrusive<zeek::AddrVal>("2606:4700:4700::1111");

        encode(*ipv4, std::back_inserter(buf));
        encode(*ipv6, std::back_inserter(buf));

        auto bval4 = zeek::Broker::detail::val_to_data(ipv4.get());
        auto bval6 = zeek::Broker::detail::val_to_data(ipv6.get());
        broker::format::bin::v1::encode(*bval4, std::back_inserter(broker_buf));
        broker::format::bin::v1::encode(*bval6, std::back_inserter(broker_buf));

        print_hex("ip non-broker", buf);
        print_hex("ip broker", broker_buf);

        auto expected = from_hex(
            "06:00:00:00:00:00:00:00:00:00:00:ff:ff:c0:a8:00:01:06:26:06:47:00:"
            "47:00:00:00:00:00:00:00:00:00:11:11");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("subnet") {
        auto sn4 = zeek::make_intrusive<zeek::SubNetVal>("192.168.0.1/16");
        auto sn6 = zeek::make_intrusive<zeek::SubNetVal>("2606:4700:4700::1111/96");

        encode(*sn4, std::back_inserter(buf));
        encode(*sn6, std::back_inserter(buf));

        auto bval4 = zeek::Broker::detail::val_to_data(sn4.get());
        auto bval6 = zeek::Broker::detail::val_to_data(sn6.get());
        broker::format::bin::v1::encode(*bval4, std::back_inserter(broker_buf));
        broker::format::bin::v1::encode(*bval6, std::back_inserter(broker_buf));

        print_hex("subnet non-broker", buf);
        print_hex("subnet broker", broker_buf);

        auto expected = from_hex(
            "07:00:00:00:00:00:00:00:00:00:00:ff:ff:c0:a8:00:00:70:07:26:06:47:"
            "00:47:00:00:00:00:00:00:00:00:00:00:00:60");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("port") {
        encode(*TCP_80, std::back_inserter(buf));
        encode(*UDP_53, std::back_inserter(buf));
        encode(*UDP_5353, std::back_inserter(buf));
        encode(*ICMP_42, std::back_inserter(buf));
        encode(*UNKNOWN_42, std::back_inserter(buf));

        auto btcp = zeek::Broker::detail::val_to_data(TCP_80.get());
        auto budp53 = zeek::Broker::detail::val_to_data(UDP_53.get());
        auto budp5353 = zeek::Broker::detail::val_to_data(UDP_5353.get());
        auto bicmp = zeek::Broker::detail::val_to_data(ICMP_42.get());
        auto bunknown = zeek::Broker::detail::val_to_data(UNKNOWN_42.get());

        broker::format::bin::v1::encode(*btcp, std::back_inserter(broker_buf));
        broker::format::bin::v1::encode(*budp53, std::back_inserter(broker_buf));
        broker::format::bin::v1::encode(*budp5353, std::back_inserter(broker_buf));
        broker::format::bin::v1::encode(*bicmp, std::back_inserter(broker_buf));
        broker::format::bin::v1::encode(*bunknown, std::back_inserter(broker_buf));

        print_hex("port non-broker", buf);
        print_hex("port broker", broker_buf);

        auto expected = from_hex("08:00:50:01:08:00:35:02:08:14:e9:02:08:00:2a:03:08:00:2a:00");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("time and interval") {
        auto ts = zeek::make_intrusive<zeek::TimeVal>(12345678.0);
        auto td = zeek::make_intrusive<zeek::IntervalVal>(42.0);

        encode(*ts, std::back_inserter(buf));
        encode(*td, std::back_inserter(buf));

        auto bts = zeek::Broker::detail::val_to_data(ts.get());
        auto btd = zeek::Broker::detail::val_to_data(td.get());
        broker::format::bin::v1::encode(*bts, std::back_inserter(broker_buf));
        broker::format::bin::v1::encode(*btd, std::back_inserter(broker_buf));

        print_hex("ts/td non-broker", buf);
        print_hex("ts/td broker", broker_buf);

        auto expected = from_hex("09:00:2b:dc:54:27:b3:8c:00:0a:00:00:00:09:c7:65:24:00");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("pattern") {
        auto* m1 = new zeek::RE_Matcher("ab*c", ".*ab*c.*");
        auto* m2 = new zeek::RE_Matcher("abc", ".*abc.*");
        auto p1 = zeek::make_intrusive<zeek::PatternVal>(m1);
        auto p2 = zeek::make_intrusive<zeek::PatternVal>(m2);

        encode(*p1, std::back_inserter(buf));
        encode(*p2, std::back_inserter(buf));

        auto bp1 = zeek::Broker::detail::val_to_data(p1.get());
        auto bp2 = zeek::Broker::detail::val_to_data(p2.get());
        broker::format::bin::v1::encode(*bp1, std::back_inserter(broker_buf));
        broker::format::bin::v1::encode(*bp2, std::back_inserter(broker_buf));

        print_hex("pattern non-broker", buf);
        print_hex("pattern broker", broker_buf);

        auto expected = from_hex(
            "0e:02:05:04:61:62:2a:63:05:08:2e:2a:61:62:2a:63:2e:2a:0e:02:05:03:"
            "61:62:63:05:07:2e:2a:61:62:63:2e:2a");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("empty vector") {
        auto vv = zeek::make_intrusive<zeek::VectorVal>(ANY_VEC);

        encode(*vv, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(vv.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("empty vector non-broker", buf);
        print_hex("empty vector broker", broker_buf);

        auto expected = from_hex("0e:00");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("count vector") {
        auto vv = zeek::make_intrusive<zeek::VectorVal>(ANY_VEC);

        vv->Append(zeek::val_mgr->Count(42));
        vv->Append(zeek::val_mgr->Count(4711));

        encode(*vv, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(vv.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("count vector non-broker", buf);
        print_hex("count vector broker", broker_buf);

        auto expected = from_hex("0e:02:02:00:00:00:00:00:00:00:2a:02:00:00:00:00:00:00:12:67");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("mixed vector") {
        auto vv_outer = zeek::make_intrusive<zeek::VectorVal>(ANY_VEC);
        auto vv_inner = zeek::make_intrusive<zeek::VectorVal>(ANY_VEC);

        vv_inner->Append(FORTY_TWO);
        vv_inner->Append(FORTY_TWO_STRING);
        vv_inner->Append(FORTY_TWO);

        vv_outer->Append(T);
        vv_outer->Append(F);
        vv_outer->Append(FORTY_TWO);
        vv_outer->Append(vv_inner);
        vv_outer->Append(T);

        encode(*vv_outer, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(vv_outer.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("mixed vector non-broker", buf);
        print_hex("mixed vector broker", broker_buf);

        auto expected = from_hex(
            "0e:05:01:01:01:00:02:00:00:00:00:00:00:00:2a:0e:03:02:00:00:00:00:"
            "00:00:00:2a:05:09:66:6f:72:74:79:20:74:77:6f:02:00:00:00:00:00:00:"
            "00:2a:01:01");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("empty table") {
        auto tbl = zeek::make_intrusive<zeek::TableVal>(TABLE_STRING_OF_STRING);
        encode(*tbl, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(tbl.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("empty table non-broker", buf);
        print_hex("empty table broker", broker_buf);

        auto expected = from_hex("0d:00");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("table") {
        auto tbl = zeek::make_intrusive<zeek::TableVal>(TABLE_STRING_OF_STRING);

        auto key1 = zeek::make_intrusive<zeek::StringVal>("key1");
        auto value1 = zeek::make_intrusive<zeek::StringVal>("value1");
        auto key2 = zeek::make_intrusive<zeek::StringVal>("key2");
        auto value2 = zeek::make_intrusive<zeek::StringVal>("value2");
        tbl->Assign(key1, value1);
        tbl->Assign(key2, value2);

        encode(*tbl, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(tbl.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        auto expected = from_hex(
            "0d:02:05:04:6b:65:79:31:05:06:76:61:6c:75:65:31:05:04:6b:65:79:32:"
            "05:06:76:61:6c:75:65:32");

        print_hex("table non-broker", buf);
        print_hex("table broker", broker_buf);

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("table composite") {
        // table[count, string] of string
        zeek::TypeListPtr tl = zeek::make_intrusive<zeek::TypeList>();
        tl->Append(zeek::base_type(zeek::TYPE_COUNT));
        tl->Append(zeek::base_type(zeek::TYPE_STRING));

        auto tt = zeek::make_intrusive<zeek::TableType>(tl, zeek::base_type(zeek::TYPE_STRING));
        auto tbl = zeek::make_intrusive<zeek::TableVal>(tt);

        auto key1 = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);
        key1->Append(zeek::val_mgr->Count(42));
        key1->Append(zeek::make_intrusive<zeek::StringVal>("key1"));
        auto value1 = zeek::make_intrusive<zeek::StringVal>("value1");

        auto key2 = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);
        key2->Append(zeek::val_mgr->Count(4242));
        key2->Append(zeek::make_intrusive<zeek::StringVal>("key2"));
        auto value2 = zeek::make_intrusive<zeek::StringVal>("value2");

        tbl->Assign(key1, value1);
        tbl->Assign(key2, value2);

        encode(*tbl, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(tbl.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("table composite non-broker", buf);
        print_hex("table composite broker", broker_buf);

        auto expected = from_hex(
            "0d:02:0e:02:02:00:00:00:00:00:00:00:2a:05:04:6b:65:79:31:05:06:76:"
            "61:6c:75:65:31:0e:02:02:00:00:00:00:00:00:10:92:05:04:6b:65:79:32:"
            "05:06:76:61:6c:75:65:32");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("set") {
        auto set = zeek::make_intrusive<zeek::TableVal>(SUBNET_SET);

        auto key1 = zeek::make_intrusive<zeek::SubNetVal>("192.168.0.1/16");
        auto key2 = zeek::make_intrusive<zeek::SubNetVal>("10.0.0.10/8");

        set->Assign(key1, nullptr);
        set->Assign(key2, nullptr);

        encode(*set, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(set.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("set non-broker", buf);
        print_hex("set broker", broker_buf);

        auto expected = from_hex(
            "0c:02:07:00:00:00:00:00:00:00:00:00:00:ff:ff:0a:00:00:00:68:07:00:"
            "00:00:00:00:00:00:00:00:00:ff:ff:c0:a8:00:00:70");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("set composite") {
        // set[count, string]
        zeek::TypeListPtr tl = zeek::make_intrusive<zeek::TypeList>();
        tl->Append(zeek::base_type(zeek::TYPE_COUNT));
        tl->Append(zeek::base_type(zeek::TYPE_STRING));

        auto st = zeek::make_intrusive<zeek::TableType>(tl, /*yield=*/nullptr);
        auto set = zeek::make_intrusive<zeek::TableVal>(st);

        auto key1 = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);
        key1->Append(zeek::val_mgr->Count(42));
        key1->Append(zeek::make_intrusive<zeek::StringVal>("key1"));

        auto key2 = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);
        key2->Append(zeek::val_mgr->Count(4242));
        key2->Append(zeek::make_intrusive<zeek::StringVal>("key2"));

        set->Assign(key1, nullptr);
        set->Assign(key2, nullptr);

        encode(*set, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(set.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("set composite non-broker", buf);
        print_hex("set composite broker", broker_buf);

        auto expected = from_hex(
            "0c:02:0e:02:02:00:00:00:00:00:00:00:2a:05:04:6b:65:79:31:0e:02:02:"
            "00:00:00:00:00:00:10:92:05:04:6b:65:79:32");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("opaque sha256") {
        auto hash = zeek::make_intrusive<zeek::SHA256Val>();
        hash->Init();
        hash->Feed("AAAA", 4);

        encode(*hash, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(hash.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("opaque sha256", buf);
        print_hex("opaque sha256", broker_buf);

        auto expected = from_hex(
            "0e:02:05:09:53:48:41:32:35:36:56:61:6c:0e:02:01:01:05:70:67:e6:09:"
            "6a:85:ae:67:bb:72:f3:6e:3c:3a:f5:4f:a5:7f:52:0e:51:8c:68:05:9b:ab:"
            "d9:83:1f:19:cd:e0:5b:20:00:00:00:00:00:00:00:41:41:41:41:00:00:00:"
            "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
            "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:"
            "00:00:00:00:00:00:00:00:00:00:00:00:00:04:00:00:00:20:00:00:00");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("record") {
        auto rt = zeek::id::find_type<zeek::RecordType>("mime_match");
        auto rec = zeek::make_intrusive<zeek::RecordVal>(rt);

        rec->Assign(0, 42);
        rec->Assign(1, zeek::make_intrusive<zeek::StringVal>("text/plain"));

        encode(*rec, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(rec.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("record mime_match", buf);
        print_hex("record mime_match", broker_buf);

        auto expected = from_hex("0e:02:03:00:00:00:00:00:00:00:2a:05:0a:74:65:78:74:2f:70:6c:61:69:6e");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("record optional") {
        auto rt = zeek::id::find_type<zeek::RecordType>("endpoint");
        auto rec = zeek::make_intrusive<zeek::RecordVal>(rt);

        rec->Assign(0, 42);   // size
        rec->Assign(1, 0);    // state
        rec->Assign(4, 4711); // flow_label

        encode(*rec, std::back_inserter(buf));

        auto bval = zeek::Broker::detail::val_to_data(rec.get());
        broker::format::bin::v1::encode(*bval, std::back_inserter(broker_buf));

        print_hex("record endpoint", buf);
        print_hex("record endpoint", broker_buf);

        auto expected =
            from_hex("0e:06:02:00:00:00:00:00:00:00:2a:02:00:00:00:00:00:00:00:00:00:00:02:00:00:00:00:00:00:12:67:00");

        CHECK_EQ(buf, broker_buf);
        CHECK_EQ(buf, expected);
    }

    SUBCASE("opaque unimplemented") {
        auto handle = zeek::telemetry_mgr->CounterInstance("test", "counter", {}, "help", "1");
        auto counter = zeek::make_intrusive<zeek::CounterMetricVal>(handle);

        auto r = encode(*counter, std::back_inserter(buf));
        CHECK_FALSE(r);

        auto bval = zeek::Broker::detail::val_to_data(counter.get());
        CHECK_FALSE(bval.has_value());
    }

    SUBCASE("") {
        auto handle = zeek::telemetry_mgr->CounterInstance("test", "counter", {}, "help", "1");
        auto counter = zeek::make_intrusive<zeek::CounterMetricVal>(handle);

        auto r = encode(*counter, std::back_inserter(buf));
        CHECK_FALSE(r);

        auto bval = zeek::Broker::detail::val_to_data(counter.get());
        CHECK_FALSE(bval.has_value());
    }
}

TEST_CASE("event roundtrip") {
    auto nts = zeek::id::find_val<zeek::EnumVal>("EventMetadata::NETWORK_TIMESTAMP");
    REQUIRE(nts);

    bool registered = zeek::event_registry->RegisterMetadata(nts, zeek::base_type(zeek::TYPE_TIME));
    REQUIRE(registered);

    auto node_up = zeek::event_registry->Lookup("Cluster::node_up");
    auto worker_name = zeek::make_intrusive<zeek::StringVal>("worker-42");
    auto worker_id = zeek::make_intrusive<zeek::StringVal>("ff8b006a-2df7-4161-9fc2-55a421fec9c7");

    zeek::cluster::detail::SansBrokerBinV1_Serializer broker_serializer;
    zeek::cluster::detail::SansBrokerBinV1_Serializer sans_broker_serializer;

    zeek::byte_buffer buf;
    zeek::byte_buffer broker_buf;

    SUBCASE("node_up") {
        REQUIRE(node_up);
        zeek::cluster::Event ev{node_up, {worker_name, worker_id}, nullptr};

        CHECK(sans_broker_serializer.SerializeEvent(buf, ev));
        CHECK(broker_serializer.SerializeEvent(broker_buf, ev));

        print_hex("node_up", buf);
        print_hex("node_up", broker_buf);

        CHECK_EQ(buf, broker_buf);
        CHECK(! buf.empty());

        auto sans_broker_event = sans_broker_serializer.UnserializeEvent(buf);
        REQUIRE(sans_broker_event);
        CHECK_EQ(sans_broker_event->Args().size(), 2UL);
        CHECK_FALSE(sans_broker_event->Metadata());

        auto broker_event = sans_broker_serializer.UnserializeEvent(buf);
        REQUIRE(broker_event);
        CHECK_EQ(broker_event->Args().size(), 2UL);
        CHECK_FALSE(broker_event->Metadata());
    }

    SUBCASE("node_up with meta") {
        REQUIRE(node_up);

        // Make two elements of vector metadata.
        auto meta = zeek::detail::MakeEventMetadataVector(12345678.0);
        zeek::detail::MetadataEntry entry{1, zeek::make_intrusive<zeek::TimeVal>(12345678.123456)};
        meta->push_back(entry);

        zeek::cluster::Event event{node_up, {worker_name, worker_id}, std::move(meta)};

        CHECK(sans_broker_serializer.SerializeEvent(buf, event));
        CHECK(broker_serializer.SerializeEvent(broker_buf, event));

        print_hex("node_up meta", buf);
        print_hex("node_up meta", broker_buf);

        CHECK_EQ(buf, broker_buf);
        CHECK(! buf.empty());

        auto sans_broker_event = sans_broker_serializer.UnserializeEvent(buf);
        REQUIRE(sans_broker_event);
        CHECK_EQ(sans_broker_event->HandlerName(), "Cluster::node_up");
        CHECK_EQ(sans_broker_event->Args().size(), 2UL);
        CHECK_EQ(sans_broker_event->Metadata()->size(), 2UL);

        auto broker_event = broker_serializer.UnserializeEvent(buf);
        REQUIRE(broker_event);
        CHECK_EQ(broker_event->HandlerName(), "Cluster::node_up");
        CHECK_EQ(broker_event->Args().size(), 2UL);
        CHECK_EQ(broker_event->Metadata()->size(), 2UL);
    }
}

TEST_SUITE_END();

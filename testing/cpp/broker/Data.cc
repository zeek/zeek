#define SUITE broker.Data

#include <array>

#include <arpa/inet.h>

#include "test.h"

#include "broker/Data.h"

using namespace bro_broker;
using namespace threading;

#define SIMPLE_ASSIGN_FUN(zeek_type, zeek_type_tag, member)                    \
	static void assign(threading::Value& value, zeek_type x)                   \
		{                                                                      \
		reset(value);                                                          \
		value.type = zeek_type_tag;                                            \
		value.val.member = x;                                                  \
		}                                                                      \

namespace {

void reset(threading::Value& x)
	{
	switch (x.type) {
	default:
		break;

	case TYPE_ENUM:
	case TYPE_STRING:
	case TYPE_FILE:
	case TYPE_FUNC :
		delete [] x.val.string_val.data;
		break;

	case TYPE_PATTERN:
		delete [] x.val.pattern_text_val;
		break;

	case TYPE_TABLE:
		for (int i = 0; i < x.val.set_val.size; ++i)
			delete x.val.set_val.vals[i];
		delete [] x.val.set_val.vals;
		break;

	case TYPE_VECTOR:
		for (int i = 0; i < x.val.vector_val.size; ++i)
			delete x.val.vector_val.vals[i];
		delete [] x.val.vector_val.vals;
		break;
	}
	x.type = TYPE_VOID;
	}

SIMPLE_ASSIGN_FUN(bro_int_t, TYPE_INT, int_val)

SIMPLE_ASSIGN_FUN(bro_uint_t, TYPE_COUNT, uint_val)

SIMPLE_ASSIGN_FUN(double, TYPE_DOUBLE, double_val)

void assign_time(threading::Value& value, double time_since_epoch)
	{
	reset(value);
	value.type = TYPE_TIME;
	value.val.double_val = time_since_epoch;
	}

void assign_interval(threading::Value& value, double time_since_epoch)
	{
	reset(value);
	value.type = TYPE_INTERVAL;
	value.val.double_val = time_since_epoch;
	}

void assign(threading::Value& value, uint16_t port, TransportProto proto)
	{
	reset(value);
	value.type = TYPE_PORT;
	value.val.port_val = {port, proto};
	}

static void assign_ipv4(threading::Value::addr_t& addr,
                        std::array<uint8_t, 4> octets)
	{
	addr.family = IPv4;
	memcpy(&addr.in.in4.s_addr, octets.data(), octets.size());
	}

void assign_ipv6(threading::Value::addr_t& addr,
                 const std::array<uint16_t, 8>& blocks)
	{
	addr.family = IPv6;
	union {
		uint8_t addr_bytes[16];
		uint16_t addr_blocks[8];
	};
	std::transform(blocks.begin(), blocks.end(), addr_blocks,
				   [](uint16_t x) { return htons(x); });
	memcpy(addr.in.in6.s6_addr, addr_bytes, 16);
	}

void assign_ipv4(threading::Value& value, std::array<uint8_t, 4> octets)
	{
	reset(value);
	value.type = TYPE_ADDR;
	assign_ipv4(value.val.addr_val, octets);
	}

void assign_ipv4_subnet(threading::Value& value, std::array<uint8_t, 4> octets,
                        uint8_t length)
	{
	reset(value);
	value.type = TYPE_SUBNET;
	auto& val = value.val.subnet_val;
	val.length = length;
	assign_ipv4(value.val.subnet_val.prefix, octets);
	}

void assign_ipv6(threading::Value& value, std::array<uint16_t, 8> blocks)
	{
	reset(value);
	value.type = TYPE_ADDR;
	auto& addr = value.val.addr_val;
	assign_ipv6(value.val.addr_val, blocks);
	}

void assign_ipv6_subnet(threading::Value& value, std::array<uint16_t, 8> blocks,
                        uint8_t length)
	{
	reset(value);
	value.type = TYPE_SUBNET;
	auto& val = value.val.subnet_val;
	val.length = length;
	assign_ipv6(val.prefix, blocks);
	}

template <size_t N>
void assign_string(threading::Value& value, const char (&str)[N])
	{
	reset(value);
	value.type = TYPE_STRING;
	auto& val = value.val.string_val;
	val.data = new char[N];
	memcpy(val.data, str, N);
	val.length = static_cast<int>(N - 1);
	}

template <size_t N>
void assign_enum(threading::Value& value, const char (&str)[N])
	{
	assign_string(value, str);
	value.type = TYPE_ENUM;
	}

void initialize(threading::Value::set_t& xs, size_t size)
	{
	xs.size = static_cast<bro_int_t>(size);
	xs.vals = new threading::Value*[size];
	for (size_t i = 0; i < size; ++i)
	  xs.vals[i] = new threading::Value(TYPE_VOID);
	}

void assign_table(threading::Value& value, size_t size, TypeTag inner_type)
	{
	reset(value);
	value.type = TYPE_TABLE;
	value.subtype = inner_type;
	initialize(value.val.set_val, size);
	}

void assign_vector(threading::Value& value, size_t size, TypeTag inner_type)
	{
	reset(value);
	value.type = TYPE_VECTOR;
	value.subtype = inner_type;
	initialize(value.val.vector_val, size);
	}

threading::Value& table_at(threading::Value& value, size_t index)
	{
	return *value.val.set_val.vals[index];
	}

threading::Value& vector_at(threading::Value& value, size_t index)
	{
	return *value.val.vector_val.vals[index];
	}

struct fixture
	{
	Value value;

	fixture() : value(TYPE_VOID, true) { }
	};

} // namespace

FIXTURE_SCOPE(broker_data_tests, fixture)

#define CHECK_VALUE(rhs) CHECK_EQUAL(threading_val_to_data(&value), rhs)

TEST(conversion to data)
	{
	using sec = std::chrono::seconds;
	using std::chrono::duration_cast;
	constexpr auto v4_family = broker::address::family::ipv4;
	constexpr auto v6_family = broker::address::family::ipv6;
	constexpr auto host_order = broker::address::byte_order::host;
	CHECK_VALUE(broker::nil);
	assign(value, bro_int_t{42});
	CHECK_VALUE(broker::integer{42});
	assign(value, bro_uint_t(24));
	CHECK_VALUE(broker::count{24});
	assign(value, 1e23);
	CHECK_VALUE(1e23);
	assign(value, 65000, TRANSPORT_UNKNOWN);
	CHECK_VALUE(broker::port(65000, broker::port::protocol::unknown));
	assign(value, 80, TRANSPORT_TCP);
	CHECK_VALUE(broker::port(80, broker::port::protocol::tcp));
	assign(value, 443, TRANSPORT_UDP);
	CHECK_VALUE(broker::port(443, broker::port::protocol::udp));
	assign_ipv4(value, {127, 0, 0, 1});
	uint32_t localhost = 0x7F000001;
	CHECK_VALUE(broker::address(&localhost, v4_family, host_order));
	assign_ipv4_subnet(value, {192, 168, 12, 24}, 24);
	uint32_t local_address = 0xC0A80C18;
	CHECK_VALUE(broker::subnet(broker::address(&local_address, v4_family,
	                                           host_order),
	                            24));
	assign_ipv6(value, {0x2001, 0xdb8, 0x0, 0x1, 0x1, 0x1, 0x1, 0x1});
	uint32_t v6_addr[] = {0x20010db8, 0x00000001, 0x00010001, 0x00010001};
	CHECK_VALUE(broker::address(v6_addr, v6_family, host_order));
	assign_ipv6_subnet(value, {0x2001, 0xdb8, 0x0, 0x1, 0x1, 0x1, 0x1, 0x1}, 72);
	CHECK_VALUE(broker::subnet(broker::address(v6_addr, v6_family, host_order),
	                           72));
	assign_interval(value, 42.);
	CHECK_VALUE(duration_cast<broker::timespan>(sec(42)));
	assign_time(value, 42.);
	CHECK_VALUE(broker::timestamp(duration_cast<broker::timespan>(sec(42))));
	assign_string(value, "Hello, Zeek!");
	CHECK_VALUE(std::string{"Hello, Zeek!"});
	assign_enum(value, "zeek::it");
	CHECK_VALUE(broker::enum_value{"zeek::it"});
	assign_vector(value, 4, TYPE_INT);
	for (size_t i = 0; i < 4; ++i)
	  assign(vector_at(value, i), static_cast<bro_int_t>(i + 1));
	CHECK_VALUE(broker::vector({broker::integer(1), broker::integer(2),
	                            broker::integer(3), broker::integer(4)}));
	assign_table(value, 4, TYPE_INT);
	for (size_t i = 0; i < 4; ++i)
	  assign(table_at(value, i), static_cast<bro_int_t>(i + 1));
	CHECK_VALUE(broker::set({broker::integer(1), broker::integer(2),
	                         broker::integer(3), broker::integer(4)}));
	}

FIXTURE_SCOPE_END()

#define SUITE broker.Data

#include <array>

#include <arpa/inet.h>

#include "test.h"

#include "broker/Data.h"

using namespace bro_broker;
using namespace threading;

#define SIMPLE_ASSIGN_FUN(zeek_type, zeek_type_tag, member)                    \
	void assign(zeek_type x)                                                   \
		{                                                                      \
		reset();                                                               \
		value.type = zeek_type_tag;                                            \
		value.val.member = x;                                                  \
		}

namespace {

struct fixture
	{
	Value value;

	fixture() : value(TYPE_VOID, true) { }

	SIMPLE_ASSIGN_FUN(bro_int_t, TYPE_INT, int_val)

	SIMPLE_ASSIGN_FUN(bro_uint_t, TYPE_COUNT, uint_val)

	SIMPLE_ASSIGN_FUN(double, TYPE_DOUBLE, double_val)

	void assign(uint16_t port, TransportProto proto)
		{
		reset();
		value.type = TYPE_PORT;
		value.val.port_val = {port, proto};
		}

	void assign_ipv4(std::array<uint8_t, 4> octets)
		{
		reset();
		value.type = TYPE_ADDR;
		auto& addr = value.val.addr_val;
		addr.family = IPv4;
		memcpy(&addr.in.in4.s_addr, octets.data(), octets.size());
		}

	void assign_ipv6(std::array<uint16_t, 8> blocks)
		{
		reset();
		value.type = TYPE_ADDR;
		auto& addr = value.val.addr_val;
		addr.family = IPv6;
		union {
			uint8_t addr_bytes[16];
			uint16_t addr_blocks[8];
		};
		std::transform(blocks.begin(), blocks.end(), addr_blocks,
					   [](uint16_t x) { return htons(x); });
		memcpy(addr.in.in6.s6_addr, addr_bytes, 16);
		}

	void reset()
		{
		switch (value.type) {
		default:
			break;

		case TYPE_ENUM:
		case TYPE_STRING:
		case TYPE_FILE:
		case TYPE_FUNC :
			delete [] value.val.string_val.data;
			break;

		case TYPE_PATTERN:
			delete [] value.val.pattern_text_val;
			break;

		case TYPE_TABLE:
			for (int i = 0; i < value.val.set_val.size; ++i)
				delete value.val.set_val.vals[i];
			delete [] value.val.set_val.vals;
			break;

		case TYPE_VECTOR:
			for (int i = 0; i < value.val.vector_val.size; ++i)
				delete value.val.vector_val.vals[i];
			delete [] value.val.vector_val.vals;
			break;
		}
		value.type = TYPE_VOID;
		}

	};

} // namespace

FIXTURE_SCOPE(broker_data_tests, fixture)

#define CHECK_VALUE(rhs) CHECK_EQUAL(threading_val_to_data(&value), rhs)

TEST(conversion to data)
	{
	CHECK_VALUE(broker::nil);
	assign(bro_int_t{42});
	CHECK_VALUE(broker::integer{42});
	assign(bro_uint_t(24));
	CHECK_VALUE(broker::count{24});
	assign(1e23);
	CHECK_VALUE(1e23);
	assign(65000, TRANSPORT_UNKNOWN);
	CHECK_VALUE(broker::port(65000, broker::port::protocol::unknown));
	assign(80, TRANSPORT_TCP);
	CHECK_VALUE(broker::port(80, broker::port::protocol::tcp));
	assign(443, TRANSPORT_UDP);
	CHECK_VALUE(broker::port(443, broker::port::protocol::udp));
	assign_ipv4({127, 0, 0, 1});
	uint32_t localhost = 0x7F000001;
	CHECK_VALUE(broker::address(&localhost, broker::address::family::ipv4,
	            broker::address::byte_order::host));
	assign_ipv6({0x2001, 0xdb8, 0x0, 0x1, 0x1, 0x1, 0x1, 0x1});
	uint32_t v6_addr[] = {0x20010db8, 0x00000001, 0x00010001, 0x00010001};
	CHECK_VALUE(broker::address(v6_addr, broker::address::family::ipv6,
	            broker::address::byte_order::host));
	}

FIXTURE_SCOPE_END()

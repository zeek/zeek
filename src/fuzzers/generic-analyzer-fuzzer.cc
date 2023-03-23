#include <binpac.h>

#include "zeek/Conn.h"
#include "zeek/RunState.h"
#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"
#include "zeek/analyzer/protocol/pia/PIA.h"
#include "zeek/analyzer/protocol/tcp/TCP.h"
#include "zeek/fuzzers/FuzzBuffer.h"
#include "zeek/fuzzers/fuzzer-setup.h"
#include "zeek/packet_analysis/protocol/tcp/TCPSessionAdapter.h"
#include "zeek/session/Manager.h"

// Simple macros for converting a compiler define into a string.
#define VAL(str) #str
#define TOSTRING(str) VAL(str)

static zeek::Connection* add_connection()
	{
	static constexpr double network_time_start = 1439471031;
	zeek::run_state::detail::update_network_time(network_time_start);

	zeek::Packet p;
	zeek::ConnTuple conn_id;
	conn_id.src_addr = zeek::IPAddr("1.2.3.4");
	conn_id.dst_addr = zeek::IPAddr("5.6.7.8");
	conn_id.src_port = htons(23132);
	conn_id.dst_port = htons(80);
	conn_id.is_one_way = false;
	conn_id.proto = TRANSPORT_TCP;
	zeek::detail::ConnKey key(conn_id);
	zeek::Connection* conn = new zeek::Connection(key, network_time_start, &conn_id, 1, &p);
	conn->SetTransport(TRANSPORT_TCP);
	zeek::session_mgr->Insert(conn);
	return conn;
	}

static std::pair<zeek::analyzer::Analyzer*, zeek::packet_analysis::TCP::TCPSessionAdapter*>
add_analyzer(zeek::Connection* conn, zeek::Tag tag)
	{
	auto* tcp = new zeek::packet_analysis::TCP::TCPSessionAdapter(conn);
	auto* pia = new zeek::analyzer::pia::PIA_TCP(conn);
	auto a = zeek::analyzer_mgr->InstantiateAnalyzer(tag, conn);
	if ( ! a )
		{
		fprintf(stderr, "Unknown or unsupported analyzer %s found\n", TOSTRING(ZEEK_FUZZ_ANALYZER));
		abort();
		}

	tcp->AddChildAnalyzer(a);
	tcp->AddChildAnalyzer(pia->AsAnalyzer());
	conn->SetSessionAdapter(tcp, pia);
	return {a, tcp};
	}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
	{
	zeek::detail::FuzzBuffer fb{data, size};

	if ( ! fb.Valid() )
		return 0;

	auto tag = zeek::analyzer_mgr->GetComponentTag(TOSTRING(ZEEK_FUZZ_ANALYZER));
	auto conn = add_connection();
	auto [a, tcp] = add_analyzer(conn, tag);

	for ( ;; )
		{
		auto chunk = fb.Next();

		if ( ! chunk )
			break;

		try
			{
			a->NextStream(chunk->size, chunk->data.get(), chunk->is_orig);
			}
		catch ( const binpac::Exception& e )
			{
			}

		chunk = {};
		zeek::event_mgr.Drain();

		// Has the analyzer been disabled during event processing?
		if ( ! tcp->HasChildAnalyzer(tag) )
			break;
		}

	zeek::detail::fuzzer_cleanup_one_input();
	return 0;
	}

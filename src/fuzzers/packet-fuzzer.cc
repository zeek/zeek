#include "binpac.h"

#include "iosource/Packet.h"
#include "Event.h"
#include "packet_analysis/Manager.h"

#include "FuzzBuffer.h"
#include "fuzzer-setup.h"

extern "C" {
#include <pcap.h>
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
	{
	zeek::detail::FuzzBuffer fb{data, size};

	if ( ! fb.Valid() )
		return 0;

	for ( ; ;  )
		{
		auto chunk = fb.Next();

		if ( ! chunk )
			break;

		zeek::Packet pkt;
		auto timestamp = 42;
		pkt_timeval ts = {timestamp, 0};
		pkt.Init(DLT_RAW, &ts, chunk->size, chunk->size, chunk->data.get(), false, "");

		try
			{
			zeek::packet_mgr->ProcessPacket(&pkt);
			}
		catch ( binpac::Exception const &e )
			{
			}

		chunk = {};
		zeek::event_mgr.Drain();
		}

	zeek::detail::fuzzer_cleanup_one_input();
	return 0;
	}

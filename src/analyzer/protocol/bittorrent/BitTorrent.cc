// This code contributed by Nadi Sarrar.

#include "BitTorrent.h"
#include "analyzer/protocol/tcp/TCP_Reassembler.h"

#include "events.bif.h"

namespace zeek::analyzer::bittorrent {

BitTorrent_Analyzer::BitTorrent_Analyzer(zeek::Connection* c)
: zeek::analyzer::tcp::TCP_ApplicationAnalyzer("BITTORRENT", c)
	{
	interp = new binpac::BitTorrent::BitTorrent_Conn(this);
	stop_orig = stop_resp = false;
	stream_len_orig = stream_len_resp = 0;
	}

BitTorrent_Analyzer::~BitTorrent_Analyzer()
	{
	delete interp;
	}

void BitTorrent_Analyzer::Done()
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Done();

	interp->FlowEOF(true);
	interp->FlowEOF(false);
	}

void BitTorrent_Analyzer::DeliverStream(int len, const u_char* data, bool orig)
	{
	uint64_t& this_stream_len = orig ? stream_len_orig : stream_len_resp;
	bool& this_stop = orig ? stop_orig : stop_resp;

	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::DeliverStream(len, data, orig);

	assert(TCP());

	if ( TCP()->IsPartial() )
		// punt on partial.
		return;

	if ( this_stop )
		return;

	this_stream_len += len;

	try
		{
		interp->NewData(orig, data, data + len);
		}
	catch ( binpac::Exception const &e )
		{
		const char except[] = "binpac exception: invalid handshake";
		if ( ! strncmp(e.c_msg(), except, strlen(except)) )
			// Does not look like bittorrent - silently
			// drop the connection.
			Parent()->RemoveChildAnalyzer(this);
		else
			{
			DeliverWeird(fmt("Stopping BitTorrent analysis: protocol violation (%s)",
					e.c_msg()), orig);
			this_stop = true;
			if ( stop_orig && stop_resp )
				ProtocolViolation("BitTorrent: content gap and/or protocol violation");
			}
		}
	}

void BitTorrent_Analyzer::Undelivered(uint64_t seq, int len, bool orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::Undelivered(seq, len, orig);

	// TODO: Code commented out for now. I think that shoving data that
	// is definitely wrong into the parser seems like a really bad idea.
	// The way it's currently tracking the next message offset isn't
	// compatible with new 64bit int support in binpac either.

	//uint64_t entry_offset = orig ?
	//	*interp->upflow()->next_message_offset() :
	//	*interp->downflow()->next_message_offset();
	//uint64_t& this_stream_len = orig ? stream_len_orig : stream_len_resp;
	//bool& this_stop = orig ? stop_orig : stop_resp;
	//
	//this_stream_len += len;
	//
	//if ( entry_offset < this_stream_len )
	//	{ // entry point is somewhere in the gap
	//	DeliverWeird("Stopping BitTorrent analysis: cannot recover from content gap", orig);
	//	this_stop = true;
	//	if ( stop_orig && stop_resp )
	//		ProtocolViolation("BitTorrent: content gap and/or protocol violation");
	//	}
	//else
	//	{ // fill the gap
	//	try
	//		{
	//		u_char gap[len];
	//		memset(gap, 0, len);
	//		interp->NewData(orig, gap, gap + len);
	//		}
	//	catch ( binpac::Exception const &e )
	//		{
	//		DeliverWeird("Stopping BitTorrent analysis: filling content gap failed", orig);
	//		this_stop = true;
	//		if ( stop_orig && stop_resp )
	//			ProtocolViolation("BitTorrent: content gap and/or protocol violation");
	//		}
	//	}
	}

void BitTorrent_Analyzer::EndpointEOF(bool is_orig)
	{
	zeek::analyzer::tcp::TCP_ApplicationAnalyzer::EndpointEOF(is_orig);
	interp->FlowEOF(is_orig);
	}

void BitTorrent_Analyzer::DeliverWeird(const char* msg, bool orig)
	{
	if ( bittorrent_peer_weird )
		EnqueueConnEvent(bittorrent_peer_weird,
		                 ConnVal(),
		                 zeek::val_mgr->Bool(orig),
		                 zeek::make_intrusive<zeek::StringVal>(msg));
	}

} // namespace zeek::analyzer::bittorrent


#include <assert.h>

#include "config.h"

#include "Source.h"

using namespace iosource::pktsrc;

NetmapSource::~NetmapSource()
	{
	Close();
	}

NetmapSource::NetmapSource(const std::string& path, const std::string& filter, bool is_live, const std::string& arg_kind)
	{
	if ( ! is_live )
		Error("netmap source does not support offline input");

	kind = arg_kind;
	props.path = path;
	props.filter = filter;
	last_data = 0;
	}

void NetmapSource::Close()
	{
	if ( ! nd )
		return;

	nm_close(nd);
	nd = 0;
	last_data = 0;

	Closed();
	}

void NetmapSource::Open()
	{
	std::string iface = kind + ":" + props.path;
	nd = nm_open(iface.c_str(), getenv("NETMAP_RING_ID"), 0, 0);

	if ( ! nd )
		{
		Error(errno ? strerror(errno) : "invalid interface");
		return;
		}

	props.selectable_fd = NETMAP_FD(nd);
	props.is_live = true;
	props.link_type = DLT_EN10MB;
	props.hdr_size = GetLinkHeaderSize(props.link_type);
	assert(props.hdr_size >= 0);

	Info(fmt("netmap listening on %s\n", props.path.c_str()));

	Opened(props);
	}

int NetmapSource::ExtractNextPacket(Packet* pkt)
	{
	nm_hdr_t hdr;
	const u_char* data = nm_nextpkt(nd, &hdr);

	if ( ! data )
		// Source has gone dry.
		return 0;

	current_hdr.ts = hdr.ts;
	current_hdr.caplen = hdr.caplen;
	current_hdr.len = hdr.len;

	pkt->ts = current_hdr.ts.tv_sec + double(current_hdr.ts.tv_usec) / 1e6;
	pkt->hdr = &current_hdr;
	pkt->data = last_data = data;

	if ( current_hdr.len == 0 || current_hdr.caplen == 0 )
		{
		Weird("empty_netmap_header", pkt);
		return 0;
		}

	last_hdr = current_hdr;
	last_data = data;
	++stats.received;
	return 1;
	}

void NetmapSource::DoneWithPacket(Packet* pkt)
	{
	// Nothing to do.
	}

void NetmapSource::Statistics(Stats* s)
	{
	if ( ! nd )
		{
		s->received = s->link = s->dropped = 0;
		return;
		}

	s->received = stats.received;

	// TODO: Seems these counter's aren't actually set?
	s->link = nd->st.ps_recv;
	s->dropped = nd->st.ps_drop + nd->st.ps_ifdrop;
	}

bool NetmapSource::GetCurrentPacket(const pcap_pkthdr** hdr, const u_char** pkt)
	{
	if ( ! last_data )
		return false;

	*hdr = &last_hdr;
	*pkt = last_data;
	return true;
	}

iosource::PktSrc* NetmapSource::InstantiateNetmap(const std::string& path, const std::string& filter, bool is_live)
	{
	return new NetmapSource(path, filter, is_live, "netmap");
	}

iosource::PktSrc* NetmapSource::InstantiateVale(const std::string& path, const std::string& filter, bool is_live)
	{
	return new NetmapSource(path, filter, is_live, "value");
	}

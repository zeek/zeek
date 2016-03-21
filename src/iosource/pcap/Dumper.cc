// See the file "COPYING" in the main distribution directory for copyright.

#include <sys/stat.h>
#include <errno.h>

#include "Dumper.h"
#include "../PktSrc.h"
#include "../../Net.h"

#include "const.bif.h"

using namespace iosource::pcap;

PcapDumper::PcapDumper(const std::string& path, bool arg_append)
	{
	append = arg_append;
	props.path = path;
	dumper = 0;
	pd = 0;
	}

PcapDumper::~PcapDumper()
	{
	}

void PcapDumper::Open()
	{
	int linktype = -1;

	pd = pcap_open_dead(DLT_EN10MB, BifConst::Pcap::snaplen);

	if ( ! pd )
		{
		Error("error for pcap_open_dead");
		return;
		}

	if ( props.path.empty() )
		{
		Error("no filename given");
		return;
		}

	struct stat s;
	int exists = 0;

	if ( append )
		{
		// See if output file already exists (and is non-empty).
		exists = stat(props.path.c_str(), &s); ;

		if ( exists < 0 && errno != ENOENT )
			{
			Error(fmt("can't stat file %s: %s", props.path.c_str(), strerror(errno)));
			return;
			}
		}

	if ( ! append || exists < 0 || s.st_size == 0 )
		{
		// Open new file.
		dumper = pcap_dump_open(pd, props.path.c_str());
		if ( ! dumper )
			{
			Error(pcap_geterr(pd));
			return;
			}
		}

	else
		{
		// Old file and we need to append, which, unfortunately,
		// is not supported by libpcap. So, we have to hack a
		// little bit, knowing that pcap_dumpter_t is, in fact,
		// a FILE ... :-(
		dumper = (pcap_dumper_t*) fopen(props.path.c_str(), "a");
		if ( ! dumper )
			{
			Error(fmt("can't open dump %s: %s", props.path.c_str(), strerror(errno)));
			return;
			}
		}

	props.open_time = network_time;
	props.hdr_size = Packet::GetLinkHeaderSize(pcap_datalink(pd));
	Opened(props);
	}

void PcapDumper::Close()
	{
	if ( ! dumper )
		return;

	pcap_dump_close(dumper);
	pcap_close(pd);
	dumper = 0;
	pd = 0;

	Closed();
	}

bool PcapDumper::Dump(const Packet* pkt)
	{
	if ( ! dumper )
		return false;

	// Reconstitute the pcap_pkthdr.
	const struct pcap_pkthdr phdr = {
		.ts = pkt->ts, .caplen = pkt->cap_len, .len = pkt->len
	};

	pcap_dump((u_char*) dumper, &phdr, pkt->data);
	return true;
	}

iosource::PktDumper* PcapDumper::Instantiate(const std::string& path, bool append)
	{
	return new PcapDumper(path, append);
	}

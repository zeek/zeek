// $Id: PktDagSrc.cc 6909 2009-09-10 19:42:19Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include "config.h"

#ifdef USE_DAG

extern "C" {
#include <dagapi.h>
#include <pcap.h>
}
#include <errno.h>

#include <set>
#include <string>

#include "PktDagSrc.h"

// Length of ERF Header before Ethernet header.
#define DAG_ETH_ERFLEN 18

static set<string> used_interfaces;

PktDagSrc::PktDagSrc(const char* arg_interface, const char* filter,
			PktSrc_Filter_Type ft)
: PktSrc()
	{
	interface = copy_string(fmt("/dev/%s", arg_interface));
	fd = -1;
	closed = true;

	if ( used_interfaces.find(interface) != used_interfaces.end() )
		{
		Error("DAG interface already in use, can't be used multiple times");
		return;
		}


	// We only support Ethernet.
	hdr_size = 14;
	datalink = DLT_EN10MB;
	filter_type = ft;
	netmask = 0xffffff00;	// XXX does this make sense?

	current_filter = 0;

	// We open a dummy pcap file to get access to pcap data structures.
	// Ideally, Bro's PktSrc would be less dependent on pcap ...

	pd = pcap_open_dead(datalink, snaplen);
	if ( ! pd )
		{
		// Note: errno not trustworthy, for example it's sometimes
		// set by malloc inside pcap_open_dead().
		Error("pcap_open_dead");
		return;
		}

	fd = dag_open(interface);

	// XXX Currently, the DAG fd is not selectable :-(.
	selectable_fd = -1;

	if ( fd < 0 )
		{
		Error("dag_open");
		return;
		}

	int dag_recordtype = dag_linktype(fd);
	if ( dag_recordtype < TYPE_MIN || dag_recordtype > TYPE_MAX )
		{
		Error("dag_linktype");
		return;
		}

	if ( dag_recordtype != TYPE_ETH )
		{
		sprintf(errbuf, "unsupported DAG link type 0x%x", dag_recordtype);
		return;
		}

	// long= is needed to prevent the DAG card from truncating jumbo frames.
	char* dag_configure_string =
		copy_string(fmt("slen=%d varlen long=%d",
				snaplen, snaplen > 1500 ? snaplen : 1500));

	fprintf(stderr, "Configuring %s with options \"%s\"...\n",
		interface, dag_configure_string);

	if ( dag_configure(fd, dag_configure_string) < 0 )
		{
		Error("dag_configure");
		delete [] dag_configure_string;
		return;
		}

	delete [] dag_configure_string;

	if ( dag_attach_stream(fd, stream_num, 0, EXTRA_WINDOW_SIZE) < 0 )
		{
		Error("dag_attach_stream");
		return;
		}

	if ( dag_start_stream(fd, stream_num) < 0 )
		{
		Error("dag_start_stream");
		return;
		}

	struct timeval maxwait, poll;
	maxwait.tv_sec = 0;	// arbitrary due to mindata == 0
	maxwait.tv_usec = 0;
	poll.tv_sec = 0;	// don't wait until more data arrives.
	poll.tv_usec = 0;

	// mindata == 0 for non-blocking.
	if ( dag_set_stream_poll(fd, stream_num, 0, &maxwait, &poll) < 0 )
		{
		Error("dag_set_stream_poll");
		return;
		}

	closed = false;

	if ( PrecompileFilter(0, filter) && SetFilter(0) )
		fprintf(stderr, "listening on DAG card on %s\n", interface);

	stats.link = stats.received = stats.dropped = 0;
	}

PktDagSrc::~PktDagSrc()
	{
	}


void PktDagSrc::Close()
	{
	if ( fd >= 0 )
		{
		PktSrc::Close();
		dag_stop_stream(fd, stream_num);
		dag_detach_stream(fd, stream_num);
		dag_close(fd);
		fd = -1;
		}

	closed = true;
	used_interfaces.erase(interface);
	}

int PktDagSrc::ExtractNextPacket()
	{
	unsigned link_count = 0;	// # packets on link for this call

	// As we can't use select() on the fd, we always have to pretend
	// we're busy (in fact this is probably even true; otherwise
	// we shouldn't be using such expensive monitoring hardware!).
	idle = false;

	struct bpf_insn* fcode = current_filter->bf_insns;
	if ( ! fcode )
		{
		run_time("filter code not valid when extracting DAG packet");
		return 0;
		}

	dag_record_t* r = 0;

	do
		{
		r = (dag_record_t*) dag_rx_stream_next_record(fd, 0);

		if ( ! r )
			{
			data = last_data = 0;	// make dataptr invalid

			if ( errno != EAGAIN )
				{
				run_time(fmt("dag_rx_stream_next_record: %s",
						strerror(errno)));
				Close();
				return 0;
				}

			else
				{ // gone dry
				idle = true;
				return 0;
				}
			}

		// Return after 20 unwanted packets on the link.
		if ( ++link_count > 20 )
			{
			data = last_data = 0;
			return 0;
			}

		hdr.len = ntohs(r->wlen);
		hdr.caplen = ntohs(r->rlen) - DAG_ETH_ERFLEN;

		// Locate start of the Ethernet header.
		data = last_data = (const u_char*) r->rec.eth.dst;

		++stats.link;
		// lctr_sum += ntohs(r->lctr);
		stats.dropped += ntohs(r->lctr);
		}
	while ( ! bpf_filter(fcode, (u_char*) data, hdr.len, hdr.caplen) );

	++stats.received;

	// Timestamp conversion taken from DAG programming manual.
	unsigned long long lts = r->ts;
	hdr.ts.tv_sec = lts >> 32;
	lts = ((lts & 0xffffffffULL) * 1000 * 1000);
	lts += (lts & 0x80000000ULL) << 1;
	hdr.ts.tv_usec = lts >> 32;
	if ( hdr.ts.tv_usec >= 1000000 )
		{
		hdr.ts.tv_usec -= 1000000;
		hdr.ts.tv_sec += 1;
		}

	next_timestamp = hdr.ts.tv_sec + double(hdr.ts.tv_usec) / 1e6;

	return 1;
	}

void PktDagSrc::GetFds(int* read, int* write, int* except)
	{
	// We don't have a selectable fd, but we take the opportunity to
	// reset our idle flag if we have data now.
	if ( ! data )
		ExtractNextPacket();
	}

void PktDagSrc::Statistics(Stats* s)
	{
	s->received = stats.received;
	s->dropped = stats.dropped;
	s->link = stats.link + stats.dropped;
	}

int PktDagSrc::SetFilter(int index)
	{
	// We don't want load-level filters for the secondary path.
	if ( filter_type == TYPE_FILTER_SECONDARY && index > 0 )
		return 1;

	HashKey* hash = new HashKey(HashKey(bro_int_t(index)));
	BPF_Program* code = filters.Lookup(hash);
	delete hash;

	if ( ! code )
		{
		sprintf(errbuf, "No precompiled pcap filter for index %d",
				index);
		return 0;
		}

	current_filter = code->GetProgram();

	// Reset counters.
	stats.received = stats.dropped = stats.link = 0;

	return 1;
	}

int PktDagSrc::SetNewFilter(const char* filter)
	{
	bpf_program* code = 0;

	if ( pcap_compile(pd, code, (char*) filter, 1, netmask) < 0 )
		{
		snprintf(errbuf, sizeof(errbuf), "pcap_compile(%s): %s",
				filter, pcap_geterr(pd));
		errbuf[sizeof(errbuf) - 1] = '\0';
		return 0;
		}

	current_filter = code;
	return 1;
	}

void PktDagSrc::Error(const char *s)
	{
	snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: %s", s, strerror(errno));
	Close();
	}
#endif

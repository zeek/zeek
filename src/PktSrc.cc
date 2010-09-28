// $Id: PktSrc.cc 6951 2009-12-04 22:23:28Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#include <errno.h>
#include <sys/stat.h>

#include "config.h"

#include "util.h"
#include "PktSrc.h"
#include "Hash.h"
#include "Net.h"
#include "Sessions.h"


// ### This needs auto-confing.
#ifdef HAVE_PCAP_INT_H
#include <pcap-int.h>
#endif

int snaplen = 8192;	// really want "capture entire packet"


PktSrc::PktSrc()
	{
	interface = readfile = 0;
	data = last_data = 0;
	hdr_size = 0;
	datalink = 0;
	netmask = 0xffffff00;
	pd = 0;
	idle = false;

	next_sync_point = 0;
	first_timestamp = current_timestamp = next_timestamp = 0.0;
	first_wallclock = current_wallclock = 0;

	stats.received = stats.dropped = stats.link = 0;
	}

PktSrc::~PktSrc()
	{
	Close();

	loop_over_list(program_list, i)
		delete program_list[i];

	BPF_Program* code;
	IterCookie* cookie = filters.InitForIteration();
	while ( (code = filters.NextEntry(cookie)) )
		delete code;

	delete [] interface;
	delete [] readfile;
	}

void PktSrc::GetFds(int* read, int* write, int* except)
	{
	if ( pseudo_realtime )
		{
		// Select would give erroneous results. But we simulate it
		// by setting idle accordingly.
		idle = CheckPseudoTime() == 0;
		return;
		}

#ifdef USE_SELECT_LOOP
	if ( selectable_fd >= 0 )
		*read = selectable_fd;
#endif
	}

int PktSrc::ExtractNextPacket()
	{
	// Don't return any packets if processing is suspended (except for the
	// very first packet which we need to set up times).
	if ( net_is_processing_suspended() && first_timestamp )
		{
		idle = true;
		return 0;
		}

	data = last_data = pcap_next(pd, &hdr);
	next_timestamp = hdr.ts.tv_sec + double(hdr.ts.tv_usec) / 1e6;

	if ( pseudo_realtime )
		current_wallclock = current_time(true);

	if ( ! first_timestamp )
		first_timestamp = next_timestamp;

#ifdef USE_SELECT_LOOP
	idle = (data == 0);
#else
	idle = false;
#endif

	if ( data )
		++stats.received;

	// Source has gone dry.  If it's a network interface, this just means
	// it's timed out. If it's a file, though, then the file has been
	// exhausted.
	if ( ! data && ! IsLive() )
		{
		closed = true;

		if ( pseudo_realtime && using_communication )
			{
			if ( remote_trace_sync_interval )
				remote_serializer->SendFinalSyncPoint();
			else
				remote_serializer->Terminate();
			}
		}

	return data != 0;
	}

double PktSrc::NextTimestamp(double* local_network_time)
	{
	if ( ! data && ! ExtractNextPacket() )
		return -1.0;

	if ( pseudo_realtime )
		{
		// Delay packet if necessary.
		double packet_time = CheckPseudoTime();
		if ( packet_time )
			return packet_time;

		idle = true;
		return -1.0;
		}

	return next_timestamp;
	}

void PktSrc::ContinueAfterSuspend()
	{
	current_wallclock = current_time(true);
	}

double PktSrc::CurrentPacketWallClock()
	{
	// We stop time when we are suspended.
	if ( net_is_processing_suspended() )
		current_wallclock = current_time(true);

	return current_wallclock;
	}

double PktSrc::CheckPseudoTime()
	{
	if ( ! data && ! ExtractNextPacket() )
		return 0;

	if ( ! current_timestamp )
		return bro_start_time;

	if ( remote_trace_sync_interval )
		{
		if ( next_sync_point == 0 || next_timestamp >= next_sync_point )
			{
			int n = remote_serializer->SendSyncPoint();
			next_sync_point = first_timestamp +
						n * remote_trace_sync_interval;
			remote_serializer->Log(RemoteSerializer::LogInfo,
				fmt("stopping at packet %.6f, next sync-point at %.6f",
					current_timestamp, next_sync_point));

			return 0;
			}
		}

	double pseudo_time = next_timestamp - first_timestamp;
	double ct = (current_time(true) - first_wallclock) * pseudo_realtime;

	return pseudo_time <= ct ? bro_start_time + pseudo_time : 0;
	}

void PktSrc::Process()
	{
	if ( ! data && ! ExtractNextPacket() )
		return;

	current_timestamp = next_timestamp;

	if ( pseudo_realtime )
		{
		current_pseudo = CheckPseudoTime();
		net_packet_arrival(current_pseudo, &hdr, data, hdr_size, this);
		if ( ! first_wallclock )
			first_wallclock = current_time(true);
		}

	else
		net_packet_arrival(current_timestamp, &hdr, data, hdr_size, this);

	data = 0;
	}

bool PktSrc::GetCurrentPacket(const struct pcap_pkthdr** arg_hdr,
				const u_char** arg_pkt)
	{
	if ( ! last_data )
		return false;

	*arg_hdr = &hdr;
	*arg_pkt = last_data;
	return true;
	}

int PktSrc::PrecompileFilter(int index, const char* filter)
	{
	// Compile filter.
	BPF_Program* code = new BPF_Program();

	if ( ! code->Compile(pd, filter, netmask, errbuf, sizeof(errbuf)) )
		{
		delete code;
		return 0;
		}

	// Store it in hash.
	HashKey* hash = new HashKey(HashKey(bro_int_t(index)));
	BPF_Program* oldcode = filters.Lookup(hash);
	if ( oldcode )
		delete oldcode;

	filters.Insert(hash, code);
	delete hash;

	return 1;
	}

int PktSrc::SetFilter(int index)
	{
	// We don't want load-level filters for the secondary path.
	if ( filter_type == TYPE_FILTER_SECONDARY && index > 0 )
		return 1;

	HashKey* hash = new HashKey(HashKey(bro_int_t(index)));
	BPF_Program* code = filters.Lookup(hash);
	delete hash;

	if ( ! code )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			      "No precompiled pcap filter for index %d",
			      index);
		return 0;
		}

	if ( pcap_setfilter(pd, code->GetProgram()) < 0 )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			      "pcap_setfilter(%d): %s",
			      index, pcap_geterr(pd));
		return 0;
		}

#ifndef HAVE_LINUX
	// Linux doesn't clear counters when resetting filter.
	stats.received = stats.dropped = stats.link = 0;
#endif

	return 1;
	}

void PktSrc::SetHdrSize()
	{
	int dl = pcap_datalink(pd);
	hdr_size = get_link_header_size(dl);

	if ( hdr_size < 0 )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			 "unknown data link type 0x%x", dl);
		Close();
		}

	datalink = dl;
	}

void PktSrc::Close()
	{
	if ( pd )
		{
		pcap_close(pd);
		pd = 0;
		closed = true;
		}
	}

void PktSrc::AddSecondaryTablePrograms()
	{
	BPF_Program* program;

	loop_over_list(secondary_path->EventTable(), i)
		{
		SecondaryEvent* se = secondary_path->EventTable()[i];
		program = new BPF_Program();

		if ( ! program->Compile(snaplen, datalink, se->Filter(),
					netmask, errbuf, sizeof(errbuf)) )
			{
			delete program;
			Close();
			}

		SecondaryProgram* sp = new SecondaryProgram(program, se);
		program_list.append(sp);
		}
	}

void PktSrc::Statistics(Stats* s)
	{
	struct pcap_stat pstat;

	if ( reading_traces )
		s->received = s->dropped = s->link = 0;

	else if ( pcap_stats(pd, &pstat) < 0 )
		{
		run_time("problem getting packet filter statistics: %s",
				ErrorMsg());
		s->received = s->dropped = s->link = 0;
		}

	s->received = stats.received;
	s->dropped = pstat.ps_drop;
	s->link = pstat.ps_recv;

	if ( pseudo_realtime )
		s->dropped = 0;

	stats.dropped = s->dropped;
	}

PktInterfaceSrc::PktInterfaceSrc(const char* arg_interface, const char* filter,
					PktSrc_Filter_Type ft)
: PktSrc()
	{
	char tmp_errbuf[PCAP_ERRBUF_SIZE];
	filter_type = ft;

	// Determine interface if not specified.
	if ( ! arg_interface && ! (arg_interface = pcap_lookupdev(tmp_errbuf)) )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			 "pcap_lookupdev: %s", tmp_errbuf);
		return;
		}

	interface = copy_string(arg_interface);

	// Determine network and netmask.
	uint32 net;
	if ( pcap_lookupnet(interface, &net, &netmask, tmp_errbuf) < 0 )
		{
		// ### The lookup can fail if no address is assigned to
		// the interface; and libpcap doesn't have any useful notion
		// of error codes, just error strings - how bogus - so we
		// just kludge around the error :-(.
		// sprintf(errbuf, "pcap_lookupnet %s", tmp_errbuf);
		// return;
		net = 0;
		netmask = 0xffffff00;
		}

#ifdef USE_SELECT_LOOP
	// We use the smallest time-out possible to return almost immediately if
	// no packets are available. (We can't use set_nonblocking() as it's
	// broken on FreeBSD: even when select() indicates that we can read
	// something, we may get nothing if the store buffer hasn't filled up
	// yet.)
	pd = pcap_open_live(interface, snaplen, 1, 1, tmp_errbuf);
#else
	pd = pcap_open_live(interface, snaplen, 1, PCAP_TIMEOUT, tmp_errbuf);
#endif

	if ( ! pd )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			 "pcap_open_live: %s", tmp_errbuf);
		closed = true;
		return;
		}

	// ### This needs autoconf'ing.
#ifdef HAVE_PCAP_INT_H
	fprintf(stderr, "pcap bufsize = %d\n", ((struct pcap *) pd)->bufsize);
#endif

#ifdef USE_SELECT_LOOP

#ifdef HAVE_LINUX
	if ( pcap_setnonblock(pd, 1, tmp_errbuf) < 0 )
		{
		safe_snprintf(errbuf, sizeof(errbuf),
			 "pcap_setnonblock: %s", tmp_errbuf);
		pcap_close(pd);
		closed = true;
		return;
		}
#endif
	selectable_fd = pcap_fileno(pd);
#endif

	if ( PrecompileFilter(0, filter) && SetFilter(0) )
		{
		SetHdrSize();
		fprintf(stderr, "listening on %s\n", interface);
		}
	else
		closed = true;
	}


PktFileSrc::PktFileSrc(const char* arg_readfile, const char* filter,
			PktSrc_Filter_Type ft)
: PktSrc()
	{
	readfile = copy_string(arg_readfile);

	filter_type = ft;

	pd = pcap_open_offline((char*) readfile, errbuf);

	if ( pd && PrecompileFilter(0, filter) && SetFilter(0) )
		{
		SetHdrSize();

		if ( closed )
			// Unknown link layer type.
			return;

#ifdef USE_SELECT_LOOP
		// We don't put file sources into non-blocking mode as
		// otherwise we would not be able to identify the EOF
		// via next_packet().

		selectable_fd = fileno(pcap_file(pd));

		if ( selectable_fd < 0 )
			internal_error("OS does not support selectable pcap fd");
#endif
		}
	else
		closed = true;
	}


SecondaryPath::SecondaryPath()
	{
	filter = 0;

	// Glue together the secondary filter, if exists.
	Val* secondary_fv = internal_val("secondary_filters");
	if ( secondary_fv->AsTableVal()->Size() == 0 )
		return;

	int did_first = 0;
	const TableEntryValPDict* v = secondary_fv->AsTable();
	IterCookie* c = v->InitForIteration();
	TableEntryVal* tv;
	HashKey* h;

	while ( (tv = v->NextEntry(h, c)) )
		{
		// Get the index values.
		ListVal* index =
			secondary_fv->AsTableVal()->RecoverIndex(h);

		const char* str =
			index->Index(0)->Ref()->AsString()->CheckString();

		if ( ++did_first == 1 )
			{
			filter = copy_string(str);
			}
		else
			{
			if ( strlen(filter) > 0 )
				{
				char* tmp_f = new char[strlen(str) + strlen(filter) + 32];
				if ( strlen(str) == 0 )
					sprintf(tmp_f, "%s", filter);
				else
					sprintf(tmp_f, "(%s) or (%s)", filter, str);
				delete [] filter;
				filter = tmp_f;
				}
			}

		// Build secondary_path event table item and link it.
		SecondaryEvent* se =
			new SecondaryEvent(index->Index(0)->Ref()->AsString()->CheckString(),
				tv->Value()->AsFunc() );

		event_list.append(se);

		delete h;
		}
	}

SecondaryPath::~SecondaryPath()
	{
	loop_over_list(event_list, i)
		delete event_list[i];

	delete [] filter;
	}


SecondaryProgram::~SecondaryProgram()
	{
	delete program;
	}

PktDumper::PktDumper(const char* arg_filename, bool arg_append)
	{
	filename[0] = '\0';
	is_error = false;
	append = arg_append;
	dumper = 0;

	// We need a pcap_t with a reasonable link-layer type. We try to get it
	// from the packet sources. If not available, we fall back to Ethernet.
	// FIXME: Perhaps we should make this configurable?
	int linktype = -1;

	if ( pkt_srcs.length() )
		linktype = pkt_srcs[0]->LinkType();

	if ( linktype < 0 )
		linktype = DLT_EN10MB;

	pd = pcap_open_dead(linktype, 8192);
	if ( ! pd )
		{
		Error("error for pcap_open_dead");
		return;
		}

	if ( arg_filename )
		Open(arg_filename);
	}

bool PktDumper::Open(const char* arg_filename)
	{
	if ( ! arg_filename && ! *filename )
		{
		Error("no filename given");
		return false;
		}

	if ( arg_filename )
		{
		if ( dumper && streq(arg_filename, filename) )
			// Already open.
			return true;

		safe_strncpy(filename, arg_filename, FNBUF_LEN);
		}

	if ( dumper )
		Close();

	struct stat s;
	int exists = 0;

	if ( append )
		{
		// See if output file already exists (and is non-empty).
		exists = stat(filename, &s); ;

		if ( exists < 0 && errno != ENOENT )
			{
			Error(fmt("can't stat file %s: %s", filename, strerror(errno)));
			return false;
			}
		}

	if ( ! append || exists < 0 || s.st_size == 0 )
		{
		// Open new file.
		dumper =  pcap_dump_open(pd, filename);
		if ( ! dumper )
			{
			Error(pcap_geterr(pd));
			return false;
			}
		}

	else
		{
		// Old file and we need to append, which, unfortunately,
		// is not supported by libpcap. So, we have to hack a
		// little bit, knowing that pcap_dumpter_t is, in fact,
		// a FILE ... :-(
		dumper = (pcap_dumper_t*) fopen(filename, "a");
		if ( ! dumper )
			{
			Error(fmt("can't open dump %s: %s", filename, strerror(errno)));
			return false;
			}
		}

	open_time = network_time;
	is_error = false;
	return true;
	}

bool PktDumper::Close()
	{
	if ( dumper )
		{
		pcap_dump_close(dumper);
		dumper = 0;
		is_error = false;
		}

	return true;
	}

bool PktDumper::Dump(const struct pcap_pkthdr* hdr, const u_char* pkt)
	{
	if ( ! dumper )
		return false;

	if ( ! open_time )
		open_time = network_time;

	pcap_dump((u_char*) dumper, hdr, pkt);

	return true;
	}

void PktDumper::Error(const char* errstr)
	{
	safe_strncpy(errbuf, errstr, sizeof(errbuf));
	is_error = true;
	}

int get_link_header_size(int dl)
	{
	switch ( dl ) {
	case DLT_NULL:
		return 4;

	case DLT_EN10MB:
		return 14;

	case DLT_FDDI:
		return 13 + 8;	// fddi_header + LLC

#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		return 16;
#endif

	case DLT_RAW:
		return 0;
	}

	return -1;
	}

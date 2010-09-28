// $Id: PktSrc.h 6916 2009-09-24 20:48:36Z vern $
//
// See the file "COPYING" in the main distribution directory for copyright.

#ifndef pktsrc_h
#define pktsrc_h

#include "Dict.h"
#include "Expr.h"
#include "BPF_Program.h"
#include "IOSource.h"
#include "RemoteSerializer.h"

#define BRO_PCAP_ERRBUF_SIZE   PCAP_ERRBUF_SIZE + 256

extern "C" {
#include <pcap.h>
}

declare(PDict,BPF_Program);

// Whether a PktSrc object is used by the normal filter structure or the
// secondary-path structure.
typedef enum {
	TYPE_FILTER_NORMAL,  // the normal filter
	TYPE_FILTER_SECONDARY,  // the secondary-path filter
} PktSrc_Filter_Type;


// {filter,event} tuples conforming the secondary path.
class SecondaryEvent {
public:
	SecondaryEvent(const char* arg_filter, Func* arg_event)
		{
		filter = arg_filter;
		event = arg_event;
		}

	const char* Filter()	{ return filter; }
	Func* Event()		{ return event; }

private:
	const char* filter;
	Func* event;
};

declare(PList,SecondaryEvent);
typedef PList(SecondaryEvent) secondary_event_list;



class SecondaryPath {
public:
	SecondaryPath();
	~SecondaryPath();

	secondary_event_list& EventTable()	{ return event_list; }
	const char* Filter()			{ return filter; }

private:
	secondary_event_list event_list;
	// OR'ed union of all SecondaryEvent filters
	char* filter;
};

// Main secondary-path object.
extern SecondaryPath* secondary_path;


// {program, {filter,event}} tuple table.
class SecondaryProgram {
public:
	SecondaryProgram(BPF_Program* arg_program, SecondaryEvent* arg_event)
		{
		program = arg_program;
		event = arg_event;
		}

	~SecondaryProgram();

	BPF_Program* Program()  { return program; }
	SecondaryEvent* Event()	{ return event; }

private:
	// Associated program.
	BPF_Program *program;

	// Event that is run in case the program is matched.
	SecondaryEvent* event;
};

declare(PList,SecondaryProgram);
typedef PList(SecondaryProgram) secondary_program_list;



class PktSrc : public IOSource {
public:
	~PktSrc();

	// IOSource interface
	bool IsReady();
	void GetFds(int* read, int* write, int* except);
	double NextTimestamp(double* local_network_time);
	void Process();
	const char* Tag()	{ return "PktSrc"; }

	const char* ErrorMsg() const	{ return errbuf; }
	void ClearErrorMsg()		{ *errbuf ='\0'; }

	// Returns the packet last processed; false if there is no
	// current packet available.
	bool GetCurrentPacket(const pcap_pkthdr** hdr, const u_char** pkt);

	int HdrSize() const		{ return hdr_size; }
	int DataLink() const		{ return datalink; }

	void ConsumePacket()	{ data = 0; }

	int IsLive() const		{ return interface != 0; }

	pcap_t* PcapHandle() const	{ return pd; }
	int LinkType() const		{ return pcap_datalink(pd); }

	const char* ReadFile() const	{ return readfile; }
	const char* Interface() const	{ return interface; }
	PktSrc_Filter_Type FilterType() const	{ return filter_type; }
	void AddSecondaryTablePrograms();
	const secondary_program_list& ProgramTable() const
		{ return program_list; }

	// Signal packet source that processing was suspended and is now going
	// to be continued.
	void ContinueAfterSuspend();

	// Only valid in pseudo-realtime mode.
	double CurrentPacketTimestamp()	{ return current_pseudo; }
	double CurrentPacketWallClock();

	struct Stats {
		unsigned int received;	// pkts received (w/o drops)
		unsigned int dropped;	// pkts dropped
		unsigned int link;	// total packets on link
					// (not always not available)
	};

	virtual void Statistics(Stats* stats);

	// Precompiles a filter and associates the given index with it.
	// Returns true on success, 0 if a problem occurred.
	virtual int PrecompileFilter(int index, const char* filter);

	// Activates the filter with the given index.
	// Returns true on success, 0 if a problem occurred.
	virtual int SetFilter(int index);

protected:
	PktSrc();

	static const int PCAP_TIMEOUT = 20;

	void SetHdrSize();

	virtual void Close();

	// Returns 1 on success, 0 on time-out/gone dry.
	virtual int ExtractNextPacket();

	// Checks if the current packet has a pseudo-time <= current_time.
	// If yes, returns pseudo-time, otherwise 0.
	double CheckPseudoTime();

	double current_timestamp;
	double next_timestamp;

	// Only set in pseudo-realtime mode.
	double first_timestamp;
	double first_wallclock;
	double current_wallclock;
	double current_pseudo;

	struct pcap_pkthdr hdr;
	const u_char* data;	// contents of current packet
	const u_char* last_data;	// same, but unaffected by consuming
	int hdr_size;
	int datalink;
	double next_sync_point; // For trace synchronziation in pseudo-realtime

	char* interface;	// nil if not reading from an interface
	char* readfile;		// nil if not reading from a file

	pcap_t* pd;
	int selectable_fd;
	uint32 netmask;
	char errbuf[BRO_PCAP_ERRBUF_SIZE];

	Stats stats;

	PDict(BPF_Program) filters; // precompiled filters

	PktSrc_Filter_Type filter_type; // normal path or secondary path
	secondary_program_list program_list;
};

class PktInterfaceSrc : public PktSrc {
public:
	PktInterfaceSrc(const char* interface, const char* filter,
			PktSrc_Filter_Type ft=TYPE_FILTER_NORMAL);
};

class PktFileSrc : public PktSrc {
public:
	PktFileSrc(const char* readfile, const char* filter,
			PktSrc_Filter_Type ft=TYPE_FILTER_NORMAL);
};


extern int get_link_header_size(int dl);

class PktDumper {
public:
	PktDumper(const char* file = 0, bool append = false);
	~PktDumper()	{ Close(); }

	bool Open(const char* file = 0);
	bool Close();
	bool Dump(const struct pcap_pkthdr* hdr, const u_char* pkt);

	pcap_dumper_t* PcapDumper() 	{ return dumper; }

	const char* FileName() const	{ return filename; }
	bool IsError() const		{ return is_error; }
	const char* ErrorMsg() const	{ return errbuf; }

	// This heuristic will horribly fail if we're using packets
	// with different link layers.  (If we can't derive a reasonable value
	// from the packet sources, our fall-back is Ethernet.)
	int HdrSize() const
		{ return get_link_header_size(pcap_datalink(pd)); }

	// Network time when dump file was opened.
	double OpenTime() const		{ return open_time; }

private:
	void InitPd();
	void Error(const char* str);

	static const int FNBUF_LEN = 1024;
	char filename[FNBUF_LEN];

	bool append;
	pcap_dumper_t* dumper;
	pcap_t* pd;
	double open_time;

	bool is_error;
	char errbuf[BRO_PCAP_ERRBUF_SIZE];
};

#endif

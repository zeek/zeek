// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_PKTSRC_H
#define IOSOURCE_PKTSRC_PKTSRC_H

extern "C" {
#include <pcap.h>
}

#include "IOSource.h"
#include "BPF_Program.h"
#include "Dict.h"

declare(PDict,BPF_Program);

namespace iosource {

class PktSrc : public IOSource {
public:
	struct Stats {
		unsigned int received;	// pkts received (w/o drops)
		unsigned int dropped;	// pkts dropped
		unsigned int link;	// total packets on link
					// (not always not available)
					//
		Stats()	{ received = dropped = link = 0; }
	};

	PktSrc();
	virtual ~PktSrc();

	const std::string& Path() const;
	const std::string& Filter() const;
	bool IsLive() const;
	int LinkType() const;
	uint32 Netmask() const;
	const char* ErrorMsg() const;
	int HdrSize() const;
	int SnapLen() const;

	// Only valid in pseudo-realtime mode.
	double CurrentPacketTimestamp();
	double CurrentPacketWallClock();

	// Signal packet source that processing was suspended and is now
	// going to be continued.
	void ContinueAfterSuspend();

	// Precompiles a BPF filter and associates the given index with it.
	// Returns true on success, 0 if a problem occurred. The compiled
	// filter will be then available via GetBPFFilter*(.
	int PrecompileBPFFilter(int index, const std::string& filter);

	// Returns the BPF filter with the given index, as compiled by
	// PrecompileBPFFilter(), or null if none has been (successfully)
	// compiled.
	BPF_Program* GetBPFFilter(int index);

	// Applies a precompiled BPF filter to a packet, returning true if it
	// maches. This will close the source with an error message if no
	// filter with that index has been compiled.
	int ApplyBPFFilter(int index, const struct pcap_pkthdr *hdr, const u_char *pkt);

	// PacketSource interace for derived classes to override.

	// Returns the packet last processed; false if there is no
	// current packet available.
	virtual bool GetCurrentPacket(const pcap_pkthdr** hdr, const u_char** pkt) = 0;

	// Precompiles a filter and associates the given index with it.
	// Returns true on success, 0 if a problem occurred or filtering is
	// not supported.
	virtual int PrecompileFilter(int index, const std::string& filter) = 0;

	// Activates the filter with the given index. Returns true on
	// success, 0 if a problem occurred or the filtering is not
	// supported.
	virtual int SetFilter(int index) = 0;

	// Returns current statistics about the source.
	virtual void Statistics(Stats* stats) = 0;

	static int GetLinkHeaderSize(int link_type);

protected:
	// Methods to use by derived classes.

	struct Properties {
		std::string path;
		std::string filter; // Maybe different than what's passed in if not (directly) supported.
		int selectable_fd;
		int link_type;
		int hdr_size;
		uint32 netmask;
		bool is_live;

		Properties()
			{
			netmask = PCAP_NETMASK_UNKNOWN;
			}
	};

	struct Packet {
		double ts;
		const struct ::pcap_pkthdr* hdr;
		const u_char* data;
	};

	void Opened(const Properties& props);
	void Closed();
	void Info(const std::string& msg);
	void Error(const std::string& msg);
	void Weird(const std::string& msg, const Packet* pkt);
	void InternalError(const std::string& msg);

	// PktSrc interface for derived classes to implement.

	virtual void Open() = 0;
	virtual void Close() = 0;
	// Returns 1 on success, 0 on time-out/gone dry.
	virtual int ExtractNextPacket(Packet* pkt) = 0;
	virtual void DoneWithPacket(Packet* pkt) = 0;

private:
	// Checks if the current packet has a pseudo-time <= current_time.
	// If yes, returns pseudo-time, otherwise 0.
	double CheckPseudoTime();

	// XXX
	int ExtractNextPacketInternal();

	// IOSource interface implementation.
	virtual void Init();
	virtual void Done();
	virtual void GetFds(int* read, int* write, int* except);
	virtual double NextTimestamp(double* local_network_time);
	virtual void Process();
	virtual const char* Tag();

	Properties props;

	bool have_packet;
	Packet current_packet;

	// For BPF filtering support.
	PDict(BPF_Program) filters;

	// Only set in pseudo-realtime mode.
	double first_timestamp;
	double first_wallclock;
	double current_wallclock;
	double current_pseudo;
	double next_sync_point; // For trace synchronziation in pseudo-realtime

	std::string errbuf;
};

}


#endif

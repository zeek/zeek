// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_PKTSRC_H
#define IOSOURCE_PKTSRC_PKTSRC_H

extern "C" {
#include <pcap.h>
}

#include "../IOSource.h"

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
	const char* ErrorMsg() const;
	int HdrSize() const;
	int SnapLen() const;

	// Only valid in pseudo-realtime mode.
	double CurrentPacketTimestamp();
	double CurrentPacketWallClock();

	// Signal packet source that processing was suspended and is now
	// going to be continued.
	void ContinueAfterSuspend();

	virtual void Statistics(Stats* stats) = 0;

	// Returns the packet last processed; false if there is no
	// current packet available.
	virtual bool GetCurrentPacket(const pcap_pkthdr** hdr, const u_char** pkt) = 0;

	// Precompiles a filter and associates the given index with it.
	// Returns true on success, 0 if a problem occurred or filtering is
	// not supported.
	virtual int PrecompileFilter(int index, const std::string& filter);

	// Activates the filter with the given index. Returns true on
	// success, 0 if a problem occurred or the filtering is not
	// supported.
	virtual int SetFilter(int index);

	static int GetLinkHeaderSize(int link_type);

protected:
	// Methods to use by derived classes.

	struct Properties {
		std::string path;
		std::string filter; // Maybe different than what's passed in if not (directly) supported.
		int selectable_fd;
		int link_type;
		int hdr_size;
		bool is_live;
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

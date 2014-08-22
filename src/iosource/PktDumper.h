// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_PKTDUMPER_H
#define IOSOURCE_PKTSRC_PKTDUMPER_H

#include "IOSource.h"

namespace iosource {

class PktDumper {
public:
	struct Packet {
		const struct pcap_pkthdr* hdr;
		const u_char* data;
	};

	PktDumper();
	virtual ~PktDumper();

	const std::string& Path() const;
	bool IsOpen() const;
	double OpenTime() const;
	bool IsError() const;
	const std::string& ErrorMsg() const;
	int HdrSize() const;
	bool Record(const Packet* pkt);

	// PktSrc interface for derived classes to implement.
	virtual void Close() = 0;
	virtual void Open() = 0;
	virtual bool Dump(const Packet* pkt) = 0;

protected:
	// Methods to use by derived classed.
	//
	struct Properties {
		std::string path;
		int hdr_size;
		double open_time;
	};

	void Opened(const Properties& props);
	void Closed();
	void Error(const std::string& msg);

private:
	bool is_open;
	Properties props;

	std::string errmsg;
};

}

#endif

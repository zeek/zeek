// See the file  in the main distribution directory for copyright.

#pragma once

extern "C" {
#include <pcap.h>
}

#include "../PktDumper.h"

namespace zeek::iosource::pcap {

class PcapDumper : public PktDumper {
public:
	PcapDumper(const std::string& path, bool append);
	~PcapDumper() override;

	static PktDumper* Instantiate(const std::string& path, bool appen);

protected:
	// PktDumper interface.
	void Open() override;
	void Close() override;
	bool Dump(const zeek::Packet* pkt) override;

private:
	Properties props;

	bool append;
	pcap_dumper_t* dumper;
	pcap_t* pd;
};

} // namespace zeek::iosource::pcap

namespace iosource::pcap {
	using PcapDumper [[deprecated("Remove in v4.1. Use zeek::iosource::pcap::PcapDumper.")]] = zeek::iosource::pcap::PcapDumper;
}

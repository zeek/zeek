// See the file  in the main distribution directory for copyright.

#pragma once

extern "C" {
#include <pcap.h>
}

#include "../PktDumper.h"

namespace iosource {
namespace pcap {

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

}
}

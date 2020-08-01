// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "../PktSrc.h"

extern "C" {
#include <pcap.h>
}

#include <sys/types.h> // for u_char

namespace zeek::iosource::pcap {

class PcapSource : public zeek::iosource::PktSrc {
public:
	PcapSource(const std::string& path, bool is_live);
	~PcapSource() override;

	static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
	// PktSrc interface.
	void Open() override;
	void Close() override;
	bool ExtractNextPacket(zeek::Packet* pkt) override;
	void DoneWithPacket() override;
	bool PrecompileFilter(int index, const std::string& filter) override;
	bool SetFilter(int index) override;
	void Statistics(Stats* stats) override;

private:
	void OpenLive();
	void OpenOffline();
	void PcapError(const char* where = nullptr);

	Properties props;
	Stats stats;

	pcap_t *pd;
};

} // namespace zeek::iosource::pcap

namespace iosource::pcap {
	using PcapSource [[deprecated("Remove in v4.1. Use zeek::iosource::pcap::PcapSource.")]] = zeek::iosource::pcap::PcapSource;
}

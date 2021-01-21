// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h> // for u_char

extern "C" {
#include <pcap.h>
}

#include "zeek/iosource/PktSrc.h"

namespace zeek::iosource::pcap {

class PcapSource : public PktSrc {
public:
	PcapSource(const std::string& path, bool is_live);
	~PcapSource() override;

	static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
	// PktSrc interface.
	void Open() override;
	void Close() override;
	bool ExtractNextPacket(Packet* pkt) override;
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

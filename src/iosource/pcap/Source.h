#pragma once

#include <pcap.h>
#include <string>

#include "iosource/PktSrc.h"

namespace iosource {
namespace pcap {

class PcapSource : public PktSrc
	{
public:
	PcapSource(const std::string& path, bool is_live);
	~PcapSource() = default;

	virtual void Open() final;
	virtual void Close() final;

	static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:

	bool PrecompileFilter(int index, const std::string& filter) final;
	bool SetFilter(int index) final;
	void Statistics(Stats* stats) final;
	void HandleNewData(int fd) final;

private:

	// These methods are overridden from PktSrc, but are unused in libuv sources.
	virtual bool ExtractNextPacket(Packet* pkt) final { return false; }
	virtual void DoneWithPacket() final {}

	bool OpenLive();
	bool OpenOffline();
	void PcapError(const std::string& where = "");
	void SetHdrSize();

	Properties props;
	Stats stats;

	pcap_t* pd = nullptr;

	struct pcap_pkthdr current_hdr;
	struct pcap_pkthdr last_hdr;
	const u_char* last_data = nullptr;
	};

}
}

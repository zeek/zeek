// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_NETMAP_SOURCE_H
#define IOSOURCE_PKTSRC_NETMAP_SOURCE_H

extern "C" {
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
}

#include "../PktSrc.h"

namespace iosource {
namespace pktsrc {

class NetmapSource : public iosource::PktSrc {
public:
	// XXX
	NetmapSource(const std::string& path, const std::string& filter, bool is_live, const std::string& kind);
	virtual ~NetmapSource();

	static PktSrc* InstantiateNetmap(const std::string& path, const std::string& filter, bool is_live);
	static PktSrc* InstantiateVale(const std::string& path, const std::string& filter, bool is_live);

protected:
	// PktSrc interface.
	virtual void Open();
	virtual void Close();
	virtual int ExtractNextPacket(Packet* pkt);
	virtual void DoneWithPacket(Packet* pkt);
	virtual void Statistics(Stats* stats);
	virtual bool GetCurrentPacket(const pcap_pkthdr** hdr, const u_char** pkt);

private:
	std::string kind;
	Properties props;
	Stats stats;

	nm_desc_t *nd;
	pcap_pkthdr current_hdr;
	pcap_pkthdr last_hdr;
	const u_char* last_data;
};

}
}

#endif

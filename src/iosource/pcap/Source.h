// See the file "COPYING" in the main distribution directory for copyright.

#ifndef IOSOURCE_PKTSRC_PCAP_SOURCE_H
#define IOSOURCE_PKTSRC_PCAP_SOURCE_H

#include "../PktSrc.h"

#ifdef HAVE_PACKET_FANOUT
extern bool packet_fanout_enable;
extern int packet_fanout_id;
extern bool packet_fanout_flag_defrag;
#endif

namespace iosource {
namespace pcap {

class PcapSource : public iosource::PktSrc {
public:
	PcapSource(const std::string& path, bool is_live);
	virtual ~PcapSource();

	static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
	// PktSrc interface.
	virtual void Open();
	virtual void Close();
	virtual bool ExtractNextPacket(Packet* pkt);
	virtual void DoneWithPacket();
	virtual bool PrecompileFilter(int index, const std::string& filter);
	virtual bool SetFilter(int index);
	virtual void Statistics(Stats* stats);

private:
	void OpenLive();
	void OpenOffline();
	void PcapError();
	void SetHdrSize();

	Properties props;
	Stats stats;

	pcap_t *pd;

	struct pcap_pkthdr current_hdr;
	struct pcap_pkthdr last_hdr;
	const u_char* last_data;
};

}
}

#endif

// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

extern "C" {
#include <errno.h>            // errorno
#include <linux/if.h>         // ifreq
#include <linux/if_packet.h>  // AF_PACKET, etc.
#include <linux/net_tstamp.h> // hwtstamp_config
#include <linux/sockios.h>    // SIOCSHWTSTAMP
#include <net/ethernet.h>     // ETH_P_ALL
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h> // close()
}

#include "zeek/iosource/PktSrc.h"
#include "zeek/iosource/af_packet/RX_Ring.h"

namespace zeek::iosource::af_packet {

class AF_PacketSource : public zeek::iosource::PktSrc {
public:
    /**
     * Constructor.
     *
     * path: Name of the interface to open (the AF_Packet source doesn't
     * support reading from files).
     *
     * is_live: Must be true (the AF_Packet source doesn't support offline
     * operation).
     */
    AF_PacketSource(const std::string& path, bool is_live);

    /**
     * Destructor.
     */
    ~AF_PacketSource() override;

    static PktSrc* InstantiateAF_Packet(const std::string& path, bool is_live);

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
    Properties props;
    Stats stats;

    int current_filter = 0;
    unsigned int num_discarded = 0;
    int checksum_mode = 0;

    int socket_fd = -1;
    RX_Ring* rx_ring = nullptr;
    struct pcap_pkthdr current_hdr = {};

    struct InterfaceInfo {
        int index = -1;
        int flags = 0;

        bool Valid() { return index >= 0; }
        bool IsUp() { return flags & IFF_UP; }
        bool IsLoopback() { return flags & IFF_LOOPBACK; }
    };

    InterfaceInfo GetInterfaceInfo(const std::string& path);
    bool BindInterface(const InterfaceInfo& info);
    bool EnablePromiscMode(const InterfaceInfo& info);
    bool ConfigureFanoutGroup(bool enabled, bool defrag);
    bool ConfigureHWTimestamping(bool enabled);
    uint32_t GetFanoutMode(bool defrag);
};

} // namespace zeek::iosource::af_packet

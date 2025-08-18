// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/zeek-config.h"

// Starting with Zeek 6.0, zeek-config.h does not provide the
// ZEEK_VERSION_NUMBER macro anymore when compiling a included
// plugin. Use the new zeek/zeek-version.h header if it exists.
#if __has_include("zeek/zeek-version.h")
#include "zeek/zeek-version.h"
#endif

#include "AF_Packet.h"
#include "RX_Ring.h"
#include "af_packet.bif.h"

// CentOS 7 if_packet.h does not yet have this define, provide it
// explicitly if missing.
#ifndef TP_STATUS_CSUM_VALID
#define TP_STATUS_CSUM_VALID (1 << 7)
#endif

using namespace zeek::iosource::pktsrc;

AF_PacketSource::~AF_PacketSource() { Close(); }

AF_PacketSource::AF_PacketSource(const std::string& path, bool is_live) {
    if ( ! is_live )
        Error("AF_Packet source does not support offline input");

    current_filter = -1;
    props.path = path;
    props.is_live = is_live;

    socket_fd = -1;
    rx_ring = nullptr;

    checksum_mode = zeek::BifConst::AF_Packet::checksum_validation_mode->AsEnum();
}

void AF_PacketSource::Open() {
    uint64_t buffer_size = zeek::BifConst::AF_Packet::buffer_size;
    uint64_t block_size = zeek::BifConst::AF_Packet::block_size;
    int block_timeout_msec = static_cast<int>(zeek::BifConst::AF_Packet::block_timeout * 1000.0);
    int link_type = zeek::BifConst::AF_Packet::link_type;

    bool enable_hw_timestamping = zeek::BifConst::AF_Packet::enable_hw_timestamping;
    bool enable_fanout = zeek::BifConst::AF_Packet::enable_fanout;
    bool enable_defrag = zeek::BifConst::AF_Packet::enable_defrag;

    socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if ( socket_fd < 0 ) {
        Error(errno ? strerror(errno) : "unable to create socket");
        return;
    }

    auto info = GetInterfaceInfo(props.path);

    if ( ! info.Valid() ) {
        Error(errno ? strerror(errno) : "unable to get interface information");
        close(socket_fd);
        socket_fd = -1;
        return;
    }

    if ( ! info.IsUp() ) {
        Error("interface is down");
        close(socket_fd);
        socket_fd = -1;
        return;
    }

    // Create RX-ring
    try {
        rx_ring = new RX_Ring(socket_fd, buffer_size, block_size, block_timeout_msec);
    } catch ( RX_RingException& e ) {
        Error(errno ? strerror(errno) : "unable to create RX-ring");
        close(socket_fd);
        return;
    }

    // Setup interface
    if ( ! BindInterface(info) ) {
        Error(errno ? strerror(errno) : "unable to bind to interface");
        close(socket_fd);
        return;
    }

    if ( ! EnablePromiscMode(info) ) {
        Error(errno ? strerror(errno) : "unable enter promiscuous mode");
        close(socket_fd);
        return;
    }

    if ( ! ConfigureFanoutGroup(enable_fanout, enable_defrag) ) {
        Error(errno ? strerror(errno) : "failed to join fanout group");
        close(socket_fd);
        return;
    }

    if ( ! ConfigureHWTimestamping(enable_hw_timestamping) ) {
        Error(errno ? strerror(errno) : "failed to configure hardware timestamping");
        close(socket_fd);
        return;
    }

    props.netmask = NETMASK_UNKNOWN;
    props.selectable_fd = socket_fd;
    props.is_live = true;
    props.link_type = link_type;

    stats.received = stats.dropped = stats.link = stats.bytes_received = 0;
    num_discarded = 0;

    Opened(props);
}

AF_PacketSource::InterfaceInfo AF_PacketSource::GetInterfaceInfo(const std::string& path) {
    AF_PacketSource::InterfaceInfo info;
    struct ifreq ifr;
    int ret;

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", path.c_str());

    ret = ioctl(socket_fd, SIOCGIFFLAGS, &ifr);
    if ( ret < 0 )
        return info;

    info.flags = ifr.ifr_flags;

    ret = ioctl(socket_fd, SIOCGIFINDEX, &ifr);
    if ( ret < 0 )
        return info;

    info.index = ifr.ifr_ifindex;

    return info;
}

bool AF_PacketSource::BindInterface(const AF_PacketSource::InterfaceInfo& info) {
    struct sockaddr_ll saddr_ll;
    int ret;

    memset(&saddr_ll, 0, sizeof(saddr_ll));
    saddr_ll.sll_family = AF_PACKET;
    saddr_ll.sll_protocol = htons(ETH_P_ALL);
    saddr_ll.sll_ifindex = info.index;

    ret = bind(socket_fd, (struct sockaddr*)&saddr_ll, sizeof(saddr_ll));
    return (ret >= 0);
}

bool AF_PacketSource::EnablePromiscMode(const AF_PacketSource::InterfaceInfo& info) {
    struct packet_mreq mreq;
    int ret;

    memset(&mreq, 0, sizeof(mreq));
    mreq.mr_ifindex = info.index;
    mreq.mr_type = PACKET_MR_PROMISC;

    ret = setsockopt(socket_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
    return (ret >= 0);
}

bool AF_PacketSource::ConfigureFanoutGroup(bool enabled, bool defrag) {
    if ( enabled ) {
        uint32_t fanout_arg, fanout_id;
        int ret;

        fanout_id = zeek::BifConst::AF_Packet::fanout_id;
        fanout_arg = ((fanout_id & 0xffff) | (GetFanoutMode(defrag) << 16));

        ret = setsockopt(socket_fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg, sizeof(fanout_arg));

        if ( ret < 0 )
            return false;
    }
    return true;
}

bool AF_PacketSource::ConfigureHWTimestamping(bool enabled) {
    if ( enabled ) {
        struct ifreq ifr;
        struct hwtstamp_config hwts_cfg;
        int ret, opt;

        memset(&hwts_cfg, 0, sizeof(hwts_cfg));
        hwts_cfg.tx_type = HWTSTAMP_TX_OFF;
        hwts_cfg.rx_filter = HWTSTAMP_FILTER_ALL;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", props.path.c_str());
        ifr.ifr_data = &hwts_cfg;

        ret = ioctl(socket_fd, SIOCSHWTSTAMP, &ifr);
        if ( ret < 0 )
            return false;

        opt = SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE;
        ret = setsockopt(socket_fd, SOL_PACKET, PACKET_TIMESTAMP, &opt, sizeof(opt));
        if ( ret < 0 )
            return false;
    }
    return true;
}

uint32_t AF_PacketSource::GetFanoutMode(bool defrag) {
    uint32_t fanout_mode;

    switch ( zeek::BifConst::AF_Packet::fanout_mode->AsEnum() ) {
        case BifEnum::AF_Packet::FANOUT_CPU: fanout_mode = PACKET_FANOUT_CPU; break;
#ifdef PACKET_FANOUT_QM
        case BifEnum::AF_Packet::FANOUT_QM: fanout_mode = PACKET_FANOUT_QM; break;
#endif
#ifdef PACKET_FANOUT_CBPF
        case BifEnum::AF_Packet::FANOUT_CBPF: fanout_mode = PACKET_FANOUT_CBPF; break;
#endif
#ifdef PACKET_FANOUT_EBPF
        case BifEnum::AF_Packet::FANOUT_EBPF: fanout_mode = PACKET_FANOUT_EBPF; break;
#endif
        default: fanout_mode = PACKET_FANOUT_HASH; break;
    }

    if ( defrag )
        fanout_mode |= PACKET_FANOUT_FLAG_DEFRAG;

    return fanout_mode;
}

void AF_PacketSource::Close() {
    if ( socket_fd < 0 )
        return;

    delete rx_ring;
    rx_ring = nullptr;

    close(socket_fd);
    socket_fd = -1;

    Closed();
}

bool AF_PacketSource::ExtractNextPacket(zeek::Packet* pkt) {
    if ( ! socket_fd )
        return false;

    struct tpacket3_hdr* packet = 0;
    const u_char* data;
    while ( true ) {
        if ( ! rx_ring->GetNextPacket(&packet) )
            return false;

        current_hdr.ts.tv_sec = packet->tp_sec;
        current_hdr.ts.tv_usec = packet->tp_nsec / 1000;
        current_hdr.caplen = packet->tp_snaplen;
        current_hdr.len = packet->tp_len;
        data = (u_char*)packet + packet->tp_mac;

        if ( ! ApplyBPFFilter(current_filter, &current_hdr, data) ) {
            ++num_discarded;
            DoneWithPacket();
            continue;
        }

        pkt->Init(props.link_type, &current_hdr.ts, current_hdr.caplen, current_hdr.len, data);

        if ( packet->tp_status & TP_STATUS_VLAN_VALID )
            pkt->vlan = packet->hv1.tp_vlan_tci & 0x0fff;

#if ZEEK_VERSION_NUMBER >= 50100
        switch ( checksum_mode ) {
            case BifEnum::AF_Packet::CHECKSUM_OFF: {
                // If set to off, just accept whatever checksum in the packet is correct and
                // skip checking it here and in Zeek.
                pkt->l4_checksummed = true;
                break;
            }
            case BifEnum::AF_Packet::CHECKSUM_KERNEL: {
                // If set to kernel, check whether the kernel thinks the checksum is valid. If it
                // does, tell Zeek to skip checking by itself.
                if ( ((packet->tp_status & TP_STATUS_CSUM_VALID) != 0) ||
                     ((packet->tp_status & TP_STATUS_CSUMNOTREADY) != 0) )
                    pkt->l4_checksummed = true;
                else
                    pkt->l4_checksummed = false;
                break;
            }
            case BifEnum::AF_Packet::CHECKSUM_ON:
            default: {
                // Let Zeek handle it.
                pkt->l4_checksummed = false;
                break;
            }
        }
#endif

        if ( current_hdr.len == 0 || current_hdr.caplen == 0 ) {
            Weird("empty_af_packet_header", pkt);
            return false;
        }

        stats.received++;
        stats.bytes_received += current_hdr.len;
        return true;
    }

    return false;
}

void AF_PacketSource::DoneWithPacket() { rx_ring->ReleasePacket(); }

bool AF_PacketSource::PrecompileFilter(int index, const std::string& filter) {
    return PktSrc::PrecompileBPFFilter(index, filter);
}

bool AF_PacketSource::SetFilter(int index) {
    current_filter = index;
    return true;
}

void AF_PacketSource::Statistics(Stats* s) {
    if ( ! socket_fd ) {
        s->received = s->bytes_received = s->link = s->dropped = 0;
        return;
    }

    struct tpacket_stats_v3 tp_stats;
    socklen_t tp_stats_len = sizeof(struct tpacket_stats_v3);
    int ret;

    ret = getsockopt(socket_fd, SOL_PACKET, PACKET_STATISTICS, &tp_stats, &tp_stats_len);
    if ( ret < 0 ) {
        Error(errno ? strerror(errno) : "unable to retrieve statistics");
        s->received = s->bytes_received = s->link = s->dropped = 0;
        return;
    }

    stats.link += tp_stats.tp_packets;
    stats.dropped += tp_stats.tp_drops;

    memcpy(s, &stats, sizeof(Stats));
}

zeek::iosource::PktSrc* AF_PacketSource::InstantiateAF_Packet(const std::string& path, bool is_live) {
    return new AF_PacketSource(path, is_live);
}

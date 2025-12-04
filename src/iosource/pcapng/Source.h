// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <optional>
#include <string>
#include <vector>

#include "zeek/iosource/PktSrc.h"

struct light_file_t;
using light_file = struct light_file_t*;

struct light_block_t;
using light_block = struct light_block_t*;

namespace zeek::iosource::pcapng {

/**
 * A packet source for reading data in the pcapng file format. See
 * https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html for more information
 * about the format of these files.
 */
class Source : public PktSrc {
public:
    Source(const std::string& path);
    ~Source() override;

    static PktSrc* Instantiate(const std::string& path, bool is_live);

protected:
    // PktSrc interface.
    void Open() override;
    void Close() override;
    bool ExtractNextPacket(Packet* pkt) override;
    void DoneWithPacket() override;
    bool SetFilter(int index) override { return true; }
    void Statistics(Stats* stats) override;

    detail::BPF_Program* CompileFilter(const std::string& filter) override;

private:
    enum IntfOptionNumbers : uint8_t {
        PCAPNG_OPT_IF_NAME = 2,
        PCAPNG_OPT_IF_DESCRIPTION = 3,
        PCAPNG_OPT_IF_IPV4ADDR = 4,
        PCAPNG_OPT_IF_IPV6ADDR = 5,
        PCAPNG_OPT_IF_MACADDR = 6,
        PCAPNG_OPT_IF_EUIADDR = 7,
        PCAPNG_OPT_IF_SPEED = 8,
        PCAPNG_OPT_IF_TSRESOL = 9,
        PCAPNG_OPT_IF_TZONE = 10,
        PCAPNG_OPT_IF_FILTER = 11,
        PCAPNG_OPT_IF_OS = 12,
        PCAPNG_OPT_IF_FCSLEN = 13,
        PCAPNG_OPT_IF_TSOFFSET = 14,
        PCAPNG_OPT_IF_HARDWARE = 15,
        PCAPNG_OPT_IF_TXSPEED = 16,
        PCAPNG_OPT_IF_RXSPEED = 17,
        PCAPNG_OPT_IF_IANA_TZNAME = 18,
    };

    enum PacketOptionNumbers : uint8_t {
        PCAPNG_OPT_EPB_FLAGS = 2,
        PCAPNG_OPT_EPB_HASH = 3,
        PCAPNG_OPT_EPB_DROPCOUNT = 4,
        PCAPNG_OPT_EPB_PACKETID = 5,
        PCAPNG_OPT_EPB_QUEUE = 6,
        PCAPNG_OPT_EPB_VERDICT = 7,
        PCAPNG_OPT_EPB_PROCESSID_THREADID = 8,
    };

    struct Interface {
        uint16_t link_type = 0;
        uint32_t snaplen = 0;
        uint32_t ts_resolution = 1e6;
        std::optional<std::string> name;
        std::optional<std::string> description;
        std::optional<std::vector<std::string>> ipv4_addrs;
        std::optional<std::vector<std::string>> ipv6_addrs;
        std::optional<std::string> mac_addr;
        std::optional<std::string> eui_addr;
        std::optional<uint64_t> if_speed;
        std::optional<std::string> filter;
        std::optional<std::string> os;
        std::optional<uint8_t> fcs_len;
        std::optional<uint64_t> ts_offset;
        std::optional<std::string> hardware;
        std::optional<uint64_t> tx_speed;
        std::optional<uint64_t> rx_speed;
        std::optional<std::string> iana_tzname;
    };

    struct PacketBlock {
        uint32_t interface = 0;
        struct timeval ts_tval{};
        uint32_t caplen = 0;
        uint32_t origlen = 0;
        uint8_t* data;

        uint64_t dropcount = 0;
        std::optional<std::vector<std::string>> comments;
        std::optional<uint32_t> flags;
        std::optional<std::vector<std::string>> hashes;
        std::optional<uint64_t> packet_id;
        std::optional<uint32_t> queue;
        std::optional<std::vector<std::string>> verdicts;
        std::optional<std::string> processid_threadid;
    };

    void ParseSectionHeaderBlock(light_block block);
    void ParseInterfaceBlock(light_block block);
    PacketBlock ParseEnhancedPacketBlock(light_block block);
    PacketBlock ParseSimplePacketBlock(light_block block);

    void PcapngError(const char* where = nullptr);

    std::vector<Interface> interfaces;

    Properties props;
    Stats stats;

    light_file pd = nullptr;
    light_block current_block = nullptr;
};

} // namespace zeek::iosource::pcapng

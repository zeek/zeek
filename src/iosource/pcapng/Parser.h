// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

struct light_block_t;
using light_block = struct light_block_t*;

namespace zeek::iosource::pcapng {

class Parser {
public:
    Parser(bool send_events) : send_events(send_events) {}

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

    enum BlockStatus : uint8_t {
        OK,
        PACKET_BLOCK,
        BAD_PACKET,
    };

    BlockStatus ParseBlock(light_block block);
    const PacketBlock& GetCurrentPacket() const { return current_packet; }
    void CleanupLastBlock();
    int GetLinkType(uint32_t interface_num) const {
        if ( interface_num > interfaces.size() )
            return -1;

        return interfaces[interface_num].link_type;
    }

    std::string GetInterfaceName(uint32_t interface_num) const {
        if ( interface_num > interfaces.size() || ! interfaces[interface_num].name )
            return "<invalid>";

        return interfaces[interface_num].name.value();
    }

private:
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

    void ParseSectionHeaderBlock(light_block block);
    void ParseInterfaceBlock(light_block block);
    PacketBlock ParseEnhancedPacketBlock(light_block block);
    PacketBlock ParseSimplePacketBlock(light_block block);

    std::vector<Interface> interfaces;
    light_block current_block = nullptr;
    PacketBlock current_packet;

    bool send_events = false;
};

} // namespace zeek::iosource::pcapng

// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <string>

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
    struct PacketBlock {
        uint32_t interface = 0;
        struct timeval ts_tval{};
        uint32_t caplen = 0;
        uint32_t origlen = 0;
        uint8_t* data;

        uint64_t dropcount = 0;
    };

    PacketBlock ParseEnhancedPacketBlock(light_block block);

    struct Interface {
        uint16_t link_type = 0;
        uint32_t snaplen = 0;
        uint32_t ts_resolution = 1e6;
    };

    void ParseInterfaceBlock(light_block block);

    Properties props;
    Stats stats;

    std::vector<Interface> interfaces;
    PacketBlock current_pkt_block;
    light_block current_block;

    light_file pd = nullptr;
};

} // namespace zeek::iosource::pcapng

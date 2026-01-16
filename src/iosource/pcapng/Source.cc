// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/pcapng/Source.h"

#include <cstdio>

#include "zeek/DebugLogger.h"
#include "zeek/Event.h"

#include "light_pcapng.h"

using namespace zeek::iosource;
using namespace zeek::iosource::pcapng;

static bool validate_option_length(int expected, int have) {
    if ( have < expected ) {
        zeek::reporter->Weird("pcapng_invalid_option_length",
                              zeek::util::fmt("expected %d bytes, got %d bytes", expected, have));
        return false;
    }

    return true;
}

static uint16_t pcapng_extract_uint16(uint8_t* opt_data, uint16_t opt_length) {
    if ( ! validate_option_length(2, opt_length) )
        return 0;

    uint16_t val = opt_data[0];
    val << 8;
    val |= opt_data[1];
    return val;
}

static uint32_t pcapng_extract_uint32(uint8_t* opt_data, uint16_t opt_length) {
    if ( ! validate_option_length(4, opt_length) )
        return 0;

    uint32_t val = pcapng_extract_uint16(opt_data, opt_length);
    val << 16;
    val |= pcapng_extract_uint16(opt_data + 2, opt_length);
    return val;
}

static uint64_t pcapng_extract_uint64(uint8_t* opt_data, uint16_t opt_length) {
    if ( ! validate_option_length(8, opt_length) )
        return 0;

    uint64_t val = pcapng_extract_uint32(opt_data, opt_length);
    val << 32;
    val |= pcapng_extract_uint32(opt_data + 4, opt_length);
    return val;
}

Source::Source(const std::string& path) {
    props.path = path;
    props.is_live = false;
    pd = nullptr;
}

Source::~Source() { Close(); }

void Source::Open() {
    char errbuf[PCAP_ERRBUF_SIZE];

    FILE* f = nullptr;
    if ( pd = light_io_open(props.path.c_str(), "rb"); ! pd ) {
        Error(util::fmt("unable to open %s: %s", props.path.c_str(), strerror(errno)));
        return;
    }

    // We don't have direct access to the file descriptor in the light_file pointer. It's
    // a FILE object internally to LightPcapNg, but it's not exposed externally.
    props.selectable_fd = -1;

    props.link_type = -1;
    props.is_live = false;

    Opened(props);
}

void Source::Close() {
    if ( ! pd )
        return;

    light_io_close(pd);
    pd = nullptr;

    Closed();

    if ( Pcap::file_done )
        event_mgr.Enqueue(Pcap::file_done, make_intrusive<StringVal>(props.path));
}

bool Source::ExtractNextPacket(Packet* pkt) {
    if ( ! pd )
        return false;

    light_block block = nullptr;

    // Loop until we've found an enhanced packet block.
    while ( true ) {
        bool endian_swap = false;
        light_read_block(pd, &block, &endian_swap);
        if ( ! block ) {
            // If we get a nullptr back, we've run out of blocks and the file is done.
            Close();
            return false;
        }

        if ( block->type == LIGHT_INTERFACE_BLOCK )
            ParseInterfaceBlock(block);
        else if ( block->type == LIGHT_ENHANCED_PACKET_BLOCK ) {
            current_pkt_block = ParseEnhancedPacketBlock(block);

            if ( current_pkt_block.caplen == 0 || current_pkt_block.origlen == 0 ) {
                reporter->Weird("empty_pcapng_header");
                light_free_block(block);
                return false;
            }

            if ( current_pkt_block.interface >= interfaces.size() ) {
                reporter->Weird("pcapng_invalid_interface_number", util::fmt("%d", current_pkt_block.interface));
                light_free_block(block);
                return false;
            }

            current_block = block;

            break;
        }
        else if ( block->type == LIGHT_SECTION_HEADER_BLOCK )
            // If we get a new section header block, it's like starting over with a new
            // file. Reset the interfaces because we should get new ones.
            interfaces.clear();
        else
            DBG_LOG(DBG_PKTIO, "pcapng: ignoring block of type %d", block->type);
    }

    uint16_t link_type = interfaces[current_pkt_block.interface].link_type;

    pkt->Init(link_type, &current_pkt_block.ts_tval, current_pkt_block.caplen, current_pkt_block.origlen,
              current_pkt_block.data);

    ++stats.received;
    stats.dropped += current_pkt_block.dropcount;
    stats.bytes_received += current_pkt_block.origlen;

    return true;
}

void Source::DoneWithPacket() { light_free_block(current_block); }

void Source::Statistics(Stats* s) {
    s->link = 0;
    s->dropped = stats.dropped;
    s->received = stats.received;
    s->bytes_received = stats.bytes_received;
}

detail::BPF_Program* Source::CompileFilter(const std::string& filter) {
    auto code = std::make_unique<detail::BPF_Program>();
    return code.release();
}

PktSrc* Source::Instantiate(const std::string& path, bool is_live) { return new Source(path); }

void Source::ParseInterfaceBlock(light_block block) {
    // Use the struct defined by Light to avoid some parsing.
    auto lidb = reinterpret_cast<_light_interface_description_block*>(block->body);

    Interface intf;
    intf.link_type = lidb->link_type;
    intf.snaplen = lidb->snapshot_length;

    light_option opt = light_find_option(block, LIGHT_OPTION_IF_TSRESOL);
    if ( opt ) {
        if ( (opt->data[0] & 0x80) == 0x80 )
            intf.ts_resolution = 2 << (opt->data[0] & 0x7F);
        else
            intf.ts_resolution = static_cast<uint32_t>(pow(10, (opt->data[0] & 0x7f)));
    }

    interfaces.emplace_back(intf);
}

Source::PacketBlock Source::ParseEnhancedPacketBlock(light_block block) {
    // Use the struct defined by Light to avoid some parsing.
    auto lepb = reinterpret_cast<_light_enhanced_packet_block*>(block->body);

    PacketBlock pb;

    pb.interface = lepb->interface_id;

    uint64_t ts = lepb->timestamp_high;
    ts <<= 32;
    ts += lepb->timestamp_low;

    // The timestamp is the number of "units" of time since unix epoch. The units are based on the
    // timestamp resolution from the interface.
    uint32_t ts_res = 1e6;
    if ( pb.interface < interfaces.size() )
        ts_res = interfaces[pb.interface].ts_resolution;
    pb.ts_tval.tv_sec = ts / ts_res;
    pb.ts_tval.tv_usec = ((ts % ts_res) * 1e6) / ts_res;

    pb.caplen = lepb->capture_packet_length;
    pb.origlen = lepb->original_capture_length;
    pb.data = lepb->packet_data;

    light_option opt = light_find_option(block, LIGHT_OPTION_EPB_DROPCOUNT);
    if ( opt )
        pb.dropcount = pcapng_extract_uint64(opt->data, opt->length);

    return pb;
}

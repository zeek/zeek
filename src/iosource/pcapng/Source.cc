// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/pcapng/Source.h"

#include <cstdio>

#include "zeek/Event.h"

#include "light_pcapng.h"

using namespace zeek::iosource;
using namespace zeek::iosource::pcapng;

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

    parser = std::make_unique<Parser>();

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

    parser->CleanupLastBlock();

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
    Parser::BlockStatus status = Parser::OK;
    while ( status == Parser::OK ) {
        bool endian_swap = false;
        light_read_block(pd, &block, &endian_swap);
        if ( ! block ) {
            // If we get a nullptr back, we've run out of blocks and the file is done.
            Close();
            return false;
        }

        status = parser->ParseBlock(block);
    }

    if ( status == Parser::BAD_PACKET )
        return false;

    auto pkt_block = parser->GetCurrentPacket();

    if ( current_interface_index == -1 || pkt_block.interface != static_cast<uint32_t>(current_interface_index) ) {
        current_interface_index = pkt_block.interface;
        current_interface_name = parser->GetInterfaceName(pkt_block.interface);
    }

    pkt->Init(parser->GetLinkType(pkt_block.interface), &pkt_block.ts_tval, pkt_block.caplen, pkt_block.origlen,
              pkt_block.data);

    ++stats.received;
    stats.dropped += pkt_block.dropcount;
    stats.bytes_received += pkt_block.origlen;

    return true;
}

void Source::DoneWithPacket() { parser->CleanupLastBlock(); }

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

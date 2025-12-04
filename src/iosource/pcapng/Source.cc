// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/pcapng/Source.h"

#include <cstdio>

#include "zeek/iosource/Packet.h"

#include "light_pcapng_ext.h"

#include "zeek/3rdparty/doctest.h"

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
    if ( pd = light_pcapng_open(props.path.c_str(), "rb"); ! pd ) {
        Error(util::fmt("unable to open %s: %s", props.path.c_str(), strerror(errno)));
        return;
    }

    // We don't register the file descriptor if we're in offline mode,
    // because libpcap's file descriptor for trace files isn't a reliable
    // way to know whether we actually have data to read.
    // See https://github.com/the-tcpdump-group/libpcap/issues/870
    props.selectable_fd = -1;

    props.link_type = -1;
    props.is_live = false;

    Opened(props);
}

void Source::Close() {
    if ( ! pd )
        return;

    light_pcapng_close(pd);
    pd = nullptr;

    Closed();
}

bool Source::ExtractNextPacket(Packet* pkt) {
    if ( ! pd )
        return false;

    const u_char* data;
    light_packet_interface intf = {0};
    light_packet_header header;

    int res = light_read_packet(pd, &intf, &header, &data);

    switch ( res ) {
        case 0:
            // Exhausted pcap file, no more packets to read.
            Close();
            return false;
        case 1:
            // Read a packet without problem.
            // Although, some libpcaps may claim to have read a packet, but either did
            // not really read a packet or at least provide no way to access its
            // contents, so the following check for null-data helps handle those cases.
            if ( ! data ) {
                reporter->Weird("pcap_null_data_packet");
                return false;
            }
            break;
        default: reporter->InternalError("unhandled light_read_packet return value: %d", res); return false;
    }

    struct timeval tv{header.timestamp.tv_sec, static_cast<int>(header.timestamp.tv_nsec / 1000)};

    pkt->Init(intf.link_type, &tv, header.captured_length, header.original_length, data);

    if ( header.original_length == 0 || header.captured_length == 0 ) {
        Weird("empty_pcap_header", pkt);
        return false;
    }

    ++stats.received;
    stats.bytes_received += header.original_length;

    return true;
}

void Source::DoneWithPacket() {
    // Nothing to do.
}

// Given two pcap_stat structures, compute the difference of linked and dropped
// and add it to the given Stats object.
static void update_pktsrc_stats(zeek::iosource::PktSrc::Stats* stats, const struct pcap_stat* now,
                                const struct pcap_stat* prev) {
    decltype(now->ps_drop) ps_drop_diff = 0;
    decltype(now->ps_recv) ps_recv_diff = 0;

    // This is subtraction of unsigned ints: It's not undefined
    // and results in modulo arithmetic.
    ps_recv_diff = now->ps_recv - prev->ps_recv;
    ps_drop_diff = now->ps_drop - prev->ps_drop;

    stats->link += ps_recv_diff;
    stats->dropped += ps_drop_diff;
}

void Source::Statistics(Stats* s) {
    // char errbuf[PCAP_ERRBUF_SIZE];

    // if ( ! (props.is_live && pd) )
    //     s->received = s->dropped = s->link = s->bytes_received = 0;

    // else {
    //     struct pcap_stat pstat;
    //     if ( pcap_stats(pd, &pstat) < 0 ) {
    //         PcapError();
    //         s->received = s->dropped = s->link = s->bytes_received = 0;
    //     }

    //     else {
    //         update_pktsrc_stats(&stats, &pstat, &prev_pstat);
    //         prev_pstat = pstat;
    //     }
    // }

    // s->link = stats.link;
    // s->dropped = stats.dropped;
    // s->received = stats.received;
    // s->bytes_received = stats.bytes_received;

    // if ( ! props.is_live )
    //     s->dropped = 0;
}

detail::BPF_Program* Source::CompileFilter(const std::string& filter) {
    auto code = std::make_unique<detail::BPF_Program>();
    return code.release();
}


PktSrc* Source::Instantiate(const std::string& path, bool is_live) { return new Source(path); }

TEST_CASE("pcap source update_pktsrc_stats") {
    PktSrc::Stats stats;
    struct pcap_stat now = {0};
    struct pcap_stat prev = {0};

    SUBCASE("all zero") {
        update_pktsrc_stats(&stats, &now, &prev);
        CHECK(stats.link == 0);
        CHECK(stats.dropped == 0);
    }

    SUBCASE("no overflow") {
        now.ps_recv = 7;
        now.ps_drop = 3;
        update_pktsrc_stats(&stats, &now, &prev);
        CHECK(stats.link == 7);
        CHECK(stats.dropped == 3);
    }

    SUBCASE("no overflow prev") {
        stats.link = 2;
        stats.dropped = 1;
        prev.ps_recv = 2;
        prev.ps_drop = 1;
        now.ps_recv = 7;
        now.ps_drop = 3;

        update_pktsrc_stats(&stats, &now, &prev);
        CHECK(stats.link == 7);
        CHECK(stats.dropped == 3);
    }

    SUBCASE("overflow") {
        prev.ps_recv = 4294967295;
        prev.ps_drop = 4294967294;
        now.ps_recv = 0;
        now.ps_drop = 1;

        update_pktsrc_stats(&stats, &now, &prev);
        CHECK(stats.link == 1);
        CHECK(stats.dropped == 3);
    }

    SUBCASE("overflow 2") {
        stats.link = 4294967295;
        stats.dropped = 4294967294;
        prev.ps_recv = 4294967295;
        prev.ps_drop = 4294967294;
        now.ps_recv = 10;
        now.ps_drop = 3;

        update_pktsrc_stats(&stats, &now, &prev);
        CHECK(stats.link == 4294967306);    // 2**32 - 1 + 11
        CHECK(stats.dropped == 4294967299); // 2**32 - 2 + 5
    }
}

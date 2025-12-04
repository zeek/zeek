// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/pcapng/Source.h"

#include <cmath>
#include <cstdio>

#include "zeek/Event.h"
#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"

#include "light_pcapng.h"
#include "light_special.h"

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
    val |= pcapng_extract_uint32(opt_data + 2, opt_length);
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

    if ( pcapng_file_info ) {
        // A pcapng file must start with a section header block which will contain all of the
        // file info.
        light_block sh_block = nullptr;
        bool endian_swap = false;
        light_read_block(pd, &sh_block, &endian_swap);
        if ( ! sh_block || sh_block->type != LIGHT_SECTION_HEADER_BLOCK ) {
            // This shouldn't be possible, since we're checking the magic number before
            // calling this packet source, but sanity check it anyways.
            light_io_close(pd);
            return;
        }

        ParseSectionHeaderBlock(sh_block);
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
    while ( true ) {
        bool endian_swap = false;
        light_read_block(pd, &block, &endian_swap);

        // If we didn't a block, either we ran out of data or there was an error. Either way
        // exit processing.
        if ( ! block ) {
            Close();
            return false;
        }

        if ( block->type == LIGHT_ENHANCED_PACKET_BLOCK )
            break;
        else if ( block->type == LIGHT_SIMPLE_PACKET_BLOCK ) {
            // Report a weird for simple packet blocks instead of dropping them, for
            // documentation reasons. We don't want to parse simple packet blocks because
            // they don't contain timestamp information. Without it, there's not much we
            // can do with them.
            reporter->Weird("pcapng_simple_packet_block");
        }
        else if ( block->type == LIGHT_INTERFACE_BLOCK ) {
            // parse interface block and send event
            ParseInterfaceBlock(block);
        }
        else if ( block->type == LIGHT_SECTION_HEADER_BLOCK ) {
            ParseSectionHeaderBlock(block);
        }
    }

    if ( block->type == LIGHT_ENHANCED_PACKET_BLOCK ) {
        PacketBlock pkt_block = ParseEnhancedPacketBlock(block);

        if ( pkt_block.caplen == 0 || pkt_block.origlen == 0 ) {
            reporter->Weird("empty_pcapng_header");
            light_free_block(block);
            return false;
        }

        if ( pkt_block.interface >= interfaces.size() ) {
            reporter->Weird("pcapng_invalid_interface_number", util::fmt("%d", pkt_block.interface));
            light_free_block(block);
            return false;
        }

        pkt->Init(interfaces[pkt_block.interface].link_type, &pkt_block.ts_tval, pkt_block.caplen, pkt_block.origlen,
                  pkt_block.data);

        ++stats.received;
        stats.dropped += pkt_block.dropcount;
        stats.bytes_received += pkt_block.origlen;

        current_block = block;
    }

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

void Source::ParseSectionHeaderBlock(light_block block) {
    if ( pcapng_file_info ) {
        // Use the struct defined by Light to avoid some parsing.
        auto lsh = reinterpret_cast<_light_section_header*>(block->body);

        // Skip over the byte-order magic number and pull the major and minor version as
        // 16-bit values. We're ok to skip this because we already verified the magic
        // number by selecting the packet source in the first place.

        static auto file_info = id::find_type<RecordType>("Pcapng::FileInfo");
        auto rec = make_intrusive<RecordVal>(file_info);
        VectorValPtr comments;

        rec->Assign(0, make_intrusive<StringVal>(util::fmt("%d.%d", lsh->major_version, lsh->minor_version)));

        light_option opt = block->options;
        while ( opt ) {
            switch ( opt->code ) {
                case LIGHT_OPTION_COMMENT:
                    if ( ! comments )
                        comments = make_intrusive<VectorVal>(id::string_vec);
                    comments->Append(
                        make_intrusive<StringVal>(std::string_view{reinterpret_cast<char*>(opt->data), opt->length}));
                    break;
                case LIGHT_OPTION_SHB_HARDWARE:
                    rec->Assign(2, make_intrusive<StringVal>(
                                       std::string_view{reinterpret_cast<char*>(opt->data), opt->length}));
                    break;
                case LIGHT_OPTION_SHB_OS:
                    rec->Assign(3, make_intrusive<StringVal>(
                                       std::string_view{reinterpret_cast<char*>(opt->data), opt->length}));
                    break;
                case LIGHT_OPTION_SHB_APP:
                    rec->Assign(4, make_intrusive<StringVal>(
                                       std::string_view{reinterpret_cast<char*>(opt->data), opt->length}));
                    break;
                default: break;
            }

            opt = opt->next_option;
        }

        if ( comments )
            rec->Assign(1, comments);

        event_mgr.Enqueue(pcapng_file_info, rec);
    }
}

void Source::ParseInterfaceBlock(light_block block) {
    // Use the struct defined by Light to avoid some parsing.
    auto lidb = reinterpret_cast<_light_interface_description_block*>(block->body);

    Interface intf;
    intf.link_type = lidb->link_type;
    intf.snaplen = lidb->snapshot_length;

    // TODO: We parse all of the options because we keep all of them in the vector. The
    // only option we really care about from packet-to-packet is the timestamp resolution
    // though, so maybe we don't need to store everything?
    light_option opt = block->options;
    while ( opt ) {
        switch ( opt->code ) {
            case PCAPNG_OPT_IF_NAME: intf.name = {reinterpret_cast<char*>(opt->data), opt->length}; break;
            case PCAPNG_OPT_IF_DESCRIPTION: intf.description = {reinterpret_cast<char*>(opt->data), opt->length}; break;
            case PCAPNG_OPT_IF_IPV4ADDR: {
                if ( ! validate_option_length(8, opt->length) )
                    break;

                // IPv4 addresses are 4 bytes with the IP address and 4 bytes with the netmask.
                std::string addr;
                char buf[INET_ADDRSTRLEN];
                if ( inet_ntop(AF_INET, opt->data, buf, sizeof(buf)) == nullptr )
                    break;

                addr = buf;

                if ( inet_ntop(AF_INET, opt->data + 4, buf, sizeof(buf)) == nullptr )
                    break;

                addr.append("/").append(buf);

                if ( ! intf.ipv4_addrs.has_value() )
                    intf.ipv4_addrs = std::vector<std::string>{};
                intf.ipv4_addrs->emplace_back(std::move(addr));
                break;
            }
            case PCAPNG_OPT_IF_IPV6ADDR: {
                if ( ! validate_option_length(17, opt->length) )
                    break;

                char buf[INET6_ADDRSTRLEN];
                if ( inet_ntop(AF_INET6, opt->data, buf, sizeof(buf)) != nullptr ) {
                    std::string addr = buf;
                    addr.append(util::fmt("/%d", opt->data[16]));

                    if ( ! intf.ipv6_addrs.has_value() )
                        intf.ipv6_addrs = std::vector<std::string>{};
                    intf.ipv6_addrs->emplace_back(std::move(addr));
                }
                break;
            }
            case PCAPNG_OPT_IF_MACADDR:
                if ( ! validate_option_length(6, opt->length) )
                    break;

                intf.mac_addr = util::fmt("%02x:%02x:%02x:%02x:%02x:%02x", opt->data[0], opt->data[1], opt->data[2],
                                          opt->data[3], opt->data[4], opt->data[5]);
                break;
            case PCAPNG_OPT_IF_EUIADDR:
                if ( ! validate_option_length(8, opt->length) )
                    break;

                intf.eui_addr =
                    util::fmt("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", opt->data[0], opt->data[1], opt->data[2],
                              opt->data[3], opt->data[4], opt->data[5], opt->data[6], opt->data[7]);
                break;
            case PCAPNG_OPT_IF_SPEED: intf.if_speed = pcapng_extract_uint64(opt->data, opt->length); break;
            case PCAPNG_OPT_IF_TSRESOL:
                if ( (opt->data[0] & 0x80) == 0x80 )
                    intf.ts_resolution = 2 << (opt->data[0] & 0x7F);
                else
                    intf.ts_resolution = static_cast<uint32_t>(pow(10, (opt->data[0] & 0x7f)));
                break;
            case PCAPNG_OPT_IF_TZONE:
                // This was replaced by iana_tzname below in later version of the file format.
                break;
            case PCAPNG_OPT_IF_FILTER: intf.filter = {reinterpret_cast<char*>(opt->data), opt->length}; break;
            case PCAPNG_OPT_IF_OS: intf.os = {reinterpret_cast<char*>(opt->data), opt->length}; break;
            case PCAPNG_OPT_IF_FCSLEN: intf.fcs_len = opt->data[0]; break;
            case PCAPNG_OPT_IF_TSOFFSET: intf.ts_offset = pcapng_extract_uint64(opt->data, opt->length); break;
            case PCAPNG_OPT_IF_HARDWARE: intf.hardware = {reinterpret_cast<char*>(opt->data), opt->length}; break;
            case PCAPNG_OPT_IF_TXSPEED: intf.tx_speed = pcapng_extract_uint64(opt->data, opt->length); break;
            case PCAPNG_OPT_IF_RXSPEED: intf.rx_speed = pcapng_extract_uint64(opt->data, opt->length); break;
            case PCAPNG_OPT_IF_IANA_TZNAME: intf.iana_tzname = {reinterpret_cast<char*>(opt->data), opt->length}; break;
            default: break;
        }

        opt = opt->next_option;
    }

    if ( pcapng_new_interface ) {
        static auto rec_type = id::find_type<RecordType>("Pcapng::Interface");
        auto rec = make_intrusive<RecordVal>(rec_type);

        rec->Assign(0, val_mgr->Count(intf.link_type));
        rec->Assign(1, val_mgr->Count(intf.snaplen));

        if ( intf.name )
            rec->Assign(2, make_intrusive<StringVal>(intf.name.value()));
        if ( intf.description )
            rec->Assign(3, make_intrusive<StringVal>(intf.description.value()));
        if ( intf.ipv4_addrs ) {
            auto vec = make_intrusive<VectorVal>(id::string_vec);
            for ( const auto& addr : intf.ipv4_addrs.value() )
                vec->Append(make_intrusive<StringVal>(addr));
            rec->Assign(4, vec);
        }
        if ( intf.ipv6_addrs ) {
            auto vec = make_intrusive<VectorVal>(id::string_vec);
            for ( const auto& addr : intf.ipv6_addrs.value() )
                vec->Append(make_intrusive<StringVal>(addr));
            rec->Assign(5, vec);
        }
        if ( intf.mac_addr )
            rec->Assign(6, make_intrusive<StringVal>(intf.mac_addr.value()));
        if ( intf.eui_addr )
            rec->Assign(7, make_intrusive<StringVal>(intf.eui_addr.value()));
        if ( intf.if_speed )
            rec->Assign(8, val_mgr->Count(intf.if_speed.value()));

        rec->Assign(9, val_mgr->Count(intf.ts_resolution));

        if ( intf.filter )
            rec->Assign(10, make_intrusive<StringVal>(intf.filter.value()));
        if ( intf.os )
            rec->Assign(11, make_intrusive<StringVal>(intf.os.value()));
        if ( intf.fcs_len )
            rec->Assign(12, val_mgr->Count(intf.fcs_len.value()));
        if ( intf.ts_offset )
            rec->Assign(13, val_mgr->Count(intf.ts_offset.value()));
        if ( intf.hardware )
            rec->Assign(14, make_intrusive<StringVal>(intf.hardware.value()));
        if ( intf.tx_speed )
            rec->Assign(15, val_mgr->Count(intf.tx_speed.value()));
        if ( intf.rx_speed )
            rec->Assign(16, val_mgr->Count(intf.rx_speed.value()));
        if ( intf.iana_tzname )
            rec->Assign(17, make_intrusive<StringVal>(intf.iana_tzname.value()));

        event_mgr.Enqueue(pcapng_new_interface, rec);
    }

    interfaces.emplace_back(std::move(intf));
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

    // TODO: Should we bother parsing any of these options if we're not sending the event? I could see
    // the dropcount option being important outside of sending an event if we want to extract that one
    // separately. If we only want to parse them for events, then a bunch of fields in the PacketBlock
    // structure can go away.
    light_option opt = block->options;
    if ( opt && pcapng_packet_options ) {
        while ( opt ) {
            switch ( opt->code ) {
                case LIGHT_OPTION_COMMENT: {
                    if ( ! pb.comments.has_value() )
                        pb.comments = std::vector<std::string>{};
                    pb.comments->emplace_back(reinterpret_cast<char*>(opt->data), opt->length);
                    break;
                }
                case PCAPNG_OPT_EPB_FLAGS: pb.flags = pcapng_extract_uint32(opt->data, opt->length); break;
                case PCAPNG_OPT_EPB_HASH: {
                    std::string hashstr;
                    // expected lengths here include the one byte for the option type.
                    uint16_t expected_length = UINT16_MAX;
                    switch ( opt->data[0] ) {
                        case 0: hashstr = "2scomp:"; break;
                        case 1: hashstr = "xor:"; break;
                        case 2:
                            hashstr = "crc32:";
                            expected_length = 5;
                            break;
                        case 3:
                            hashstr = "md5:";
                            expected_length = 17;
                            break;
                        case 4:
                            hashstr = "sha-1:";
                            expected_length = 21;
                            break;
                        case 5:
                            hashstr = "toeplitz:";
                            expected_length = 5;
                            break;
                        default: hashstr = "unknown:"; break;
                    }

                    if ( ! validate_option_length(expected_length, opt->length) )
                        break;

                    for ( size_t i = 1; i < opt->length; i++ )
                        hashstr.append(util::fmt("%02x", opt->data[i]));

                    if ( ! pb.hashes.has_value() )
                        pb.hashes = std::vector<std::string>{};
                    pb.hashes->emplace_back(std::move(hashstr));
                    break;
                }
                case PCAPNG_OPT_EPB_DROPCOUNT: pb.dropcount = pcapng_extract_uint64(opt->data, opt->length); break;
                case PCAPNG_OPT_EPB_PACKETID: pb.packet_id = pcapng_extract_uint64(opt->data, opt->length); break;
                case PCAPNG_OPT_EPB_QUEUE: pb.queue = pcapng_extract_uint32(opt->data, opt->length); break;
                case PCAPNG_OPT_EPB_VERDICT: {
                    if ( ! pb.verdicts.has_value() )
                        pb.verdicts = std::vector<std::string>{};

                    switch ( opt->data[0] ) {
                        case 0: {
                            std::string verdict = "hardware:";
                            verdict.append({reinterpret_cast<char*>(opt->data), opt->length});
                            pb.verdicts->emplace_back(std::move(verdict));
                            break;
                        }
                        case 1: {
                            if ( ! validate_option_length(9, opt->length) )
                                break;

                            uint64_t val = pcapng_extract_uint64(opt->data + 1, opt->length - 1);
                            switch ( val ) {
                                case 0: pb.verdicts->emplace_back("Linux_eBPF_TC:OK"); break;
                                case 1: pb.verdicts->emplace_back("Linux_eBPF_TC:RECLASSIFY"); break;
                                case 2: pb.verdicts->emplace_back("Linux_eBPF_TC:SHOT"); break;
                                case 3: pb.verdicts->emplace_back("Linux_eBPF_TC:PIPE"); break;
                                case 4: pb.verdicts->emplace_back("Linux_eBPF_TC:STOLEN"); break;
                                case 5: pb.verdicts->emplace_back("Linux_eBPF_TC:QUEUED"); break;
                                case 6: pb.verdicts->emplace_back("Linux_eBPF_TC:REPEAT"); break;
                                case 7: pb.verdicts->emplace_back("Linux_eBPF_TC:REDIRECT"); break;
                                case 8: pb.verdicts->emplace_back("Linux_eBPF_TC:TRAP"); break;
                                default:
                                    pb.verdicts->emplace_back(util::fmt("Linux_eBPF_TC:unknown(%" PRIu64 ")", val));
                            }
                            break;
                        }
                        case 2: {
                            if ( ! validate_option_length(9, opt->length) )
                                break;

                            uint64_t val = pcapng_extract_uint64(opt->data + 1, opt->length - 1);
                            switch ( val ) {
                                case 0: pb.verdicts->emplace_back("Linux_eBPF_XDP:ABORTED"); break;
                                case 1: pb.verdicts->emplace_back("Linux_eBPF_XDP:DROP"); break;
                                case 2: pb.verdicts->emplace_back("Linux_eBPF_XDP:PASS"); break;
                                case 3: pb.verdicts->emplace_back("Linux_eBPF_XDP:TX"); break;
                                case 4: pb.verdicts->emplace_back("Linux_eBPF_XDP:REDIRECT"); break;
                                default:
                                    pb.verdicts->emplace_back(util::fmt("Linux_eBPF_XDP:unknown(%" PRIu64 ")", val));
                            }
                            break;
                        }
                        default: pb.verdicts->emplace_back(util::fmt("unknown_type(%d)", opt->data[0])); break;
                    }
                    break;
                }
                case PCAPNG_OPT_EPB_PROCESSID_THREADID: {
                    uint64_t pidtid = pcapng_extract_uint64(opt->data, opt->length);
                    uint32_t pid = pidtid >> 32;
                    uint32_t tid = pidtid & 0xFFFFFFFF;
                    pb.processid_threadid = util::fmt("%d-%d", pid, tid);
                    break;
                }
                default: break;
            }

            opt = opt->next_option;
        }

        static auto rec_type = id::find_type<RecordType>("Pcapng::PacketOptions");
        auto rec = make_intrusive<RecordVal>(rec_type);

        if ( pb.comments ) {
            auto vec = make_intrusive<VectorVal>(id::string_vec);
            for ( const auto& comment : pb.comments.value() )
                vec->Append(make_intrusive<StringVal>(comment));
            rec->Assign(0, vec);
        }
        if ( pb.flags )
            rec->Assign(1, val_mgr->Count(pb.flags.value()));
        if ( pb.hashes ) {
            auto vec = make_intrusive<VectorVal>(id::string_vec);
            for ( const auto& hash : pb.hashes.value() )
                vec->Append(make_intrusive<StringVal>(hash));
            rec->Assign(2, vec);
        }
        rec->Assign(3, pb.dropcount);
        if ( pb.packet_id )
            rec->Assign(4, val_mgr->Count(pb.packet_id.value()));
        if ( pb.queue )
            rec->Assign(5, val_mgr->Count(pb.queue.value()));
        if ( pb.verdicts ) {
            auto vec = make_intrusive<VectorVal>(id::string_vec);
            for ( const auto& verdict : pb.verdicts.value() )
                vec->Append(make_intrusive<StringVal>(verdict));
            rec->Assign(6, vec);
        }
        if ( pb.processid_threadid )
            rec->Assign(7, make_intrusive<StringVal>(pb.processid_threadid.value()));

        event_mgr.Enqueue(pcapng_packet_options,
                          make_intrusive<TimeVal>(pb.ts_tval.tv_sec + static_cast<double>(pb.ts_tval.tv_usec) / 1e6),
                          rec);
    }

    return pb;
}

PktSrc* Source::Instantiate(const std::string& path, bool is_live) { return new Source(path); }

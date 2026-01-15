// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/iosource/pcapng/Parser.h"

#include <sys/socket.h>
#include <cinttypes>
#include <cmath>

#include "zeek/Reporter.h"
#include "zeek/Type.h"
#include "zeek/Val.h"

#include "light_pcapng.h"
#include "light_special.h"

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

Parser::BlockStatus Parser::ParseBlock(light_block block) {
    if ( block->type == LIGHT_INTERFACE_BLOCK )
        ParseInterfaceBlock(block);
    else if ( block->type == LIGHT_ENHANCED_PACKET_BLOCK ) {
        current_packet = ParseEnhancedPacketBlock(block);

        if ( current_packet.caplen == 0 || current_packet.origlen == 0 ) {
            reporter->Weird("empty_pcapng_header");
            light_free_block(block);
            return BAD_PACKET;
        }

        if ( current_packet.interface >= interfaces.size() ) {
            reporter->Weird("pcapng_invalid_interface_number", util::fmt("%d", current_packet.interface));
            light_free_block(block);
            return BAD_PACKET;
        }

        current_block = block;

        return PACKET_BLOCK;
    }

    return OK;
}

void Parser::ParseInterfaceBlock(light_block block) {
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
            case LIGHT_OPTION_IF_NAME: intf.name = {reinterpret_cast<char*>(opt->data), opt->length}; break;
            case LIGHT_OPTION_IF_DESCRIPTION:
                intf.description = {reinterpret_cast<char*>(opt->data), opt->length};
                break;
            case LIGHT_OPTION_IF_IPV4ADDR: {
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
            case LIGHT_OPTION_IF_IPV6ADDR: {
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
            case LIGHT_OPTION_IF_MACADDR:
                if ( ! validate_option_length(6, opt->length) )
                    break;

                intf.mac_addr = util::fmt("%02x:%02x:%02x:%02x:%02x:%02x", opt->data[0], opt->data[1], opt->data[2],
                                          opt->data[3], opt->data[4], opt->data[5]);
                break;
            case LIGHT_OPTION_IF_EUIADDR:
                if ( ! validate_option_length(8, opt->length) )
                    break;

                intf.eui_addr =
                    util::fmt("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", opt->data[0], opt->data[1], opt->data[2],
                              opt->data[3], opt->data[4], opt->data[5], opt->data[6], opt->data[7]);
                break;
            case LIGHT_OPTION_IF_SPEED: intf.if_speed = pcapng_extract_uint64(opt->data, opt->length); break;
            case LIGHT_OPTION_IF_TSRESOL:
                if ( (opt->data[0] & 0x80) == 0x80 )
                    intf.ts_resolution = 2 << (opt->data[0] & 0x7F);
                else
                    intf.ts_resolution = static_cast<uint32_t>(pow(10, (opt->data[0] & 0x7f)));
                break;
            case LIGHT_OPTION_IF_TZONE:
                // This was replaced by iana_tzname below in later version of the file format.
                break;
            case LIGHT_OPTION_IF_FILTER: intf.filter = {reinterpret_cast<char*>(opt->data), opt->length}; break;
            case LIGHT_OPTION_IF_OS: intf.os = {reinterpret_cast<char*>(opt->data), opt->length}; break;
            case LIGHT_OPTION_IF_FCSLEN: intf.fcs_len = opt->data[0]; break;
            case LIGHT_OPTION_IF_TSOFFSET: intf.ts_offset = pcapng_extract_uint64(opt->data, opt->length); break;
            case LIGHT_OPTION_IF_HARDWARE: intf.hardware = {reinterpret_cast<char*>(opt->data), opt->length}; break;
            case LIGHT_OPTION_IF_TXSPEED: intf.tx_speed = pcapng_extract_uint64(opt->data, opt->length); break;
            case LIGHT_OPTION_IF_RXSPEED: intf.rx_speed = pcapng_extract_uint64(opt->data, opt->length); break;
            case LIGHT_OPTION_IF_IANA_TZNAME:
                intf.iana_tzname = {reinterpret_cast<char*>(opt->data), opt->length};
                break;
            default: break;
        }

        opt = opt->next_option;
    }

    interfaces.emplace_back(std::move(intf));
}

Parser::PacketBlock Parser::ParseEnhancedPacketBlock(light_block block) {
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

    light_option opt = block->options;
    while ( opt ) {
        switch ( opt->code ) {
            case LIGHT_OPTION_COMMENT: {
                if ( ! pb.comments.has_value() )
                    pb.comments = std::vector<std::string>{};
                pb.comments->emplace_back(reinterpret_cast<char*>(opt->data), opt->length);
                break;
            }
            case LIGHT_OPTION_EPB_FLAGS: pb.flags = pcapng_extract_uint32(opt->data, opt->length); break;
            case LIGHT_OPTION_EPB_HASH: {
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
            case LIGHT_OPTION_EPB_DROPCOUNT: pb.dropcount = pcapng_extract_uint64(opt->data, opt->length); break;
            case LIGHT_OPTION_EPB_PACKETID: pb.packet_id = pcapng_extract_uint64(opt->data, opt->length); break;
            case LIGHT_OPTION_EPB_QUEUE: pb.queue = pcapng_extract_uint32(opt->data, opt->length); break;
            case LIGHT_OPTION_EPB_VERDICT: {
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
                            default: pb.verdicts->emplace_back(util::fmt("Linux_eBPF_TC:unknown(%" PRIu64 ")", val));
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
                            default: pb.verdicts->emplace_back(util::fmt("Linux_eBPF_XDP:unknown(%" PRIu64 ")", val));
                        }
                        break;
                    }
                    default: pb.verdicts->emplace_back(util::fmt("unknown_type(%d)", opt->data[0])); break;
                }
                break;
            }
            case LIGHT_OPTION_EPB_PID_TID: {
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

    return pb;
}

void Parser::CleanupLastBlock() {
    if ( current_block ) {
        light_free_block(current_block);
        current_block = nullptr;
    }
}

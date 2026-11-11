// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/packet_analysis/protocol/l2tp/L2TP.h"

#include <algorithm>

#include "zeek/net_util.h"

using namespace zeek::packet_analysis::L2TP;

detail::V3SessionTimer::V3SessionTimer(L2TPAnalyzer* analyzer, double t)
    : zeek::detail::Timer(t, zeek::detail::TIMER_L2TP_V3_SESSION_EXPIRE), analyzer(analyzer) {}

detail::V3SessionTimer::~V3SessionTimer() {
    if ( analyzer->v3_session_timer == this )
        analyzer->v3_session_timer = nullptr;
}

void detail::V3SessionTimer::Dispatch(double t, bool do_expire) {
    // The manager has already removed this timer and will delete it after we
    // return, so the analyzer no longer has a pending timer. Drop the reference
    // up front so ExpireV3Sessions() can arm a fresh one when sessions remain.
    analyzer->v3_session_timer = nullptr;
    analyzer->ExpireV3Sessions(do_expire);
}


L2TPAnalyzer::L2TPAnalyzer() : zeek::packet_analysis::Analyzer("L2TP") {
    v3_session_max_age = zeek::id::find_val("PacketAnalyzer::L2TP::v3_session_max_age")->AsDouble();
    v3_state_timer_interval = zeek::id::find_val("PacketAnalyzer::L2TP::v3_state_timer_interval")->AsDouble();
    v3_max_sessions = zeek::id::find_val("PacketAnalyzer::L2TP::v3_max_sessions")->AsCount();
}

L2TPAnalyzer::~L2TPAnalyzer() {
    if ( zeek::detail::timer_mgr && v3_session_timer )
        zeek::detail::timer_mgr->Cancel(v3_session_timer);
}

bool L2TPAnalyzer::AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) {
    FlagsAndVersion flags;

    // L2TP can arrive via either IP or UDP, and what version we get and how the packets
    // are formed depends on where we get them from. v2 will only ever arrive via UDP,
    // where v3 can arrive via both. v2/v3 over UDP start with the same flags field, but
    // v3 over IP is slightly different.

    if ( packet->session == nullptr ) {
        // If received via IP, check whether the first 4 bytes are zeroes. This will be a
        // control packet with flags to parse. otherwise it's a data packet and has no
        // flags.
        if ( len < 4 ) {
            Weird("l2tp_header_truncated");
            return false;
        }

        cur_v3_session_id = extract_uint32(data);
        data += 4;
        len -= 4;

        if ( cur_v3_session_id == 0 ) {
            // A v3 control packet must be at least 16 bytes based on the required flags.
            if ( len < 12 ) {
                Weird("l2tp_header_truncated");
                return false;
            }

            ExtractFlags(flags, data);

            if ( flags.version != 3 ) {
                Weird("l2tp_invalid_version_over_ip", packet, util::fmt("%d", flags.version));
                return false;
            }

            return ParseControl(flags, data, len, packet);
        }
        else {
            flags.from_ip = true;
            return ParseV3Data(flags, data, len, packet);
        }
    }
    else {
        // If received via UDP, the packet always starts with a set of flags (2 bytes) for
        // both versions.
        if ( len < 2 ) {
            Weird("l2tp_header_truncated");
            return false;
        }

        ExtractFlags(flags, data);

        if ( flags.control )
            return ParseControl(flags, data, len, packet);

        if ( flags.version == 2 )
            return ParseV2Data(flags, data, len, packet);

        return ParseV3Data(flags, data, len, packet);
    }
}

void L2TPAnalyzer::ExtractFlags(FlagsAndVersion& flags, const uint8_t* data) {
    flags.control = (data[0] & 0x80) != 0;
    flags.length = (data[0] & 0x40) != 0;
    flags.sequence = (data[0] & 0x08) != 0;
    flags.version = data[1] & 0x0F;

    // These two are only valid for v2. They're not present in v3.
    if ( flags.version == 2 ) {
        flags.offset = (data[0] & 0x02) != 0;
        flags.priority = (data[0] & 0x01) != 0;
    }
}

bool L2TPAnalyzer::ParseControl(const FlagsAndVersion& flags, const uint8_t* data, size_t len, Packet* packet) {
    // The length of a control packet must be at least 12 bytes based on the above flags.
    if ( len < 12 ) {
        Weird("l2tp_header_truncated");
        return false;
    }

    // validate flags that must be set for control packets.
    if ( ! flags.length ) {
        Weird("l2tp_control_no_l_bit");
        return false;
    }
    else if ( ! flags.sequence ) {
        Weird("l2tp_control_no_s_bit");
        return false;
    }

    if ( flags.version == 2 ) {
        if ( flags.offset ) {
            Weird("l2tp_control_o_bit");
            return false;
        }
        else if ( flags.priority ) {
            Weird("l2tp_control_p_bit");
            return false;
        }
    }

    // Length if the full size of the message including the header.
    uint16_t msg_len = extract_uint16(data + 2);

    if ( msg_len != len ) {
        Weird("l2tp_invalid_length", nullptr, util::fmt("%d < %zu", msg_len, len - 2));
        return false;
    }

    // Next up are tunnel/session IDs (v2) or conn id (v3) and the two sequence number
    // fields. We don't use them for anything so just skip over them.
    data += 12;
    len -= 12;
    msg_len -= 12;

    bool is_icrp = false;
    bool is_cdn = false;

    // A map containing all of the AVPs, indexed by a vendor id/avp type pair, storing
    // the length and at most the first 8 bytes of the value. An AVP can be up to 1023
    // bytes total including the header, but we're not going to keep all of it.
    std::map<std::pair<uint16_t, uint16_t>, std::pair<uint16_t, uint64_t>> avps;

    while ( msg_len >= 2 ) {
        uint16_t avp_len = data[0] & 0x03;
        avp_len <<= 8;
        avp_len |= data[1];

        if ( (avp_len < 6) || (avp_len > msg_len) ) {
            Weird("l2tp_invalid_avp_length");
            return false;
        }

        uint16_t vendor_id = extract_uint16(data + 2);
        uint16_t avp_type = extract_uint16(data + 4);
        data += 6;
        avp_len -= 6;
        msg_len -= 6;

        if ( avp_len == 0 )
            continue;

        uint64_t avp_value = 0;
        if ( avp_len == 1 )
            avp_value = data[0];
        else if ( avp_len == 2 )
            avp_value = extract_uint16(data);
        else if ( avp_len == 4 )
            avp_value = extract_uint32(data);
        else
            // TODO: this reads in host byte order, which might be weird if we log it as
            // as a byte string.
            memcpy(&avp_value, data, std::min<size_t>(8, avp_len));

        if ( avp_type == 0 ) {
            if ( avp_value == 11 )
                is_icrp = true;
            else if ( avp_value == 14 )
                is_cdn = true;
        }

        avps.insert({{vendor_id, avp_type}, {avp_len + 6, avp_value}});

        data += avp_len;
        msg_len -= avp_len;
    }

    // TODO: send all of the AVPs in an event

    if ( flags.version == 3 ) {
        if ( is_icrp ) {
            // This is an Incoming Call Reply control packet, which contains both session IDs
            // and the rest of the necessary state entries.
            V3SessionState state;
            uint32_t local_session_id = 0;
            uint32_t remote_session_id = 0;

            for ( const auto& [k, v] : avps ) {
                if ( k.first == 0 ) {
                    if ( k.second == 63 )
                        local_session_id = v.second;
                    else if ( k.second == 64 )
                        remote_session_id = v.second;
                    else if ( k.second == 65 ) {
                        // This is the length of the cookie, which is the full AVP length
                        // minus the header bits.
                        state.cookie_length = v.first - 6;
                        if ( state.cookie_length != 0 && state.cookie_length != 4 && state.cookie_length != 8 ) {
                            Weird("l2tp_cookie_length_invalid", nullptr, util::fmt("%d", state.cookie_length));
                            return false;
                        }
                    }
                    else if ( k.second == 68 )
                        state.psw_type = v.second;
                    else if ( k.second == 69 ) {
                        if ( v.second != 0 )
                            state.has_sublayer = true;
                    }
                }
            }

            state.last_used_time = run_state::network_time;

            if ( local_session_id != 0 )
                v3_session_state_map.insert_or_assign(local_session_id, state);
            if ( remote_session_id != 0 )
                v3_session_state_map.insert_or_assign(remote_session_id, state);

            if ( v3_max_sessions > 0 && v3_session_state_map.size() > v3_max_sessions ) {
                Weird("l2tp_max_v3_sessions_exceeded");
                return false;
            }

            if ( v3_session_state_map.size() <= 2 )
                InstallV3SessionTimer();
        }

        if ( is_cdn ) {
            // This is a Call Disconnect Notification control packet, which contains the two
            // local session IDs. It's sent at the end of connection so the sessions can be
            // torn down.
            for ( const auto& [k, v] : avps ) {
                if ( k.first == 0 ) {
                    if ( k.second == 63 || k.second == 64 )
                        v3_session_state_map.erase(v.second);
                }
            }

            if ( v3_session_state_map.empty() && v3_session_timer ) {
                zeek::detail::timer_mgr->Cancel(v3_session_timer);
                v3_session_timer = nullptr;
            }
        }
    }

    if ( packet->session )
        AnalyzerConfirmation(packet->session);

    return true;
}

bool L2TPAnalyzer::ParseV2Data(const FlagsAndVersion& flags, const uint8_t* data, size_t len, Packet* packet) {
    // The length of a data packet must be at least 6 bytes. This is the flags and
    // control/tunnel/session IDs. All other fields in the header are optional for data
    // packets.
    uint16_t header_size = 6;

    if ( flags.length )
        header_size += 2;
    if ( flags.sequence )
        header_size += 4;

    if ( len < header_size ) {
        Weird("l2tp_header_truncated");
        return false;
    }

    // Skip the flags
    data += 2;

    // The optional length field is the total message length in bytes including the size
    // of the header. This will be adjusted as the rest of the optional fields are parsed.
    uint16_t msg_len = 0;
    if ( flags.length ) {
        // optional msg_len field
        msg_len = extract_uint16(data);

        if ( msg_len != len ) {
            Weird("l2tp_invalid_length");
            return false;
        }

        data += 2;
    }

    // In v2 the next two fields are the tunnel and session IDs. We don't use them for
    // anything so skip them.
    data += 4;

    if ( flags.sequence ) {
        // We don't do anything with the sequence numbers, but need to skip them anyways.
        data += 4;
    }

    // Drop the headers we've parsed so far from the length so we can validate the offset
    // size below if needed.
    len -= header_size;

    if ( flags.offset ) {
        if ( len < 2 ) {
            Weird("l2tp_invalid_length");
            return false;
        }

        uint16_t offset_len = extract_uint16(data);
        if ( offset_len > len - 2 ) {
            Weird("l2tp_invalid_offset_size");
            return false;
        }

        // Skip over the offset size and the offset itself. This should put us right at
        // the start of the payload.
        data += offset_len + 2;
        len -= offset_len + 2;
    }

    // Confirm the protocol so it shows up in the services
    AnalyzerConfirmation(packet->session);

    // This shouldn't happen, but better to check than forward an empty packet.
    if ( len == 0 )
        return true;

    return ForwardPacket(len, data, packet);
}

bool L2TPAnalyzer::ParseV3Data(const FlagsAndVersion& flags, const uint8_t* data, size_t len, Packet* packet) {
    if ( ! flags.from_ip ) {
        // The length of a UDP packet has to be at least 8 bytes. This is the flags, 2
        // bytes of reserved data, and the session ID.
        if ( len < 8 ) {
            Weird("l2tp_header_truncated");
            return false;
        }

        // Skip the flags and the 2 bytes of reserved data
        data += 4;
        len -= 4;

        // This was already extracted for IP packets in AnalyzePacket().
        cur_v3_session_id = extract_uint32(data);
        data += 4;
        len -= 4;
    }

    auto it = v3_session_state_map.find(cur_v3_session_id);
    if ( it == v3_session_state_map.end() )
        return false;

    auto& state = it->second;
    state.last_used_time = run_state::network_time;

    if ( len < state.cookie_length ) {
        Weird("l2tp_header_truncated");
        return false;
    }

    data += state.cookie_length;
    len -= state.cookie_length;

    if ( state.has_sublayer ) {
        if ( len < 4 ) {
            Weird("l2tp_header_truncated");
            return false;
        }

        data += 4;
        len -= 4;
    }

    // Confirm the protocol so it shows up in the services
    AnalyzerConfirmation(packet->session);

    // This shouldn't happen, but better to check than forward an empty packet.
    if ( len == 0 )
        return true;

    return ForwardPacket(len, data, packet, state.psw_type);
}

void L2TPAnalyzer::ExpireV3Sessions(bool do_expire) {
    for ( auto it = v3_session_state_map.begin(); it != v3_session_state_map.end(); ) {
        if ( it->second.last_used_time + v3_session_max_age < run_state::network_time ) {
            Weird("l2tp_session_timed_out");
            it = v3_session_state_map.erase(it);
        }
        else
            ++it;
    }

    if ( ! v3_session_state_map.empty() && ! do_expire ) {
        InstallV3SessionTimer();
    }
}

void L2TPAnalyzer::InstallV3SessionTimer() {
    if ( ! v3_session_timer ) {
        v3_session_timer = new detail::V3SessionTimer(this, run_state::network_time + v3_state_timer_interval);
        zeek::detail::timer_mgr->Add(v3_session_timer);
    }
}

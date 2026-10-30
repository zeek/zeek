// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <unordered_map>

#include "zeek/Timer.h"
#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::L2TP {

class L2TPAnalyzer;

namespace detail {

class V3SessionTimer : public zeek::detail::Timer {
public:
    V3SessionTimer(L2TPAnalyzer* analyzer, double t);
    ~V3SessionTimer() override;

    void Dispatch(double t, bool is_expire) override;

private:
    L2TPAnalyzer* analyzer;
};

} // namespace detail

/**
 * Analyzer for the L2TP protocol. It only supports L2TPv2 at the moment, with
 * intentions to support V3 later. See https://www.rfc-editor.org/rfc/rfc2661.html for
 * more information about the protocol.
 */
class L2TPAnalyzer : public zeek::packet_analysis::Analyzer {
public:
    L2TPAnalyzer();
    ~L2TPAnalyzer() override;

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<L2TPAnalyzer>(); }

private:
    friend class detail::V3SessionTimer;

    struct FlagsAndVersion {
        bool control = false;
        bool length = false;
        bool sequence = false;
        bool offset = false;
        bool priority = false;
        uint8_t version = 0;
        bool from_ip = false;
    };

    struct V3SessionState {
        uint16_t psw_type = 0;
        uint16_t cookie_length = 0;
        bool has_sublayer = false;
        double last_used_time = 0;
    };

    void ExtractFlags(FlagsAndVersion& flags, const uint8_t* data);
    bool ParseControl(const FlagsAndVersion& flags, const uint8_t* data, size_t len, Packet* packet);
    bool ParseV2Data(const FlagsAndVersion& flags, const uint8_t* data, size_t len, Packet* packet);
    bool ParseV3Data(const FlagsAndVersion& flags, const uint8_t* data, size_t len, Packet* packet);

    void ExpireV3Sessions(bool do_expire);
    void InstallV3SessionTimer();

    double v3_state_timer_interval = 0;
    double v3_session_max_age = 0;
    uint64_t v3_max_sessions = 0;

    std::unordered_map<uint32_t, V3SessionState> v3_session_state_map;
    uint32_t cur_v3_session_id = 0;
    detail::V3SessionTimer* v3_session_timer = nullptr;
};

namespace detail {} // namespace detail

} // namespace zeek::packet_analysis::L2TP

// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <hilti/rt/types/stream.h>

#include <spicy/rt/driver.h>
#include <spicy/rt/parser.h>

#include "zeek/spicy/cookie.h"

namespace zeek::spicy::rt {

/** Parsing state for a packet. */
class PacketState : public ::spicy::rt::driver::ParsingState {
public:
    /**
     * Constructor.
     *
     * @param cookie cookie to associated with the packet
     */
    PacketState(Cookie cookie) : ParsingState(::spicy::rt::driver::ParsingType::Block), _cookie(std::move(cookie)) {}

    /** Returns the cookie pointer to use with the runtime library during analysis. */
    auto* cookie() { return &_cookie; }

    /** Returns the packet-specific cookie state associated with the endpoint. */
    auto& packet() {
        assert(_cookie.packet);
        return *_cookie.packet;
    }

    /**
     * Records a debug message pertaining to the specific file.
     *
     * @param msg message to record
     */
    void DebugMsg(const std::string& msg) { debug(msg); }

protected:
    // Overridden from driver::ParsingState.
    void debug(const std::string& msg) override;

private:
    Cookie _cookie;
};

/** A Spicy file analyzer. */
class PacketAnalyzer : public packet_analysis::Analyzer {
public:
    PacketAnalyzer(std::string name);
    virtual ~PacketAnalyzer();

    /** Records a debug message. */
    void DebugMsg(const std::string& msg) { _state.DebugMsg(msg); }

    static packet_analysis::AnalyzerPtr Instantiate(std::string name) {
        name = util::canonify_name(name);
        return std::make_shared<PacketAnalyzer>(name);
    }

protected:
    // Overridden from Zeek's packet analyzer.
    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

private:
    PacketState _state;
};

} // namespace zeek::spicy::rt

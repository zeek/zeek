// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <cstdint>
#include <functional>
#include <span>

#include "zeek/iosource/Packet.h"
#include "zeek/packet_analysis/Analyzer.h"

namespace zeek::packet_analysis::Geneve {

namespace detail {

/**
 * Callback for parse_options(), passing the individual option pieces.
 */
using Callback =
    std::function<void(uint16_t opt_class, bool opt_critical, uint8_t opt_type, std::span<const uint8_t> opt_data)>;

/**
 * Parse Geneve options from the header data.
 *
 * For each option, the given callback is invoked.
 *
 * @param data The data span to treat as a Geneve header.
 * @param cb The callback to invoke with each parsed option.
 */
void parse_options(std::span<const uint8_t> data, Callback cb);

} // namespace detail

class GeneveAnalyzer : public zeek::packet_analysis::Analyzer {
public:
    GeneveAnalyzer();

    bool AnalyzePacket(size_t len, const uint8_t* data, Packet* packet) override;

    static zeek::packet_analysis::AnalyzerPtr Instantiate() { return std::make_shared<GeneveAnalyzer>(); }
};

} // namespace zeek::packet_analysis::Geneve

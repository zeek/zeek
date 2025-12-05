// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/iosource/PktSrc.h"

struct light_pcapng_t;
using light_pcapng = struct light_pcapng_t*;

namespace zeek::iosource::pcapng {

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
    void Statistics(Stats* stats) override;

    bool PrecompileFilter(int index, const std::string& filter) override;
    bool SetFilter(int index) override;

private:
    void PcapngError(const char* where = nullptr);

    Properties props;
    Stats stats;

    light_pcapng pd;

    struct pcap_pkthdr current_hdr = {};
    int current_filter = 0;
    unsigned int num_discarded = 0;
};

} // namespace zeek::iosource::pcapng

// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <vector>

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
    bool SetFilter(int index) override { return true; }
    void Statistics(Stats* stats) override;

    detail::BPF_Program* CompileFilter(const std::string& filter) override;

private:
    void PcapngError(const char* where = nullptr);

    Properties props;
    Stats stats;

    light_pcapng pd;

    // Buffer provided to setvbuf() when reading from a PCAPNG file.
    std::vector<char> iobuf;
};

} // namespace zeek::iosource::pcapng

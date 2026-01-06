// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>
#include <string>

#include "zeek/iosource/PktSrc.h"
#include "zeek/iosource/pcapng/Parser.h"

struct light_file_t;
using light_file = struct light_file_t*;

namespace zeek::iosource::pcapng {

/**
 * A packet source for reading data in the pcapng file format. See
 * https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-05.html for more information
 * about the format of these files.
 */
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
    Properties props;
    Stats stats;
    std::unique_ptr<Parser> parser;

    light_file pd = nullptr;
};

} // namespace zeek::iosource::pcapng

// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <sys/types.h>
#include <fstream>

#include "zeek/input/ReaderBackend.h"

namespace zeek::input::reader::detail {

/**
 * Binary mode file reader.
 */
class Binary : public ReaderBackend {
public:
    explicit Binary(ReaderFrontend* frontend);
    ~Binary() override;

    static ReaderBackend* Instantiate(ReaderFrontend* frontend) { return new Binary(frontend); }

protected:
    bool DoInit(const ReaderInfo& info, int arg_num_fields, const threading::Field* const* fields) override;
    void DoClose() override;
    bool DoUpdate() override;
    bool DoHeartbeat(double network_time, double current_time) override;

private:
    bool OpenInput();
    bool CloseInput();
    std::streamsize GetChunk(char** chunk);
    int UpdateModificationTime();

    std::string fname;
    std::ifstream* in = nullptr;
    time_t mtime = 0;
    ino_t ino = 0;
    bool firstrun = true;

    // options set from the script-level.
    static std::streamsize chunk_size;
    std::string path_prefix;
};

} // namespace zeek::input::reader::detail

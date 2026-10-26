// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <zlib.h>

#include "zeek/analyzer/protocol/tcp/TCP.h"

namespace zeek::analyzer::zip {

class ZIP_Analyzer final : public analyzer::tcp::TCP_SupportAnalyzer {
public:
    enum Method : uint8_t { GZIP, DEFLATE };

    ZIP_Analyzer(Connection* conn, bool orig, Method method = GZIP) : ZIP_Analyzer(conn, 0, orig, method) {}
    ZIP_Analyzer(Connection* conn, uint64_t max_uncompressed_size, bool orig, Method method = GZIP);
    ~ZIP_Analyzer() override;

    void Done() override;

    void DeliverStream(int len, const u_char* data, bool orig) override;

protected:
    bool ForwardDecompressed(uint64_t len, const Bytef* data);

    enum : uint8_t { NONE, ZIP_OK, ZIP_FAIL };
    z_stream* zip;
    int zip_status;
    Method method;
    uint64_t max_uncompressed_size;
    uint64_t uncompressed_size = 0;
    bool limit_exceeded = false;
};

} // namespace zeek::analyzer::zip

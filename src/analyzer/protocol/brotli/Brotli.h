// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <memory>

#include "zeek/analyzer/protocol/tcp/TCP.h"

struct BrotliDecoderStateStruct;

namespace zeek::analyzer::brotli {

/**
 * Support analyzer that decompresses a Brotli (RFC 7932) stream and forwards
 * the decompressed data. Requires Zeek to be built with libbrotlidec
 * (USE_BROTLI).
 *
 * Create instances with Instantiate(), which returns nullptr when Zeek was
 * built without Brotli support. Without it, none of the other members are
 * defined.
 *
 * How memory limit enforcement works:
 *
 * libbrotlidec allocates its decoder state (mainly the sliding window, which
 * a stream can make up to 16 MiB) through allocator callbacks. The analyzer
 * passes its own Alloc() and Free() functions, with itself as the opaque
 * pointer, when creating the decoder. Alloc() stores each block's size in a
 * small header in front of the block and adds it to a per-instance counter;
 * Free() reads the header and subtracts it again. If an allocation would push
 * the counter above max_decoder_memory, Alloc() returns nullptr. The decoder
 * then fails, and the analyzer reports brotli_decoder_memory_exceeded and
 * stops decompressing that stream.
 */
class Brotli_Analyzer final : public analyzer::tcp::TCP_SupportAnalyzer {
public:
    /**
     * Creates a Brotli analyzer.
     *
     * The result is typed as the base class so that callers don't depend on
     * Brotli_Analyzer symbols, which only exist when built with USE_BROTLI.
     *
     * @param max_uncompressed_size Maximum number of bytes to forward. 0 means no limit.
     * @param max_decoder_memory Maximum number of bytes the decoder may allocate. 0 means no limit.
     *
     * @return The new analyzer, or nullptr if Zeek was built without Brotli support.
     */
    static std::unique_ptr<analyzer::tcp::TCP_SupportAnalyzer> Instantiate(Connection* conn, bool orig,
                                                                           uint64_t max_uncompressed_size,
                                                                           uint64_t max_decoder_memory);

    ~Brotli_Analyzer() override;

    void Done() override;

    void DeliverStream(int len, const u_char* data, bool orig) override;

private:
    Brotli_Analyzer(Connection* conn, bool orig, uint64_t max_uncompressed_size, uint64_t max_decoder_memory);

    static void* Alloc(void* opaque, size_t size);
    static void Free(void* opaque, void* address);

    bool ForwardDecompressed(size_t len, const uint8_t* data);
    void FinishStream();

    BrotliDecoderStateStruct* state = nullptr;
    uint64_t max_uncompressed_size;
    uint64_t max_decoder_memory;
    uint64_t decoder_memory = 0;
    uint64_t uncompressed_size = 0;
    uint64_t denied_memory = 0; // Total the decoder asked for when the limit stopped it, 0 if never.
    bool stopped = false;
};

} // namespace zeek::analyzer::brotli

// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/brotli/Brotli.h"

#include "zeek/zeek-config.h"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <string>
#include <string_view>

#ifdef USE_BROTLI
#include <brotli/decode.h>
#endif

namespace zeek::analyzer::brotli {

std::unique_ptr<analyzer::tcp::TCP_SupportAnalyzer> Brotli_Analyzer::Instantiate(Connection* conn, bool orig,
                                                                                 uint64_t max_uncompressed_size,
                                                                                 uint64_t max_decoder_memory) {
#ifdef USE_BROTLI
    // The constructor is private, so std::make_unique() can't call it.
    return std::unique_ptr<Brotli_Analyzer>(new Brotli_Analyzer(conn, orig, max_uncompressed_size, max_decoder_memory));
#else
    return nullptr;
#endif
}

#ifdef USE_BROTLI

namespace {

// Each allocation stores its size in front of the block, so Free() can
// subtract it from the decoder's memory count.
constexpr size_t alloc_header = alignof(std::max_align_t);

} // namespace

Brotli_Analyzer::Brotli_Analyzer(Connection* conn, bool orig, uint64_t max_uncompressed_size,
                                 uint64_t max_decoder_memory)
    : analyzer::tcp::TCP_SupportAnalyzer("Brotli", conn, orig),
      max_uncompressed_size(max_uncompressed_size),
      max_decoder_memory(max_decoder_memory) {
    state = BrotliDecoderCreateInstance(Alloc, Free, this);

    if ( ! state ) {
        Weird("brotli_init_failed");
        stopped = true;
    }
}

Brotli_Analyzer::~Brotli_Analyzer() { FinishStream(); }

void Brotli_Analyzer::Done() {
    analyzer::tcp::TCP_SupportAnalyzer::Done();
    FinishStream();
}

void* Brotli_Analyzer::Alloc(void* opaque, size_t size) {
    auto* self = static_cast<Brotli_Analyzer*>(opaque);

    if ( self->max_decoder_memory > 0 && self->decoder_memory + size > self->max_decoder_memory ) {
        self->denied_memory = self->decoder_memory + size;
        return nullptr;
    }

    auto* block = static_cast<char*>(std::malloc(alloc_header + size));
    if ( ! block )
        return nullptr;

    *reinterpret_cast<size_t*>(block) = size;
    self->decoder_memory += size;
    return block + alloc_header;
}

void Brotli_Analyzer::Free(void* opaque, void* address) {
    if ( ! address )
        return;

    auto* self = static_cast<Brotli_Analyzer*>(opaque);
    auto* block = static_cast<char*>(address) - alloc_header;
    self->decoder_memory -= *reinterpret_cast<size_t*>(block);
    std::free(block);
}

bool Brotli_Analyzer::ForwardDecompressed(size_t len, const uint8_t* data) {
    if ( len == 0 )
        return true;

    if ( max_uncompressed_size == 0 ) {
        uncompressed_size += len;
        ForwardStream(static_cast<int>(len), data, IsOrig());
        return true;
    }

    const auto remaining = max_uncompressed_size > uncompressed_size ? max_uncompressed_size - uncompressed_size : 0;
    const auto forward_len = std::min<uint64_t>(len, remaining);
    if ( forward_len > 0 ) {
        uncompressed_size += forward_len;
        ForwardStream(static_cast<int>(forward_len), data, IsOrig());
    }

    if ( forward_len == len )
        return true;

    LimitReachedWeird("brotli_output_size_exceeded", uncompressed_size, max_uncompressed_size);
    return false;
}

void Brotli_Analyzer::FinishStream() {
    if ( state ) {
        BrotliDecoderDestroyInstance(state);
        state = nullptr;
    }
}

void Brotli_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    analyzer::tcp::TCP_SupportAnalyzer::DeliverStream(len, data, orig);

    if ( len <= 0 || stopped || ! state )
        return;

    constexpr size_t out_size = 4096;
    uint8_t out[out_size];

    size_t avail_in = len;
    const uint8_t* next_in = data;

    while ( true ) {
        size_t avail_out = out_size;
        uint8_t* next_out = out;

        auto result = BrotliDecoderDecompressStream(state, &avail_in, &next_in, &avail_out, &next_out, nullptr);

        if ( result == BROTLI_DECODER_RESULT_ERROR ) {
            if ( denied_memory > 0 )
                LimitReachedWeird("brotli_decoder_memory_exceeded", denied_memory, max_decoder_memory);
            else {
                // Newer libbrotli (1.1) returns "_ERROR_FORMAT_DICTIONARY" where
                // older versions (1.0.x) return "DICTIONARY". Strip the prefix so
                // the weird is the same on all versions.
                std::string_view err = BrotliDecoderErrorString(BrotliDecoderGetErrorCode(state));
                for ( std::string_view prefix : {"_ERROR_FORMAT_", "_ERROR_"} ) {
                    if ( err.starts_with(prefix) ) {
                        err.remove_prefix(prefix.size());
                        break;
                    }
                }
                Weird("brotli_decompress_failed", std::string(err).c_str());
            }

            stopped = true;
            FinishStream();
            return;
        }

        if ( ! ForwardDecompressed(out_size - avail_out, out) ) {
            stopped = true;
            FinishStream();
            return;
        }

        if ( result == BROTLI_DECODER_RESULT_SUCCESS ) {
            stopped = true;
            FinishStream();
            return;
        }

        // All input is consumed. Wait for the next chunk.
        if ( result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT )
            return;

        // BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT: loop to drain more output.
    }
}

#endif // USE_BROTLI

} // namespace zeek::analyzer::brotli

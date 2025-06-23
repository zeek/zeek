// See the file "COPYING" in the main distribution directory for copyright.
#pragma once

#include <string>

#include "zeek/Conn.h"
#include "zeek/analyzer/Analyzer.h"

namespace zeek::analyzer {

namespace mime {
class MIME_Message;
}

namespace smtp {

class SMTP_Analyzer;

namespace detail {

/**
 * Parsed from a BDAT argument.
 *
 * If error is non-nil, parsing failed.
 */
struct BDATCmd {
    uint64_t chunk_size = 0;
    bool is_last_chunk = false;
    const char* error = nullptr;
};

/**
 * Helper to parse a BDAT argument.
 *
 * @param length Length of arg
 * @param arg String following the "BDAT " part of the line.
 */
struct BDATCmd parse_bdat_arg(int length, const char* arg);

/**
 * The type of a BDAT chunk.
 *
 * Helper class to avoid true/false parameters.
 */
enum class ChunkType : uint8_t {
    None,
    Intermediate,
    Last,
};

/**
 * An analyzer to consume BDAT data.
 *
 * Yes, this is basically a small ContentLineAnalyzer, but instead
 * of being hooked up as a SupportAnalyzer and assumes TCP, too,
 * this directly forwards chunks into a MIME_Message instance. It's
 * also BDAT chunk aware and knows when a chunk should have completed.
 */
class SMTP_BDAT_Analyzer : public zeek::analyzer::Analyzer {
public:
    /**
     * Constructor.
     *
     * @param conn The connection over which data is transferred.
     * @param mail The MIME_Message to deliver lines to.
     * @param max_line_length Maximum line length before forcefully delivering.
     */
    SMTP_BDAT_Analyzer(zeek::Connection* conn, mime::MIME_Message* mail, size_t max_line_length);

    /**
     * Setup state for the next BDAT chunk.
     *
     * @param chunk_size The size in octest of the next chunk.
     * @param chunk_type Whether this is the last or an intermediate chunk.
     */
    void NextChunk(smtp::detail::ChunkType chunk_type, uint64_t chunk_size);

    /**
     * @see Analyzer::DeliverStream()
     */
    void DeliverStream(int len, const u_char* data, bool is_orig) override;

    /**
     * @see Analyzer::DeliverStream()
     */
    void Done() override;

    /**
     * @return The remaining size of the current chunk.
     */
    uint64_t RemainingChunkSize() const { return remaining_chunk_size; }

    /**
     * @return true if the current chunk was started with LAST.
     */
    bool IsLastChunk() const { return cur_chunk_type == ChunkType::Last; }

private:
    ChunkType cur_chunk_type = ChunkType::None;
    uint64_t remaining_chunk_size = 0;
    std::string buf;

    size_t max_line_length = 0;

    mime::MIME_Message* mail; // owned by SMTP analyzer.
};

} // namespace detail
} // namespace smtp
} // namespace zeek::analyzer

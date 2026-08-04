// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/zip/ZIP.h"

#include <algorithm>
#include <cinttypes>

namespace zeek::analyzer::zip {

ZIP_Analyzer::ZIP_Analyzer(Connection* conn, bool orig, Method arg_method)
    : analyzer::tcp::TCP_SupportAnalyzer("ZIP", conn, orig) {
    zip = nullptr;
    zip_status = Z_OK;
    method = arg_method;

    zip = new z_stream;
    zip->zalloc = nullptr;
    zip->zfree = nullptr;
    zip->opaque = nullptr;
    zip->next_out = nullptr;
    zip->avail_out = 0;
    zip->next_in = nullptr;
    zip->avail_in = 0;

    // "32" is a gross overload hack that means "check it
    // for whether it's a gzip file".  Sheesh.
    if ( inflateInit2(zip, MAX_WBITS + 32) != Z_OK ) {
        Weird("inflate_init_failed");
        delete zip;
        zip = nullptr;
    }
}

ZIP_Analyzer::~ZIP_Analyzer() { delete zip; }

void ZIP_Analyzer::Done() {
    Analyzer::Done();

    if ( zip )
        inflateEnd(zip);
}

bool ZIP_Analyzer::ForwardDecompressed(uint64_t len, const Bytef* data) {
    if ( len == 0 )
        return true;

    const auto limit = BifConst::ZIP::max_uncompressed_size;
    if ( limit == 0 ) {
        ForwardStream(static_cast<int>(len), data, IsOrig());
        return true;
    }

    const auto remaining = limit > uncompressed_size ? limit - uncompressed_size : 0;
    const auto forward_len = std::min(len, remaining);
    if ( forward_len > 0 ) {
        uncompressed_size += forward_len;
        ForwardStream(static_cast<int>(forward_len), data, IsOrig());
    }

    if ( forward_len == len )
        return true;

    Weird("zip_inflate_output_size_exceeded",
          zeek::util::fmt("limit=%" PRIu64 " in=%zu out=%" PRIu64, limit, zip->total_in, uncompressed_size));
    Conn()->CheckHistory(zeek::session::detail::HIST_UNKNOWN_PKT, 'X');
    zip_status = Z_MEM_ERROR;
    return false;
}

void ZIP_Analyzer::DeliverStream(int len, const u_char* data, bool orig) {
    analyzer::tcp::TCP_SupportAnalyzer::DeliverStream(len, data, orig);

    if ( ! len || zip_status != Z_OK )
        return;

    static unsigned int unzip_size = 4096;
    auto unzipbuf = std::make_unique<Bytef[]>(unzip_size);

    int allow_restart = 1;

    zip->next_in = (Bytef*)data;
    zip->avail_in = len;

    auto orig_next_in = zip->next_in;
    size_t orig_avail_in = zip->avail_in;

    while ( true ) {
        zip->next_out = unzipbuf.get();
        zip->avail_out = unzip_size;

        zip_status = inflate(zip, Z_SYNC_FLUSH);

        if ( zip_status == Z_STREAM_END || zip_status == Z_OK ) {
            allow_restart = 0;

            uint64_t have = unzip_size - zip->avail_out;
            if ( ! ForwardDecompressed(have, unzipbuf.get()) )
                return;

            if ( zip_status == Z_STREAM_END ) {
                inflateEnd(zip);
                return;
            }

            if ( zip->avail_in == 0 )
                return;
        }

        else if ( allow_restart && zip_status == Z_DATA_ERROR ) {
            // Some servers seem to not generate zlib headers,
            // so this is an attempt to fix and continue anyway.
            inflateEnd(zip);

            if ( inflateInit2(zip, -MAX_WBITS) != Z_OK ) {
                Weird("inflate_init_failed");
                return;
            }

            zip->next_in = orig_next_in;
            zip->avail_in = orig_avail_in;
            allow_restart = 0;
            continue;
        }

        else {
            Weird("inflate_failed");
            return;
        }
    }
}

} // namespace zeek::analyzer::zip

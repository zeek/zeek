// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/zip/ZIP.h"

#include <algorithm>
#include <cinttypes>

#include "zeek/analyzer/protocol/zip/events.bif.h"

namespace zeek::analyzer::zip {

ZIP_Analyzer::ZIP_Analyzer(Connection* conn, uint64_t max_uncompressed_size, bool orig, Method arg_method)
    : analyzer::tcp::TCP_SupportAnalyzer("ZIP", conn, orig), max_uncompressed_size(max_uncompressed_size) {
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

    if ( zip ) {
        if ( zip->total_in > 0 )
            zeek::BifEvent::enqueue_zip_analyzer_stats(this, Conn(), GetID(), zip->total_in, uncompressed_size,
                                                       size_exceeded);
        inflateEnd(zip);
    }
}

bool ZIP_Analyzer::ForwardDecompressed(uint64_t len, const Bytef* data) {
    if ( len == 0 )
        return true;

    if ( max_uncompressed_size == 0 ) {
        uncompressed_size += len;
        ForwardStream(static_cast<int>(len), data, IsOrig());
        return true;
    }

    const auto remaining = max_uncompressed_size > uncompressed_size ? max_uncompressed_size - uncompressed_size : 0;
    const auto forward_len = std::min(len, remaining);
    if ( forward_len > 0 ) {
        uncompressed_size += forward_len;
        ForwardStream(static_cast<int>(forward_len), data, IsOrig());
    }

    if ( forward_len == len )
        return true;

    Weird("zip_inflate_output_size_exceeded", zeek::util::fmt("limit=%" PRIu64 " in=%zu out=%" PRIu64,
                                                              max_uncompressed_size, zip->total_in, uncompressed_size));
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

    zip->next_in = reinterpret_cast<Bytef*>(const_cast<u_char*>(data));
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
            size_exceeded |= ! ForwardDecompressed(have, unzipbuf.get());
            if ( size_exceeded )
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

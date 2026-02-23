// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/analyzer/protocol/smtp/BDAT.h"

#include <strings.h>
#include <cinttypes>

#include "zeek/Conn.h"
#include "zeek/DebugLogger.h"
#include "zeek/analyzer/protocol/mime/MIME.h"
#include "zeek/packet_analysis/protocol/ip/conn_key/IPBasedConnKey.h"
#include "zeek/util.h"

#include "zeek/3rdparty/doctest.h"

namespace zeek::analyzer::smtp::detail {


struct BDATCmd parse_bdat_arg(int length, const char* arg) {
    struct BDATCmd r = {0};

    // UINT64_MAX followed by " LAST" is the most we can deal with
    // and anyway this would be really weird for a client to use.
    // strlen("18446744073709551615 LAST")
    constexpr int max_arg_len = 25;

    if ( length <= 0 || length > max_arg_len ) {
        r.error = "BDAT argument bad length";
        return r;
    }

    if ( *arg == '\0' || ! isdigit(*arg) ) {
        r.error = "BDAT not followed by a valid chunk-size";
        return r;
    }

    // Ensure arg is NULL terminated by copying the
    // input into a new std::string object so we can use
    // strtoull() properly. We do have zeek::util::atoi_n,
    // but it's not handling overflows.
    //
    // The size is bounded, see max_arg_len above.
    std::string arg_copy = {arg, static_cast<std::string::size_type>(length)};
    const char* arg_end = arg_copy.c_str() + length;

    errno = 0;
    char* chunk_size_end = nullptr;
    uint64_t chunk_size = strtoull(arg_copy.c_str(), &chunk_size_end, 10);
    if ( *chunk_size_end != ' ' && *chunk_size_end != '\0' ) {
        r.error = "BDAT chunk-size not valid";
        return r;
    }

    // strtoull() returns ULLONG_MAX and sets errno on overflow.
    if ( chunk_size == ULLONG_MAX && errno == ERANGE ) {
        r.error = "BDAT chunk-size too large";
        return r;
    }

    r.chunk_size = chunk_size;

    // If there's something left after the chunk-size,
    // it should be LAST, otherwise it's an error.
    if ( chunk_size_end != arg_end ) {
        r.is_last_chunk = strncasecmp(chunk_size_end, " LAST", 5) == 0;

        if ( ! r.is_last_chunk || chunk_size_end + 5 != arg_end )
            r.error = "BDAT chunk-size followed by junk";
    }

    return r;
}


SMTP_BDAT_Analyzer::SMTP_BDAT_Analyzer(Connection* conn, mime::MIME_Message* mail, size_t max_line_length)
    : analyzer::Analyzer("SMTP_BDAT", conn), max_line_length(max_line_length), mail(mail) {}

void SMTP_BDAT_Analyzer::NextChunk(ChunkType chunk_type, uint64_t chunk_size) {
    DBG_LOG(DBG_ANALYZER, "BDAT: NextChunk size=%" PRIi64 " last=%d", chunk_size, chunk_type == ChunkType::Last);
    assert(remaining_chunk_size == 0);
    cur_chunk_type = chunk_type;
    remaining_chunk_size = chunk_size;
}

void SMTP_BDAT_Analyzer::DeliverStream(int len, const u_char* data, bool is_orig) {
    analyzer::Analyzer::DeliverStream(len, data, is_orig);
    assert(mail != nullptr);
    assert(! IsFinished());

    // We cast to uint64_t, so need to have a positive value.
    if ( len < 0 ) {
        Weird("smtp_bdat_negative_len");
        return;
    }

    // Upstream analyzer delivers more data than we're
    // expecting for the current chunk. Likely a logic
    // error on their side. Truncate it.
    if ( static_cast<uint64_t>(len) > RemainingChunkSize() ) {
        Weird("smtp_bdat_chunk_overflow");
        len = static_cast<int>(RemainingChunkSize());
    }

    // If the buffer ends with a cr and the new data doesn't start with lf
    // or it's empty, deliver everything in the buffer, including the cr.
    if ( ! buf.empty() && buf[buf.size() - 1] == '\r' ) {
        if ( len == 0 || (len > 0 && data[0] != '\n') ) {
            Weird("smtp_bdat_line_cr_only");
            mail->Deliver(buf.size(), buf.data(), false /*trailing_crlf*/);
            buf.resize(0);
        }
    }

    // Start searching for crlf at the end of the old buffer, if any.
    std::string::size_type i = ! buf.empty() ? buf.size() - 1 : 0;

    buf.append(reinterpret_cast<const char*>(data), len);

    std::string::size_type line_start = 0;
    for ( ; i < buf.size(); i++ ) {
        if ( i < buf.size() - 1 && buf[i] == '\r' && buf[i + 1] == '\n' ) {
            // Found a match, buf[line_start, i) is the line we want to Deliver()
            buf[i] = '\0';
            buf[i + 1] = '\0';
            mail->Deliver(i - line_start, &buf[line_start], true /*trailing_crlf*/);
            line_start = i + 2;
            i += 1;
        }
        else if ( buf[i] == '\n' ) {
            // There's only a lf without a preceding cr, deliver the
            // line including the lf, but trailing_CRLF set as false.
            Weird("smtp_bdat_line_lf_only");
            mail->Deliver(i - line_start + 1, &buf[line_start], false /*trailing_crlf*/);
            line_start = i + 1;
        }
        else if ( i - line_start >= max_line_length ) {
            Weird("smtp_bdat_line_too_long", zeek::util::fmt("%zu", buf.size()));
            mail->Deliver(i - line_start, &buf[line_start], false /*trailing_crlf*/);
            line_start = i;
        }
    }

    // Trim everything that was delivered (might be nothing).
    buf.erase(0, line_start);
    remaining_chunk_size -= len;

    // If this is the last chunk and all data was received, Flush any
    // remaining data out now. Done() is called by the owner of mail.
    if ( IsLastChunk() && RemainingChunkSize() == 0 && ! buf.empty() ) {
        mail->Deliver(buf.size(), buf.data(), false /*trailing_crlf*/); // Maybe this should be true?
        buf.erase();
    }
}

void SMTP_BDAT_Analyzer::Done() {
    analyzer::Analyzer::Done();

    // Anything still buffered? Unexpected, but deliver it.
    if ( ! buf.empty() ) {
        Weird("smtp_bdat_undelivered_at_done");
        mail->Deliver(buf.size(), buf.data(), false /*trailing_crlf*/);
        buf.erase();
    }
}

} // namespace zeek::analyzer::smtp::detail


#include "zeek/analyzer/Analyzer.h"
#include "zeek/analyzer/Manager.h"

namespace {

using zeek::analyzer::smtp::detail::parse_bdat_arg;

TEST_SUITE_BEGIN("bdat command parsing");

TEST_CASE("last chunk") {
    std::string line = "86 LAST";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    CHECK(error == nullptr);
    CHECK(chunk_size == 86);
    CHECK(is_last_chunk == true);
}

TEST_CASE("last chunk lower") {
    std::string line = "86 last";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    CHECK(error == nullptr);
    CHECK(chunk_size == 86);
    CHECK(is_last_chunk == true);
}

TEST_CASE("intermediate chunk") {
    std::string line = "86";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    CHECK(error == nullptr);
    CHECK(chunk_size == 86);
    CHECK(is_last_chunk == false);
}

TEST_CASE("intermediate chunk rn") {
    std::string line = "86\r\n";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size() - 2, line.c_str());
    CHECK(error == nullptr);
    CHECK(chunk_size == 86);
    CHECK(is_last_chunk == false);
}

TEST_CASE("space pre chunk size") {
    std::string line = " 86 LAST";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    REQUIRE(error != nullptr);
    CHECK(error == std::string("BDAT not followed by a valid chunk-size"));
}

TEST_CASE("non-numeric chunk size") {
    std::string line = "scramble LAST";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    REQUIRE(error != nullptr);
    CHECK(error == std::string("BDAT not followed by a valid chunk-size"));
}

TEST_CASE("missing space post chunk size") {
    std::string line = "86LAST";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    REQUIRE(error != nullptr);
    CHECK(error == std::string("BDAT chunk-size not valid"));
}

TEST_CASE("chunk size followed by junk") {
    std::string line = "86 SCRAMBLE";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    REQUIRE(error != nullptr);
    CHECK(error == std::string("BDAT chunk-size followed by junk"));
}

TEST_CASE("chunk size followed by lastjunk") {
    std::string line = "86 LASTSCRAMBLE";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    REQUIRE(error != nullptr);
    CHECK(error == std::string("BDAT chunk-size followed by junk"));
}

TEST_CASE("huge chunk size") {
    std::string line = "15555555557777777777";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    REQUIRE(error == nullptr);
    CHECK(chunk_size == 15555555557777777777UL);
}

TEST_CASE("UINT64_MAX * 10 chunk size") {
    // UINT64_MAX is 18446744073709551615UL, multiply by 10
    std::string line = "184467440737095516150";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    REQUIRE(error != nullptr);
    CHECK(error == std::string("BDAT chunk-size too large"));
}

TEST_CASE("negative chunk size") {
    std::string line = "-42 LAST";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    REQUIRE(error != nullptr);
    CHECK(error == std::string("BDAT not followed by a valid chunk-size"));
}

TEST_CASE("non null terminated") {
    // Regression test for buffer overread triggered by non-null
    // terminated input from a wrongly configured ContentLineAnalyzer.
    const char* input_data = "7777777777";
    auto data = std::make_unique<char[]>(strlen(input_data));
    memcpy(data.get(), input_data, strlen(input_data));

    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(strlen(input_data), data.get());
    REQUIRE(error == nullptr);
    CHECK(chunk_size == 7777777777);
}

TEST_CASE("maximum length") {
    std::string line = "18446744073709551615 LAST";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    REQUIRE(error == nullptr);
    CHECK(chunk_size == 18446744073709551615UL);
    CHECK(is_last_chunk == true);
}

TEST_CASE("maximum length exceeded") {
    std::string line = "184467440737095516150 LAST";
    const auto& [chunk_size, is_last_chunk, error] = parse_bdat_arg(line.size(), line.c_str());
    REQUIRE(error != nullptr);
    CHECK(error == std::string("BDAT argument bad length"));
}

TEST_SUITE_END();

TEST_SUITE_BEGIN("bdat line analyzer");

using zeek::analyzer::smtp::detail::ChunkType;
using zeek::analyzer::smtp::detail::SMTP_BDAT_Analyzer;

namespace mime = zeek::analyzer::mime;

/**
 * Helper class to test Deliver()  calls.
 */
class Test_MIME_Message : public mime::MIME_Message {
public:
    Test_MIME_Message(zeek::analyzer::Analyzer* a) : MIME_Message(a) {}

    void Deliver(int len, const char* data, bool trailing_CRLF) override {
        assert(len >= 0);
        // std::printf("Deliver: '%s' trailing_CRLF=%d\n", data, trailing_CRLF);
        deliver_calls.emplace_back(std::string{data, static_cast<std::string::size_type>(len)}, trailing_CRLF);
    }


    // Noops, should not be called
    void BeginEntity(mime::MIME_Entity* entity) override {}
    void EndEntity(mime::MIME_Entity* entity) override {}
    void SubmitHeader(mime::MIME_Header* h) override {}
    void SubmitAllHeaders(mime::MIME_HeaderList& hlist) override {}
    void SubmitData(int len, const char* buf) override {}
    bool RequestBuffer(int* plen, char** pbuf) override { return false; }
    void SubmitEvent(int event_type, const char* detail) override {}

    const auto& DeliverCalls() const { return deliver_calls; }

private:
    std::vector<std::pair<std::string, bool>> deliver_calls;
};

TEST_CASE("line forward testing") {
    zeek::Packet p;
    zeek::IPBasedConnKeyPtr kp = std::make_unique<zeek::IPConnKey>();
    auto conn = std::make_unique<zeek::Connection>(std::move(kp), 0, 0, &p);
    auto smtp_analyzer =
        std::unique_ptr<zeek::analyzer::Analyzer>(zeek::analyzer_mgr->InstantiateAnalyzer("SMTP", conn.get()));
    auto mail = std::make_unique<Test_MIME_Message>(smtp_analyzer.get());
    auto bdat = std::make_unique<SMTP_BDAT_Analyzer>(conn.get(), mail.get(), 128 /* max line length*/);

    auto deliver_all = [](const auto& ds, auto& bdat) {
        for ( const auto& d : ds )
            bdat->NextStream(d.size(), reinterpret_cast<const u_char*>(d.data()), true /*is_orig, irrelevant*/);
    };

    auto total_size = [](const auto& ds) {
        uint64_t r = 0;
        for ( const auto& d : ds )
            r += d.size();

        return r;
    };

    // Helpers for type deduction.
    std::vector<std::string> deliveries;
    std::vector<std::pair<std::string, bool>> expected;

    SUBCASE("test two lines split in four") {
        deliveries = {"MIME-", "Version: 1.0\r\n", "Subject: Zeek", " Logo\r\n"};
        bdat->NextChunk(ChunkType::Last, total_size(deliveries));
        deliver_all(deliveries, bdat);

        expected = {{"MIME-Version: 1.0", true}, {"Subject: Zeek Logo", true}};
        CHECK(mail->DeliverCalls() == expected);
    }

    SUBCASE("split on cr") {
        deliveries = {"MIME-", "Version: 1.0\r", "\nSubject: Zeek", " Logo\r", "\n"};
        bdat->NextChunk(ChunkType::Last, total_size(deliveries));
        deliver_all(deliveries, bdat);

        expected = {{"MIME-Version: 1.0", true}, {"Subject: Zeek Logo", true}};
        CHECK(mail->DeliverCalls() == expected);
    }

    SUBCASE("cr without lf") {
        // Currently, when there's just a \r, will deliver including the cr
        deliveries = {"MIME-Version: 1.0\r", "Subject: Zeek", " Logo\r\n"};
        bdat->NextChunk(ChunkType::Last, total_size(deliveries));
        deliver_all(deliveries, bdat);

        expected = {{"MIME-Version: 1.0\r", false}, {"Subject: Zeek Logo", true}};
        CHECK(mail->DeliverCalls() == expected);
    }

    SUBCASE("lf without cr") {
        // When a line ends only with lf, will deliver it, but including the lf
        deliveries = {"MIME-Version: 1.0\n", "Subject: Zeek", " Logo\n", "From: Zeek <zeek@localhost>\r\n"};
        bdat->NextChunk(ChunkType::Last, total_size(deliveries));
        deliver_all(deliveries, bdat);

        expected = {{"MIME-Version: 1.0\n", false},
                    {"Subject: Zeek Logo\n", false},
                    {"From: Zeek <zeek@localhost>", true}};
        CHECK(mail->DeliverCalls() == expected);
    }

    SUBCASE("max_line_length 10") {
        bdat->Done(); // Assertion prevention.
        bdat = std::make_unique<SMTP_BDAT_Analyzer>(conn.get(), mail.get(), 10 /* max line length*/);
        deliveries = {"1234567890123: 45\r\n", "X-Test: Y\r\n"};
        bdat->NextChunk(ChunkType::Last, total_size(deliveries));
        deliver_all(deliveries, bdat);

        expected = {{"1234567890", false}, {"123: 45", true}, {"X-Test: Y", true}};
        CHECK(mail->DeliverCalls() == expected);
    }

    // Proper cleanup to avoid assertions
    bdat->Done();
    mail->Done();
    smtp_analyzer->Done();
    conn->Done();
}

TEST_SUITE_END();
} // namespace

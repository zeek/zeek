// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <optional>
#include <string>
#include <utility>

#include <hilti/rt/types/stream.h>

#include <spicy/rt/driver.h>
#include <spicy/rt/parser.h>

#include "zeek/spicy/cookie.h"

namespace zeek::spicy::rt {

/** Parsing state for a file. */
class FileState : public ::spicy::rt::driver::ParsingState {
public:
    /**
     * Constructor.
     *
     * @param cookie cookie to associated with the file
     */
    FileState(Cookie cookie) : ParsingState(::spicy::rt::driver::ParsingType::Stream), _cookie(std::move(cookie)) {}

    /** Returns the cookie pointer to use with the runtime library during analysis. */
    auto* cookie() { return &_cookie; }

    /** Returns the file-specific cookie state associated with the endpoint. */
    auto& file() {
        assert(_cookie.file);
        return *_cookie.file;
    }

    /**
     * Records a debug message pertaining to the specific file.
     *
     * @param msg message to record
     */
    void DebugMsg(const std::string& msg) { debug(msg); }

protected:
    // Overridden from driver::ParsingState.
    void debug(const std::string& msg) override;

private:
    Cookie _cookie;
};

/** A Spicy file analyzer. */
class FileAnalyzer : public file_analysis::Analyzer {
public:
    FileAnalyzer(RecordValPtr arg_args, file_analysis::File* arg_file);
    virtual ~FileAnalyzer();

    static file_analysis::Analyzer* InstantiateAnalyzer(RecordValPtr args, file_analysis::File* file);

protected:
    // Overridden from Zeek's file analyzer.
    void Init() override;
    void Done() override;
    bool DeliverStream(const u_char* data, uint64_t len) override;
    bool Undelivered(uint64_t offset, uint64_t len) override;
    bool EndOfFile() override;

    /**
     * Feeds a chunk of data into parsing.
     *
     * @param len number of bytes valid in *data*
     * @param data pointer to data
     * @return true if processing succeeded, false if an error occurred that
     * stopped parsing
     */
    bool Process(int len, const u_char* data);

    /**
     * Finalizes parsing. After calling this, no more data can be passed into
     * Process().
     */
    void Finish();

    /** Records a debug message. */
    void DebugMsg(const std::string& msg) { _state.DebugMsg(msg); }

private:
    FileState _state;
};

} // namespace zeek::spicy::rt

// See the file "COPYING" in the main distribution directory for copyright.

#include "file-analyzer.h"

#include <utility>

#include "spicy.bif.h"
#include "zeek/file_analysis/File.h"
#include "zeek/spicy/manager.h"
#include "zeek/spicy/runtime-support.h"

using namespace zeek;
using namespace zeek::spicy;
using namespace zeek::spicy::rt;

#ifdef DEBUG
#define STATE_DEBUG_MSG(...) DebugMsg(__VA_ARGS__)
#else
#define STATE_DEBUG_MSG(...)
#endif

void FileState::debug(const std::string& msg) { spicy::rt::debug(_cookie, msg); }

static auto create_file_state(FileAnalyzer* analyzer) {
    uint64_t depth = 0;
    if ( auto current_cookie = static_cast<Cookie*>(hilti::rt::context::cookie()) ) {
        if ( const auto f = current_cookie->file )
            depth = f->depth + 1;
    }

    cookie::FileAnalyzer cookie{.analyzer = analyzer,
                                .depth = depth,
                                .fstate = cookie::FileStateStack(analyzer->GetFile()->GetID())};
    return FileState(std::move(cookie));
}

FileAnalyzer::FileAnalyzer(RecordValPtr args, file_analysis::File* file)
    : file_analysis::Analyzer(std::move(args), file), _state(create_file_state(this)) {}

FileAnalyzer::~FileAnalyzer() {}

void FileAnalyzer::Init() {}

void FileAnalyzer::Done() { Finish(); }

bool FileAnalyzer::DeliverStream(const u_char* data, uint64_t len) {
    file_analysis::Analyzer::DeliverStream(data, len);

    return Process(len, data);
}

bool FileAnalyzer::Undelivered(uint64_t offset, uint64_t len) {
    file_analysis::Analyzer::Undelivered(offset, len);

    STATE_DEBUG_MSG("undelivered data, skipping further originator payload");
    _state.skipRemaining();
    return false;
}

bool FileAnalyzer::EndOfFile() {
    file_analysis::Analyzer::EndOfFile();
    Finish();
    return false;
}

bool FileAnalyzer::Process(int len, const u_char* data) {
    if ( ! _state.hasParser() && ! _state.isSkipping() ) {
        auto parser = spicy_mgr->parserForFileAnalyzer(_state.file().analyzer->Tag());
        if ( parser )
            _state.setParser(parser);
        else {
            STATE_DEBUG_MSG("no unit specified for parsing");
            _state.skipRemaining();
            return false;
        }
    }

    auto* file = _state.file().analyzer->GetFile();

    const auto& max_file_depth = BifConst::Spicy::max_file_depth;

    if ( _state.file().depth >= max_file_depth ) {
        const auto& file_val = file->ToVal();

        const auto analyzer_args = _state.file().analyzer->GetArgs();

        file->FileEvent(Spicy::max_file_depth_exceeded, {file_val, analyzer_args, val_mgr->Count(_state.file().depth)});

        auto tag = spicy_mgr->tagForFileAnalyzer(_state.file().analyzer->Tag());
#if ZEEK_VERSION_NUMBER >= 50200
        AnalyzerViolation("maximal file depth exceeded", reinterpret_cast<const char*>(data), len, tag);
#else
        // We don't have an an appropriate way to report this with older Zeeks.
#endif
        return false;
    }

    try {
        hilti::rt::context::CookieSetter _(_state.cookie());
        _state.process(len, reinterpret_cast<const char*>(data));
    } catch ( const hilti::rt::RuntimeError& e ) {
        STATE_DEBUG_MSG(hilti::rt::fmt("error during parsing, triggering analyzer violation: %s", e.what()));
        auto tag = spicy_mgr->tagForFileAnalyzer(_state.file().analyzer->Tag());
#if ZEEK_VERSION_NUMBER >= 50200
        AnalyzerViolation(e.what(), reinterpret_cast<const char*>(data), len, tag);
#else
        // We don't have an an appropriate way to report this with older Zeeks.
#endif
    } catch ( const hilti::rt::Exception& e ) {
        STATE_DEBUG_MSG(e.what());
        spicy_mgr->analyzerError(_state.file().analyzer, e.description(),
                                 e.location()); // this sets Zeek to skip sending any further input
    }

    return true;
}

void FileAnalyzer::Finish() {
    try {
        hilti::rt::context::CookieSetter _(_state.cookie());
        _state.finish();
    } catch ( const hilti::rt::RuntimeError& e ) {
        STATE_DEBUG_MSG(hilti::rt::fmt("error during parsing, triggering analyzer violation: %s", e.what()));
        auto tag = spicy_mgr->tagForFileAnalyzer(_state.file().analyzer->Tag());
#if ZEEK_VERSION_NUMBER >= 50200
        AnalyzerViolation(e.what(), "", 0, tag);
#else
        // We don't have an an appropriate way to report this with older Zeeks.
#endif
    } catch ( const hilti::rt::Exception& e ) {
        spicy_mgr->analyzerError(_state.file().analyzer, e.description(),
                                 e.location()); // this sets Zeek to skip sending any further input
    }
}

file_analysis::Analyzer* FileAnalyzer::InstantiateAnalyzer(RecordValPtr args, file_analysis::File* file) {
    return new FileAnalyzer(std::move(args), file);
}

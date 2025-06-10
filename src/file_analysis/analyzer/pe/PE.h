// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/Val.h"

#include "file_analysis/analyzer/pe/pe_pac.h"

namespace zeek::file_analysis::detail {

/**
 * Analyze Portable Executable files
 */
class PE : public file_analysis::Analyzer {
public:
    ~PE() override;

    static file_analysis::Analyzer* Instantiate(RecordValPtr args, file_analysis::File* file) {
        return new PE(std::move(args), file);
    }

    bool DeliverStream(const u_char* data, uint64_t len) override;
    bool EndOfFile() override;

protected:
    PE(RecordValPtr args, file_analysis::File* file);
    binpac::PE::File* interp;
    binpac::PE::MockConnection* conn;
    bool done;
};

} // namespace zeek::file_analysis::detail

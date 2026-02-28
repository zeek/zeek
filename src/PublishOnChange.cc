// See the file "COPYING" in the main distribution directory for copyright.
//
#include "zeek/PublishOnChange.h"

#include <memory>

#include "zeek/Val.h"

#include "Desc.h"

namespace zeek::detail {

bool operator&(uint8_t mask, TableChange v) { return (static_cast<uint8_t>(v) & mask) == static_cast<uint8_t>(v); }

std::unique_ptr<PublishOnChangeState> PublishOnChangeState::FromRecord(const zeek::RecordVal& rec) {
    //
    std::fprintf(stderr, "yes %s\n", obj_desc_short(&rec).c_str());

    return std::make_unique<PublishOnChangeState>(0, 0, 0);
}

} // namespace zeek::detail

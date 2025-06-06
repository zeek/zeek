// See the file "COPYING" in the main distribution directory for copyright.

// Management of the ZAM frame used to hold low-level local variables.

#pragma once

#include <vector>

#include "zeek/Attr.h"
#include "zeek/ID.h"
#include "zeek/util-types.h"

namespace zeek::detail {

using AttributesPtr = IntrusivePtr<Attributes>;

// Maps ZAM frame slots to associated identifiers. These are the simplest
// types of frames, where each identifier has its own slot.
using FrameMap = std::vector<const ID*>;

// Maps ZAM frame slots to information for sharing the slot across
// multiple script variables.
class FrameSharingInfo {
public:
    // The variables sharing the slot.  ID's need to be non-const so we
    // can manipulate them, for example by changing their interpreter
    // frame offset.
    std::vector<const ID*> ids;

    // A parallel vector, only used for fully compiled code, which
    // gives the names of the identifiers.  When in use, the above
    // "ids" member variable may be empty.
    std::vector<const char*> names;

    // The ZAM instruction number where a given identifier starts its
    // scope, parallel to "ids".
    std::vector<zeek_uint_t> id_start;

    // The current end of the frame slot's scope.  Gets updated as
    // new IDs are added to share the slot.
    int scope_end = -1;

    // Whether this is a managed slot.
    bool is_managed = false;
};

using FrameReMap = std::vector<FrameSharingInfo>;

} // namespace zeek::detail

// See the file "COPYING" in the main distribution directory for copyright.

// Utility functions that return information about Zeek functions. Currently
// this is limited to information about whether BiFs are side-effect-free
// (from a Zeek scripting perspective), but could be expanded in the future
// to include information about Zeek script functions, idempotency, and the
// like.

#pragma once

#include "zeek/Func.h"

namespace zeek::detail {

extern bool is_side_effect_free(std::string f);

} // namespace zeek::detail

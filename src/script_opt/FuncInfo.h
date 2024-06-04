// See the file "COPYING" in the main distribution directory for copyright.

// Utility functions that return information about Zeek functions.

#pragma once

#include "zeek/Func.h"

namespace zeek::detail {

// A "special script function" is one that the event engine explicitly
// knows about.
extern bool is_special_script_func(const std::string& func_name);

// Whether ZAM can replace the given script with specialized instructions.
extern bool is_ZAM_replaceable_script_func(const std::string& func_name);

// An idempotent function returns the same value when called with the
// same arguments (and has no meaningful side effects in terms of script-level
// or Zeek-internal state).
extern bool is_idempotent(const std::string& func_name);

// A foldable function can be folded at compile time if all of its arguments
// are constants. Such functions cannot generate error messages.
extern bool is_foldable(const std::string& func_name);

// Whether the given function (currently, just BiFs) has Zeek-script-level
// side effects.
extern bool has_script_side_effects(const std::string& func_name);

} // namespace zeek::detail

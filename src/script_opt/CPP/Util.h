// See the file "COPYING" in the main distribution directory for copyright.

// Utility functions for compile-to-C++ compiler.

#pragma once

#include "zeek/script_opt/ProfileFunc.h"

namespace zeek::detail {

// Conversions to strings.
inline std::string Fmt(int i)		{ return std::to_string(i); }
inline std::string Fmt(p_hash_type u)	{ return std::to_string(u) + "ULL"; }
extern std::string Fmt(double d);

// Returns the prefix for the scoping used by the compiler.
extern std::string scope_prefix(const std::string& scope);

// Same, but for scopes identified with numbers.
extern std::string scope_prefix(int scope);

// True if the given function is compilable to C++.  If it isn't, and
// the second argument is non-nil, then on return it points to text
// explaining why not.
extern bool is_CPP_compilable(const ProfileFunc* pf,
                              const char** reason = nullptr);

// Helper utilities for file locking, to ensure that hash files
// don't receive conflicting writes due to concurrent compilations.
extern void lock_file(const std::string& fname, FILE* f);
extern void unlock_file(const std::string& fname, FILE* f);

} // zeek::detail

//
// These functions are used by both Bro and bifcl.
//

#pragma once

#include <string>

namespace zeek::detail {

static constexpr const char* GLOBAL_MODULE_NAME = "GLOBAL";

extern std::string extract_module_name(const char* name);
extern std::string extract_var_name(const char* name);
extern std::string normalized_module_name(const char* module_name); // w/o ::

// Concatenates module_name::var_name unless var_name is already fully
// qualified, in which case it is returned unmodified.
extern std::string make_full_var_name(const char* module_name, const char* var_name);

} // namespace zeek::detail

constexpr auto GLOBAL_MODULE_NAME [[deprecated("Remove in v4.1. Use zeek::detail::GLOBAL_MODULE_NAME.")]] = zeek::detail::GLOBAL_MODULE_NAME;
constexpr auto extract_module_name [[deprecated("Remove in v4.1. Use zeek::detail::extract_module_name.")]] = zeek::detail::extract_module_name;
constexpr auto extract_var_name [[deprecated("Remove in v4.1. Use zeek::detail::extract_var_name.")]] = zeek::detail::extract_var_name;
constexpr auto normalized_module_name [[deprecated("Remove in v4.1. Use zeek::detail::normalized_module_name.")]] = zeek::detail::normalized_module_name;
constexpr auto make_full_var_name [[deprecated("Remove in v4.1. Use zeek::detail::make_full_var_name.")]] = zeek::detail::make_full_var_name;

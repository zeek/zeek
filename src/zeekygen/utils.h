// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include <time.h> // for time_t
#include <string>

ZEEK_FORWARD_DECLARE_NAMESPACED(ID, zeek::detail);

namespace zeek::zeekygen::detail {

/**
 * Transform content of a Zeekygen comment which may contain function
 * parameter or return value documentation to a prettier reST format.
 * @param s Content from a Zeekygen comment to transform. "id: ..." and
 * "Returns: ..." change to ":id: ..." and ":returns: ...".
 * @return Whether any content in \a s was transformed.
 */
bool prettify_params(std::string& s);

/**
 * Check whether an identifier is part of the "public" interface.
 * @param id A script-level identifier.
 * @return true if the ID is in the global scope or if it's exported in to
 * any modules namespace.
 */
bool is_public_api(const zeek::detail::ID* id);

/**
 * Get the modification time of a file or abort if there's an error.
 * @param filename Path to a file.
 * @return The modification time of \a filename via stat(2).
 */
time_t get_mtime(const std::string& filename);

/**
 * Make a reST-style heading.
 * @param heading Content of the heading.
 * @param underline Character in which to underline heading content.
 * @return underlined heading string.
 */
std::string make_heading(const std::string& heading, char underline);

/**
 * Get the position of the end of the first sentence in a string.
 * @param s Any string.
 * @return The position which looks like the end of the first sentence in
 * \a s or 0 if no such position is found.
 */
size_t end_of_first_sentence(const std::string& s);

/**
 * Check if a string is entirely white space.
 * @param s Any string.
 * @return True if \a s is nothing but white space, else false.
 */
bool is_all_whitespace(const std::string& s);

/**
 * @return a string indicating the script that has redef'd an enum value or
 * record field.
 */
std::string redef_indication(const std::string& from_script);

} // namespace zeek::zeekygen::detail

namespace zeekygen {

constexpr auto prettify_params [[deprecated("Remove in v4.1. Use zeek::zeekygen::detail::prettify_params.")]] = zeek::zeekygen::detail::prettify_params;
constexpr auto is_public_api [[deprecated("Remove in v4.1. Use zeek::zeekygen::detail::is_public_api.")]] = zeek::zeekygen::detail::is_public_api;
constexpr auto get_mtime [[deprecated("Remove in v4.1. Use zeek::zeekygen::detail::get_mtime.")]] = zeek::zeekygen::detail::get_mtime;
constexpr auto make_heading [[deprecated("Remove in v4.1. Use zeek::zeekygen::detail::make_heading.")]] = zeek::zeekygen::detail::make_heading;
constexpr auto end_of_first_sentence [[deprecated("Remove in v4.1. Use zeek::zeekygen::detail::end_of_first_sentence.")]] = zeek::zeekygen::detail::end_of_first_sentence;
constexpr auto is_all_whitespace [[deprecated("Remove in v4.1. Use zeek::zeekygen::detail::is_all_whitespace.")]] = zeek::zeekygen::detail::is_all_whitespace;
constexpr auto redef_indication [[deprecated("Remove in v4.1. Use zeek::zeekygen::detail::redef_indication.")]] = zeek::zeekygen::detail::redef_indication;

} // namespace zeekygen

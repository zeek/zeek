// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/zeek-config.h"

#include <ctime> // for time_t
#include <optional>
#include <string>

namespace zeek::detail {
class ID;
}

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

/**
 * Turns a script's path into a shortened, normalized version that
 * can be used for indexing and cross-referencing links.
 *
 * @param path  the associate path to a Zeek script, which may be absolute.
 *
 * @return  a normalized/shortened path (containing no ZEEKPATH components)
 *
 */
std::string normalize_script_path(std::string_view path);

/**
 * Determines the associated section of source code associated with an
 * identifier's definition.
 *
 * @param id  identifier for which obtain source code location info is obtained
 *
 * @return  a nil value if source code location could not be determined, else
 * a space-separated string with 3 components.  The 1st component is a path
 * relative to the "scripts/" directory, the 2nd and 3rd components are
 * line numbers denoting the start and end of the relevant source code.
 */
std::optional<std::string> source_code_range(const zeek::detail::ID* id);

} // namespace zeek::zeekygen::detail

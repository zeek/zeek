// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

namespace zeek {

class ODesc;

namespace detail {
class ID;
}

namespace zeekygen::detail {

/**
 * Render a script-level identifier's declaration as reST.

 * @param id The identifier to describe.
 * @param d The description object to write to.
 * @param roles_only Whether to emit just a cross-reference role instead of a full
 *                   directive with the identifier's type, attributes, and values.
 */
void describe_id_rest(const zeek::detail::ID* id, ODesc* d, bool roles_only = false);

/**
 * Render a script-level identifier's name and type as reST, for use in the
 * summary tables of a script's documentation.

 * @param id The identifier to describe.
 * @param d The description object to write to.
 */
void describe_id_rest_short(const zeek::detail::ID* id, ODesc* d);

} // namespace zeekygen::detail
} // namespace zeek

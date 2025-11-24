// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include <span>

#include "zeek/IntrusivePtr.h"

namespace zeek {

class Val;
using ValPtr = IntrusivePtr<Val>;

class VectorVal;
using VectorValPtr = IntrusivePtr<VectorVal>;

using ArgsSpan = std::span<const ValPtr>;

namespace cluster::table::detail::bif {

void publish_elements_new(zeek::ArgsSpan args);

/**
 * Insert all elements from \a new_elements into the table identified by \a id.
 *
 * @param id
 * @param new_elements
 *
 * Note that running the &on_change handler publish_new_element() will be
 * skipped as the idea is that ``insert_new_elements()`` inserts elements that
 * were published via ``publish_new_element()`` and re-publishing is not intended.
 */
bool insert_elements_new(std::string_view id, const VectorVal& new_elements);

} // namespace cluster::table::detail::bif
} // namespace zeek

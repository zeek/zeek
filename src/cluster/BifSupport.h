// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/IntrusivePtr.h"
#include "zeek/Span.h"

// Helpers for cluster.bif

namespace zeek {

namespace detail {
class Frame;
}

class Val;

using ValPtr = IntrusivePtr<Val>;

using ArgsSpan = Span<const ValPtr>;

namespace cluster::detail::bif {

class ScriptLocationScope {
public:
    ScriptLocationScope(const zeek::detail::Frame* frame);
    ~ScriptLocationScope();
};

/**
 * Publish helper.
 *
 * @param topic The topic to publish to. Should be a StringVal.
 * @param args The arguments to the BiF function. May either be a prepared event from make_event(),
 *  or a FuncValPtr and it's arguments
 *
 * @return A BoolValPtr that's true if the event was published, else false.
 */
zeek::ValPtr publish_event(const zeek::ValPtr& topic, zeek::ArgsSpan args);

} // namespace cluster::detail::bif

} // namespace zeek

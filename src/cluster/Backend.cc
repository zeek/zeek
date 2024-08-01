// See the file "COPYING" in the main distribution directory for copyright.

#include "Backend.h"

#include <iterator>

#include "zeek/Func.h"

using namespace zeek::cluster;

std::string_view detail::Event::HandlerName() const {
    if ( std::holds_alternative<FuncValPtr>(handler) )
        return std::get<FuncValPtr>(handler)->AsFunc()->Name();

    return std::get<EventHandlerPtr>(handler)->Name();
}

detail::Event Backend::MakeClusterEvent(FuncValPtr handler, ArgsIter first, ArgsIter last, double timestamp) const {
    return detail::Event{handler, zeek::Args(first, last), timestamp};
}

bool Backend::PublishEvent(const zeek::Args& args) {
    if ( args.size() < 2 ) {
        zeek::emit_builtin_error("publish expected at least 2 args");
        return false;
    }

    if ( args[0]->GetType()->Tag() != zeek::TYPE_STRING ) {
        zeek::emit_builtin_error("publish expects topic string");
        return false;
    }

    const auto& topic = cast_intrusive<zeek::StringVal>(args[0]);

    if ( args[1]->GetType()->Tag() == TYPE_FUNC ) {
        const auto& func = cast_intrusive<zeek::FuncVal>(args[1]);
        auto it = args.begin();
        std::advance(it, 2);
        auto ev = MakeClusterEvent(func, it, args.end());
        return PublishEvent(topic->ToStdString(), ev);
    }
    else {
        // args[1] is a ValPtr produced via Backend::MakeEvent().
        // The implementation should double check that's true.
        //
        // Deprecate this:
        zeek::reporter->Deprecation(zeek::util::fmt("don't do this this"));
        return PublishEvent(topic->ToStdString(), args[1]);
    }
}

// See the file "COPYING" in the main distribution directory for copyright.

#include "Backend.h"

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/Reporter.h"

using namespace zeek::cluster;

std::string_view detail::Event::HandlerName() const {
    if ( std::holds_alternative<FuncValPtr>(handler) )
        return std::get<FuncValPtr>(handler)->AsFunc()->Name();

    return std::get<EventHandlerPtr>(handler)->Name();
}

detail::Event Backend::MakeClusterEvent(FuncValPtr handler, ArgsSpan args, double timestamp) const {
    return detail::Event{handler, zeek::Args(args.begin(), args.end()), timestamp};
}

zeek::RecordValPtr Backend::MakeEvent(zeek::ArgsSpan args) {
    static const auto& any_vec_type = zeek::id::find_type<zeek::VectorType>("any_vec");
    static const auto& event_record_type = zeek::id::find_type<zeek::RecordType>("Cluster::Event");
    auto rec = zeek::make_intrusive<zeek::RecordVal>(event_record_type);

    if ( args.size() < 1 ) {
        zeek::reporter->Error("not enough arguments to make_event");
        return rec;
    }

    const auto& maybe_func_val = args[0];

    if ( maybe_func_val->GetType()->Tag() != zeek::TYPE_FUNC ) {
        zeek::reporter->Error("attempt to convert non-event into an event type (%s)",
                              zeek::obj_desc_short(maybe_func_val->GetType().get()).c_str());
        return rec;
    }

    const auto* func = maybe_func_val->AsFunc();
    const auto func_type = func->GetType();
    if ( func_type->Flavor() != zeek::FUNC_FLAVOR_EVENT ) {
        zeek::reporter->Error("attempt to convert non-event into an event type (%s)",
                              func_type->FlavorString().c_str());
        return rec;
    }


    const auto& types = func->GetType()->ParamList()->GetTypes();
    if ( args.size() - 1 != types.size() ) {
        zeek::reporter->Error("bad # of arguments: got %zu, expect %zu", args.size() - 1, types.size());
        return rec;
    }

    auto vec = zeek::make_intrusive<zeek::VectorVal>(any_vec_type);
    vec->Reserve(args.size() - 1);
    rec->Assign(0, maybe_func_val);

    for ( size_t i = 1; i < args.size(); i++ ) {
        const auto& a = args[i];
        const auto& got_type = a->GetType();
        const auto& expected_type = types[i - 1];

        if ( ! same_type(got_type, expected_type) ) {
            zeek::reporter->Error("event parameter #%zu type mismatch, got %s, expect %s", i - 1,
                                  zeek::obj_desc(got_type.get()).c_str(), zeek::obj_desc(expected_type.get()).c_str());
            return rec;
        }

        vec->Append(a);
    }

    rec->Assign(1, vec); // Args

    return rec;
}

bool Backend::PublishEvent(const std::string& topic, const zeek::ValPtr& event) {
    static const auto& event_record_type = zeek::id::find_type<zeek::RecordType>("Cluster::Event");
    if ( event->GetType() != event_record_type ) {
        zeek::emit_builtin_error(zeek::util::fmt("Wrong event type, expected '%s', got '%s'",
                                                 obj_desc(event->GetType().get()).c_str(),
                                                 obj_desc(event_record_type.get()).c_str()));
        return false;
    }

    const auto& rec = cast_intrusive<zeek::RecordVal>(event);
    const auto& func = rec->GetField<zeek::FuncVal>(0);
    const auto& vargs = rec->GetField<VectorVal>(1);
    zeek::Args args(vargs->Size());
    for ( size_t i = 0; i < vargs->Size(); i++ )
        args[i] = vargs->ValAt(i);

    auto ev = cluster::detail::Event(func, std::move(args));

    return PublishEvent(topic, ev);
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
        zeek::ArgsSpan span{args};
        auto ev = MakeClusterEvent(func, span.subspan(2));
        return PublishEvent(topic->ToStdString(), ev);
    }
    else {
        return PublishEvent(topic->ToStdString(), args[1]);
    }
}

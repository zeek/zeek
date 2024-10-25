#include "BifSupport.h"

#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/RunState.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/cluster/Backend.h"

namespace zeek::cluster::detail::bif {

zeek::ValPtr publish_event(const zeek::ValPtr& topic, zeek::ArgsSpan args) {
    std::fprintf(stderr, "publish helper\n");

    if ( args.empty() ) {
        zeek::emit_builtin_error("no event arguments given");
        return zeek::val_mgr->False();
    }

    if ( topic->GetType()->Tag() != zeek::TYPE_STRING ) {
        zeek::emit_builtin_error("topic is a string");
        return zeek::val_mgr->False();
    }

    const auto topic_str = topic->AsStringVal()->ToStdString();
    bool result = false;

    if ( args[0]->GetType()->Tag() == zeek::TYPE_FUNC ) {
        auto event = zeek::cluster::backend->MakeClusterEvent({zeek::NewRef{}, args[0]->AsFuncVal()}, args.subspan(1),
                                                              zeek::run_state::network_time);
        result = zeek::cluster::backend->PublishEvent(topic_str, event);
    }
    else if ( args[0]->GetType()->Tag() == zeek::TYPE_RECORD ) {
        result = zeek::cluster::backend->PublishEvent(topic_str, zeek::cast_intrusive<zeek::RecordVal>(args[0]));
    }
    else {
        result = false;
        zeek::emit_builtin_error("publish second argument neither function nor record");
    }

    return zeek::val_mgr->Bool(true);
}
} // namespace zeek::cluster::detail::bif

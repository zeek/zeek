// See the file "COPYING" in the main distribution directory for copyright.
//
#include "zeek/cluster/PublishOnChange.h"

#include <cstdio>
#include <memory>
#include <optional>

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/Timer.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/cluster/Backend.h"
#include "zeek/types.bif.netvar_h"

#include "Attr.h"
#include "IntrusivePtr.h"
#include "Scope.h"
#include "Type.h"

namespace {

// Receives the set[TableChange] value and returns it as a bitmask.
uint8_t changes_to_bitmask(const zeek::TableVal& changes) {
    using zeek::detail::TableChange;
    uint8_t result = 0;

    for ( const auto& [k, _] : changes.ToMap() ) {
        assert(k->GetType()->Tag() == zeek::TYPE_LIST);
        assert(k->AsListVal()->Length() == 1);

        // Map contains ListVal of size 1 as key.
        switch ( k->AsListVal()->Idx(0)->AsEnum() ) {
            case zeek::BifEnum::TABLE_ELEMENT_NEW: {
                result |= TableChange::New;
                break;
            }
            case zeek::BifEnum::TABLE_ELEMENT_CHANGED: {
                result |= TableChange::Changed;
                break;
            }
            case zeek::BifEnum::TABLE_ELEMENT_REMOVED: {
                result |= TableChange::Removed;
                break;
            }
            case zeek::BifEnum::TABLE_ELEMENT_EXPIRED: {
                result |= TableChange::Expired;
                break;
            }
            default: zeek::reporter->InternalError("unexpected enum value for TableChange %" PRId64, k->AsEnum());
        }
    }

    return result;
}

zeek::VectorValPtr key_to_vec(zeek::ListVal& lv) {
    static const auto& any_vec_type = zeek::id::find_type<zeek::VectorType>("any_vec");

    auto key_vec = zeek::make_intrusive<zeek::VectorVal>(any_vec_type);
    key_vec->Reserve(lv.Length());

    for ( int i = 0; i < lv.Length(); i++ )
        key_vec->Append(lv.Idx(i));

    return key_vec;
}

// Check if the index of tv matches the arguments of ft.
bool topic_func_is_ok(const zeek::TableVal& tv, const zeek::Func& f) {
    const auto& index_types = tv.GetType<zeek::TableType>()->GetIndexTypes();
    const auto& arg_types = f.GetType()->ParamList()->GetTypes();
    const auto& yield_type = f.GetType()->Yield();

    if ( ! yield_type || yield_type->Tag() != zeek::TYPE_STRING )
        return false;

    if ( index_types.size() != arg_types.size() )
        return false;

    for ( size_t i = 0; i < index_types.size(); i++ ) {
        if ( ! zeek::same_type(index_types[i], arg_types[i]) )
            return false;
    }

    return true;
}

using zeek::detail::PublishOnChangeState;
using zeek::detail::Timer;
using zeek::detail::TIMER_TABLE_PUBLISH_QUEUED_CHANGES;

class PublishQueuedChangesTimer : public Timer {
public:
    PublishQueuedChangesTimer(double t, zeek::detail::PublishOnChangeState* state)
        : Timer(t, TIMER_TABLE_PUBLISH_QUEUED_CHANGES), state(state) {}

    void Dispatch(double t, bool is_expire) override {
        state->ResetTimer();
        state->PublishQueuedChanges(t);
    }

private:
    PublishOnChangeState* state;
};

} // namespace

namespace zeek::detail {

PublishOnChangeState::PublishOnChangeState(const TableVal* table_val, uint8_t change_mask,
                                           std::optional<std::string> topic, FuncPtr topic_func, size_t max_batch_size,
                                           double max_batch_delay)
    : table_val(table_val),
      change_mask(change_mask),
      topic(std::move(topic)),
      topic_func(std::move(topic_func)),
      max_batch_size(max_batch_size),
      max_batch_delay(max_batch_delay) {}


PublishOnChangeState::~PublishOnChangeState() = default;


void PublishOnChangeState::QueueChange(TableChange tc, const ValPtr& key, const ValPtr& value,
                                       const ValPtr& previous_value) {
    // Static type and field offsets.
    static const auto table_change_info = zeek::id::find_type<zeek::RecordType>("Cluster::Table::TableChangeInfo");
    static const auto table_change_infos = zeek::id::find_type<zeek::VectorType>("Cluster::Table::TableChangeInfos");
    static const auto change_new = zeek::id::find("TABLE_ELEMENT_NEW")->GetVal();
    static const auto change_changed = zeek::id::find("TABLE_ELEMENT_CHANGED")->GetVal();
    static const auto change_removed = zeek::id::find("TABLE_ELEMENT_REMOVED")->GetVal();
    static const auto change_expired = zeek::id::find("TABLE_ELEMENT_EXPIRED")->GetVal();

    static const int change_offset = table_change_info->FieldOffset("change");
    static const int key_offset = table_change_info->FieldOffset("key");
    static const int value_offset = table_change_info->FieldOffset("value");
    static const int previous_value_offset = table_change_info->FieldOffset("previous_value");

    // Initialize the topic once, unless there's a topic_func given.
    if ( ! topic_func && ! topic.has_value() ) {
        const auto* loc = table_val->GetLocationInfo();
        std::string loc_str = zeek::util::fmt("%s:%d", loc->FileName(), loc->FirstLine());
        zeek::reporter->InternalError("No topic for table with &publish_on_change at %s", loc_str.c_str());
    }

    ValPtr change;
    switch ( tc ) {
        case detail::TableChange::New: change = change_new; break;
        case detail::TableChange::Changed: change = change_changed; break;
        case detail::TableChange::Removed: change = change_removed; break;
        case detail::TableChange::Expired: change = change_expired; break;
        default: zeek::reporter->InternalError("invalid TableChange %d", static_cast<int>(tc));
    }

    auto rv = zeek::make_intrusive<zeek::RecordVal>(table_change_info);
    rv->Assign(change_offset, change);
    rv->Assign(key_offset, key_to_vec(*key->AsListVal()));
    rv->Assign(value_offset, value->Clone());

    if ( previous_value )
        rv->Assign(previous_value_offset, previous_value->Clone());

    std::string effective_topic;
    std::string* topic_ptr;

    if ( topic.has_value() )
        topic_ptr = &(*topic);
    else {
        // Invoke topic_func!
        effective_topic = "blub blub";
        topic_ptr = &effective_topic;
    }

    auto it = queued_changes.find(*topic_ptr);
    if ( it == queued_changes.end() ) {
        zeek::VectorValPtr change_infos = zeek::make_intrusive<zeek::VectorVal>(table_change_infos);
        const auto [nit, inserted] = queued_changes.emplace(*topic_ptr, std::move(change_infos));
        assert(inserted);
        it = nit;
    }


    queued_changes_total++;
    it->second->Append(std::move(rv));

    auto now = run_state::network_time;

    // NOLINTBEGIN(bugprone-branch-clone)
    if ( max_batch_delay == 0.0 || max_batch_size == 0 ) {
        PublishQueuedChanges(now);
    }
    else if ( (now - last_publish_ts) > max_batch_delay ) {
        PublishQueuedChanges(now);
    }
    else if ( queued_changes_total >= max_batch_size ) {
        PublishQueuedChanges(now);
    }
    // NOLINTEND(bugprone-branch-clone)
    else {
        // If we get here, we're actually queueing the change.
        if ( ! timer )
            timer = ArmTimer(now);
    }
}

void PublishOnChangeState::PublishQueuedChanges(double now) {
    std::fprintf(stderr, "flush flush! queued_changes=%zu %x %zu %.3f\n", queued_changes_total, change_mask,
                 max_batch_size, max_batch_delay);
    if ( timer )
        detail::timer_mgr->Cancel(timer);

    for ( const auto& [topic, vector] : queued_changes ) {
        std::fprintf(stderr, "publish to %s (%u)\n", topic.c_str(), vector->Size());
        // zeek::cluster::Event ev{};
        //         zeek::cluster::backend->PublishEvent(topic, ev);
    }

    last_publish_ts = now;
    queued_changes_total = 0;
}

detail::Timer* PublishOnChangeState::ArmTimer(double now) {
    auto* timer = new PublishQueuedChangesTimer(now + max_batch_delay, this);
    detail::timer_mgr->Add(timer);
    return timer;
}

std::unique_ptr<PublishOnChangeState> PublishOnChangeState::FromRecord(const TableVal* table_val,
                                                                       const zeek::RecordVal& rec) {
    // Static type and field offsets.
    static const auto poc_attr_type = zeek::id::find_type<zeek::RecordType>("Cluster::Table::PublishOnChangeAttr");

    static const int changes_offset = poc_attr_type->FieldOffset("changes");
    static const int topic_offset = poc_attr_type->FieldOffset("topic");
    static const int topic_func_offset = poc_attr_type->FieldOffset("topic_func");
    static const int max_batch_size_offset = poc_attr_type->FieldOffset("max_batch_size");
    static const int max_batch_delay_offset = poc_attr_type->FieldOffset("max_batch_delay");

    if ( rec.GetType() != poc_attr_type )
        zeek::reporter->InternalError("got %s instead of %s", obj_desc_short(rec.GetType()).c_str(),
                                      obj_desc_short(poc_attr_type).c_str());

    const auto changes = rec.GetField<zeek::TableVal>(changes_offset);
    assert(changes->IsSet());
    assert(changes->GetType<zeek::TableType>()->GetIndexTypes().size() == 1);

    uint8_t change_mask = changes_to_bitmask(*changes);

    std::optional<std::string> topic;
    FuncPtr topic_func;

    if ( rec.HasField(topic_offset) && ! rec.HasField(topic_func_offset) )
        topic = rec.GetField<zeek::StringVal>(topic_offset)->ToStdString();
    else if ( rec.HasField(topic_func_offset) && ! rec.HasField(topic_offset) ) {
        topic_func = rec.GetField<FuncVal>(topic_func_offset)->AsFuncPtr();

        if ( ! topic_func_is_ok(*table_val, *topic_func) )
            zeek::reporter->Error("topic_func %s not applicable for %s", obj_desc_short(topic_func->GetType()).c_str(),
                                  obj_desc_short(table_val->GetType()).c_str());
        topic_func = nullptr;
    }
    else if ( ! rec.HasField(topic_offset) && ! rec.HasField(topic_func_offset) )
        // Actual topic will be determined during InitPostScript() and populated
        // via SetTopic(). See below in static InitPostScript() function.
        topic = std::nullopt;
    else
        rec.Error("only one of topic or topic_func can be set for &publish_on_change");

    zeek_uint_t max_batch_size = rec.GetField<zeek::CountVal>(max_batch_size_offset)->AsCount();
    double max_batch_delay = rec.GetField<zeek::IntervalVal>(max_batch_delay_offset)->AsInterval();

    return std::make_unique<PublishOnChangeState>(table_val, change_mask, std::move(topic), std::move(topic_func),
                                                  max_batch_size, max_batch_delay);
}

void PublishOnChangeState::InitPostScript() {
    // Find all top-level global tables with the &publish_on_change attribute.
    for ( const auto& [name, id] : global_scope()->Vars() ) {
        if ( ! id->GetAttr(zeek::detail::ATTR_PUBLISH_ON_CHANGE) )
            continue;

        if ( id->GetType()->Tag() != TYPE_TABLE )
            zeek::reporter->InternalError("&publish_on_change attribute on non-table?");

        auto tval = zeek::cast_intrusive<zeek::TableVal>(id->GetVal());

        auto* poc_state = tval->GetPublishOnChangeState();
        if ( ! poc_state )
            continue;

        // topic or topic_func already set? This happens when they were
        // explicitly provided by the user.
        if ( poc_state->GetTopic().has_value() || poc_state->GetTopicFunc() )
            continue;

        // Hard-code the default topic here.
        //
        // TODO: Make this a callback? Worth it? The topic
        // separator would be good to extract as Broker has
        // traditionally used "/", where NATS and ZeroMQ
        // lean towards "." and it shouldn't matter anyhow.
        const char* topic_sep = "/";
        std::string topic = util::fmt("zeek%stable%s%s%s", topic_sep, topic_sep, name.c_str(), topic_sep);
        poc_state->SetTopic(std::move(topic));
    }
}

} // namespace zeek::detail

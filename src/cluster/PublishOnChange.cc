// See the file "COPYING" in the main distribution directory for copyright.
//
#include "zeek/cluster/PublishOnChange.h"

#include <cstdio>
#include <optional>

#include "zeek/Attr.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/Timer.h"
#include "zeek/Type.h"
#include "zeek/Val.h"
#include "zeek/broker/Data.h" // for data_to_val()
#include "zeek/cluster/Backend.h"
#include "zeek/types.bif.netvar_h"

namespace {

// Receives the set[TableChange] value and returns it as a bitmask.
uint8_t changes_to_bitmask(const zeek::TableVal& changes) {
    using zeek::detail::TableChangeBits;
    uint8_t result = 0;

    for ( const auto& [k, _] : changes.ToMap() ) {
        assert(k->GetType()->Tag() == zeek::TYPE_LIST);
        assert(k->AsListVal()->Length() == 1);

        // Map contains ListVal of size 1 as key.
        switch ( k->AsListVal()->Idx(0)->AsEnum() ) {
            case zeek::BifEnum::TABLE_ELEMENT_NEW: {
                result |= TableChangeBits::New;
                break;
            }
            case zeek::BifEnum::TABLE_ELEMENT_CHANGED: {
                result |= TableChangeBits::Changed;
                break;
            }
            case zeek::BifEnum::TABLE_ELEMENT_REMOVED: {
                result |= TableChangeBits::Removed;
                break;
            }
            case zeek::BifEnum::TABLE_ELEMENT_EXPIRED: {
                result |= TableChangeBits::Expired;
                break;
            }
            default: zeek::reporter->InternalError("unexpected enum value for TableChange %" PRId64, k->AsEnum());
        }
    }

    return result;
}

// Convert a key in ListVal form (from a TableVal) to a anyvec
zeek::VectorValPtr listval_to_anyvec(const zeek::ListVal& lv) {
    static const auto& any_vec_type = zeek::id::find_type<zeek::VectorType>("any_vec");

    auto index_vec = zeek::make_intrusive<zeek::VectorVal>(any_vec_type);
    index_vec->Reserve(lv.Length());

    for ( int i = 0; i < lv.Length(); i++ )
        index_vec->Append(lv.Idx(i));

    return index_vec;
}


// Helper to convert a received any value (which might be wrapped by Broker::Data) to a ValPtr
//
// Broker unserialization wraps any values into the opaque Broker::Data type. This helper
// unwraps that and converts to the correct type t.
zeek::ValPtr maybe_unwrap_broker_data(zeek::Type& t, zeek::Val* any) {
    zeek::ValPtr ret;
    if ( any->GetType() == zeek::Broker::detail::DataVal::ScriptDataType() ) {
        auto ov = any->AsRecordVal()->GetField<zeek::OpaqueVal>(0);
        if ( ov->GetType() != zeek::Broker::detail::opaque_of_data_type ) {
            zeek::reporter->Error("PublishOnChange: bad broker::data wrapping: %s",
                                  zeek::obj_desc_short(ov->GetType()).c_str());
            return nullptr;
        }

        auto* data_val = static_cast<zeek::Broker::detail::DataVal*>(ov.get());

        if ( ! data_val->canCastTo(&t) ) {
            zeek::reporter->Error("PublishOnChange: cannot cast %s to %s", broker::to_string(data_val->data).c_str(),
                                  zeek::obj_desc_short(&t).c_str());
            return nullptr;
        }

        return data_val->castTo(&t);
    }

    return zeek::IntrusivePtr(zeek::NewRef{}, any);
}

// Convert a VectorVal raw vector holding ZVals to a ListValPtr for TableVal operations.
zeek::ListValPtr raw_vec_to_listval(zeek::TypeListPtr tl, const std::vector<std::optional<zeek::ZVal>>& raw_vec) {
    std::vector<zeek::ValPtr> index_vals;

    const auto& types = tl->GetTypes();
    index_vals.reserve(raw_vec.size());

    for ( size_t i = 0; i < raw_vec.size(); i++ ) {
        const auto& typ = tl->IsPure() ? tl->GetPureType() : types[i];

        // This shouldn't happen and will likely only cause trouble downstream.
        if ( ! raw_vec[i].has_value() ) {
            zeek::reporter->InternalWarning("PublishOnChange::raw_vec_to_listval: Unset raw_vec %zu", i);
            return nullptr;
        }

        // The index is a vector of any and right now that means the Broker::DataVal type is used :-(
        zeek::Val* index_any_i = raw_vec[i]->AsAny();
        zeek::ValPtr index_i = maybe_unwrap_broker_data(*typ, index_any_i);
        if ( ! index_i ) {
            zeek::reporter->InternalWarning("PublishOnChange::raw_vec_to_listval: failed to unwrap %zu", i);
            return nullptr;
        }

        index_vals.emplace_back(index_i);
    }

    return zeek::make_intrusive<zeek::ListVal>(std::move(tl), std::move(index_vals));
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

/**
 * Per table timer for any queued changes to be published. Owned by PublishOnChangeState.
 */
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

/**
 * Just a helper struct with information about TableChangeInfo and TableChangeInfos
 */
struct RecordInfo {
    zeek::RecordTypePtr table_change_info;
    zeek::VectorTypePtr table_change_infos;

    int change_offset = -1;
    int ts_offset = -1;
    int index_offset = -1;
    int value_offset = -1;
    int previous_value_offset = -1;
};

RecordInfo init_record_info() {
    auto table_change_info = zeek::id::find_type<zeek::RecordType>("Cluster::Table::TableChangeInfo");
    auto table_change_infos = zeek::id::find_type<zeek::VectorType>("Cluster::Table::TableChangeInfos");
    int change_offset = table_change_info->FieldOffset("change");
    int ts_offset = table_change_info->FieldOffset("ts");
    int index_offset = table_change_info->FieldOffset("index");
    int value_offset = table_change_info->FieldOffset("value");
    int previous_value_offset = table_change_info->FieldOffset("previous_value");

    if ( ! table_change_info || ! table_change_infos )
        zeek::reporter->InternalError("lookup failed table_change_info=%p table_change_infos=%p",
                                      table_change_info.get(), table_change_infos.get());

    if ( change_offset < 0 || ts_offset < 0 || index_offset < 0 || value_offset < 0 || previous_value_offset < 0 )
        zeek::reporter->InternalError("offset lookup failed change=%d ts=%d index=%d value=%d previous_value=%d",
                                      change_offset, ts_offset, index_offset, value_offset, previous_value_offset);

    return {
        .table_change_info = table_change_info,
        .table_change_infos = table_change_infos,
        .change_offset = change_offset,
        .ts_offset = ts_offset,
        .index_offset = index_offset,
        .value_offset = value_offset,
        .previous_value_offset = previous_value_offset,
    };
}


} // namespace

/*
#define debug(fmt, ...)                                                                                                \
    do {                                                                                                               \
        DBG_LOG(DBG_CLUSTER, fmt, __VA_ARGS__)                                                                         \
    } while ( 0 )
     */

#define debug(fmt, ...)                                                                                                \
    do {                                                                                                               \
        fprintf(stderr, "publish_on_change: ");                                                                        \
        fprintf(stderr, fmt, __VA_ARGS__);                                                                             \
        fprintf(stderr, "\n");                                                                                         \
    } while ( 0 )


namespace zeek::detail {

PublishOnChangeState::PublishOnChangeState(TableVal* table_val, uint8_t change_mask, std::optional<std::string> topic,
                                           FuncPtr topic_func, size_t max_batch_size, double max_batch_delay,
                                           EventHandlerPtr eh)
    : change_mask(change_mask),
      topic(std::move(topic)),
      topic_func(std::move(topic_func)),
      max_batch_size(max_batch_size),
      max_batch_delay(max_batch_delay),
      table_val(table_val),
      event_handler(std::move(eh)) {}


PublishOnChangeState::~PublishOnChangeState() = default;


void PublishOnChangeState::QueueChange(TableChangeBits tc, const Val& index, const ValPtr& value,
                                       const ValPtr& previous_value) {
    // Static type and field offsets.
    static const auto ri = init_record_info();

    // Enum values.
    static const auto change_new = id::find("TABLE_ELEMENT_NEW")->GetVal()->AsEnum();
    static const auto change_changed = id::find("TABLE_ELEMENT_CHANGED")->GetVal()->AsEnum();
    static const auto change_removed = id::find("TABLE_ELEMENT_REMOVED")->GetVal()->AsEnum();
    static const auto change_expired = id::find("TABLE_ELEMENT_EXPIRED")->GetVal()->AsEnum();


    // Initialize the topic once, unless there's a topic_func given.
    if ( ! topic_func && ! topic.has_value() ) {
        const auto* loc = table_val->GetLocationInfo();
        std::string loc_str = util::fmt("%s:%d", loc->FileName(), loc->FirstLine());
        reporter->InternalError("No topic for table with &publish_on_change at %s", loc_str.c_str());
    }

    auto now = run_state::network_time;

    // Convert from the bitmask style detail::TableChange to the BifEnum::TableChange.
    zeek_int_t change;
    switch ( tc ) {
        case detail::TableChangeBits::New: change = change_new; break;
        case detail::TableChangeBits::Changed: change = change_changed; break;
        case detail::TableChangeBits::Removed: change = change_removed; break;
        case detail::TableChangeBits::Expired: change = change_expired; break;
        default: reporter->InternalError("invalid TableChange %d", static_cast<int>(tc));
    }

    // Build the TableChangeInfo record to be queued.
    auto rv = make_intrusive<RecordVal>(ri.table_change_info);
    rv->Assign(ri.change_offset, change);
    rv->AssignTime(ri.ts_offset, now);
    rv->Assign(ri.index_offset, listval_to_anyvec(*index.AsListVal()));
    if ( value )
        rv->Assign(ri.value_offset, value->Clone());
    if ( previous_value )
        rv->Assign(ri.previous_value_offset, previous_value->Clone());

    // Figure out the topic name to use.
    std::string effective_topic;
    std::string* topic_ptr;

    if ( topic.has_value() )
        topic_ptr = &(*topic);
    else if ( topic_func ) {
        const auto* lv = index.AsListVal();
        zeek::Args args;
        args.reserve(lv->Length());
        for ( int i = 0; i < lv->Length(); i++ )
            args.emplace_back(lv->Idx(i));

        auto result = topic_func->Invoke(&args);
        if ( ! result || result->GetType()->Tag() != TYPE_STRING ) {
            zeek::reporter->Error("PublishOnChange: Failed to call topic_func %s for %s (result=%s)",
                                  obj_desc_short(topic_func).c_str(), identifier->ToStdString().c_str(),
                                  result ? obj_desc_short(result).c_str() : "nil");
            return;
        }

        effective_topic = result->AsStringVal()->ToStdString();
        topic_ptr = &effective_topic;
    }
    else {
        zeek::reporter->InternalError("Neither topic nor topic_func set for %s", identifier->ToStdString().c_str());
    }

    debug("QueueChange %ld index=%s value=%p %s", change, obj_desc_short(&index).c_str(), value.get(),
          value ? obj_desc_short(value).c_str() : "<no value>");

    // Find the queue for the topic, or create a new one.
    auto it = queued_changes.find(*topic_ptr);
    if ( it == queued_changes.end() ) {
        VectorValPtr change_infos = make_intrusive<VectorVal>(ri.table_change_infos);
        const auto [nit, inserted] = queued_changes.emplace(*topic_ptr, std::move(change_infos));
        assert(inserted);
        it = nit;
    }

    // Append the TableChangeInfo record to the queue.
    if ( ! it->second->Append(rv) )
        reporter->InternalError("failed to append change to queue: %s %s", obj_desc_short(rv).c_str(),
                                obj_desc_short(it->second->GetType()).c_str());

    queued_changes_total++;

    // Figure out if we should publish immediately:
    //
    // 1) Batching or delaying is disabled
    // 2) The last publish operation was longer than max_batch_delay ago.
    // 3) The max_batch_size has been reached.
    //
    // Otherwise, arm the timer for delayed publishing based
    // on the last_publish_ts.
    //
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
            timer = ArmPublishTimer(last_publish_ts);
    }
}

void PublishOnChangeState::PublishQueuedChanges(double now) {
    // Unconditionally cancel the timer if it is set.
    CancelPublishTimer();

    debug("Publishing to %zu topics (total=%zu)", queued_changes.size(), queued_changes_total);

    for ( const auto& [topic, table_change_infos] : queued_changes ) {
        debug("Publish event %s to topic %s table_change_infos=%u", event_handler->Name(), topic.c_str(),
              table_change_infos->Size());

        auto ts = make_intrusive<TimeVal>(now);
        Args args{identifier, ts, std::move(table_change_infos)};

        detail::EventMetadataVectorPtr meta;
        if ( BifConst::EventMetadata::add_network_timestamp )
            meta = detail::MakeEventMetadataVector(now);

        cluster::Event ev{event_handler, std::move(args), std::move(meta)};
        if ( ! cluster::backend->PublishEvent(topic, ev) ) {
            reporter->InternalError("PublishOnChange: PublishEvent() failed");
        }
    }

    last_publish_ts = now;
    queued_changes_total = 0;
    queued_changes.clear();
}

void PublishOnChangeState::ApplyChanges(double ts, const VectorVal& table_change_infos) {
    static const auto ri = init_record_info();

    // Set the in_apply_changes member to true such that OnChange() short-circuits
    // while processing incoming changes. Resets to false when leaving.
    InApplyChangesScope scope(this);

    const auto& raw_vec = table_change_infos.RawVec();

    for ( size_t i = 0; i < table_change_infos.Size(); i++ ) {
        const auto& cr = raw_vec[i]->AsRecord();

        auto change = cr->GetFieldAs<zeek::EnumVal>(ri.change_offset);
        auto index_raw_vec = cr->GetFieldAs<zeek::VectorVal>(ri.index_offset)->RawVec();

        ValPtr index = raw_vec_to_listval(table_val->GetType()->AsTableType()->GetIndices(), index_raw_vec);
        if ( ! index ) {
            zeek::reporter->InternalWarning("PublishOnChange: failed to create index (change=%ld i=%zu identifier=%s)",
                                            change, i, identifier->ToStdString().c_str());
            continue;
        }

        ValPtr value;
        if ( cr->HasField(ri.value_offset) ) {
            // Don't expect values for sets.
            value = cr->GetField(ri.value_offset);

            if ( table_val->GetType()->IsSet() ) {
                zeek::reporter->InternalWarning(
                    "PublishOnChange: unexpected value for set (index=%s value=%s change=%ld i=%zu identifier=%s)",
                    obj_desc_short(index).c_str(), obj_desc_short(value).c_str(), change, i,
                    identifier->ToStdString().c_str());

                continue;
            }

            value = maybe_unwrap_broker_data(*table_val->GetType()->Yield(), cr->GetField(ri.value_offset).get());
        }

        // We don't use previous_value at this point. It's mostly for users that want to do fancy
        // stuff with the apply_table_change_infos_policy hook.
        if ( cr->HasField(ri.previous_value_offset) ) {
            // Don't expect previous values when the element is new, removed or expired.
            if ( change == BifEnum::TABLE_ELEMENT_NEW || change == BifEnum::TABLE_ELEMENT_REMOVED ||
                 change == BifEnum::TABLE_ELEMENT_EXPIRED ) {
                zeek::reporter->InternalWarning(
                    "PublishOnChange: unexpected previous value (index=%s value=%s change=%ld i=%zu identifier=%s)",
                    obj_desc_short(index).c_str(), obj_desc_short(value).c_str(), change, i,
                    identifier->ToStdString().c_str());

                continue;
            }
        }

        // Apply the change to the table.
        switch ( static_cast<BifEnum::TableChange>(change) ) {
            case BifEnum::TABLE_ELEMENT_NEW:
            case BifEnum::TABLE_ELEMENT_CHANGED:
                debug("assigning %s %s (change=%ld)", obj_desc_short(index).c_str(),
                      value ? obj_desc_short(value).c_str() : "<no value>", change);

                table_val->Assign(index, value, /*broker_forward=*/false, /*iterators_invalidated=*/nullptr);

                break;

            case BifEnum::TABLE_ELEMENT_REMOVED:
                debug("removing %s (change=%ld)", obj_desc_short(index).c_str(), change);
                table_val->Remove(*index, /*broker_forward=*/false, /*iterators_invalidated=*/nullptr);
                break;

            default:
                zeek::reporter->InternalWarning(
                    "PublishOnChange: unexpected change (index=%s value=%s change=%ld i=%zu identifier=%s)",
                    obj_desc_short(index).c_str(), value ? obj_desc_short(value).c_str() : "<no value>", change, i,
                    identifier->ToStdString().c_str());
        }
    }
}

zeek::detail::Timer* PublishOnChangeState::ArmPublishTimer(double from) {
    auto* new_timer = new PublishQueuedChangesTimer(from + max_batch_delay, this);
    detail::timer_mgr->Add(new_timer);
    return new_timer;
}

void PublishOnChangeState::CancelPublishTimer() {
    if ( timer ) {
        debug("cancelling publish timer %p", timer);
        detail::timer_mgr->Cancel(timer);
        timer = nullptr;
    }
}

void PublishOnChangeState::SetIdentifier(const std::string& id) { identifier = make_intrusive<StringVal>(id); }

std::unique_ptr<PublishOnChangeState> PublishOnChangeState::FromRecord(TableVal* table_val, const RecordVal& rec) {
    // Static type and field offsets.
    static const auto poc_attr_type = id::find_type<RecordType>("Cluster::Table::PublishOnChangeAttr");
    static const int changes_offset = poc_attr_type->FieldOffset("changes");
    static const int topic_offset = poc_attr_type->FieldOffset("topic");
    static const int topic_func_offset = poc_attr_type->FieldOffset("topic_func");
    static const int max_batch_size_offset = poc_attr_type->FieldOffset("max_batch_size");
    static const int max_batch_delay_offset = poc_attr_type->FieldOffset("max_batch_delay");

    // The event handler that's used for publishing.
    static auto eh = event_registry->Register("Cluster::Table::table_change_infos_internal");
    if ( ! eh.Ptr() )
        reporter->InternalError("could not find event for &publish_on_change");

    if ( rec.GetType() != poc_attr_type )
        reporter->InternalError("got %s instead of %s", obj_desc_short(rec.GetType()).c_str(),
                                obj_desc_short(poc_attr_type).c_str());

    const auto changes = rec.GetField<TableVal>(changes_offset);
    assert(changes->GetType()->IsSet());
    assert(changes->GetType<TableType>()->GetIndexTypes().size() == 1);

    uint8_t change_mask = changes_to_bitmask(*changes);

    std::optional<std::string> topic;
    FuncPtr topic_func;

    if ( rec.HasField(topic_offset) && ! rec.HasField(topic_func_offset) )
        topic = rec.GetField<StringVal>(topic_offset)->ToStdString();
    else if ( rec.HasField(topic_func_offset) && ! rec.HasField(topic_offset) ) {
        if ( rec.GetField(topic_func_offset)->GetType()->Tag() == TYPE_FUNC ) {
            topic_func = rec.GetField<FuncVal>(topic_func_offset)->AsFuncPtr();

            if ( ! topic_func_is_ok(*table_val, *topic_func) ) {
                reporter->Error("topic_func %s not applicable for table type %s",
                                obj_desc_short(topic_func->GetType()).c_str(),
                                obj_desc_short(table_val->GetType()).c_str());
                topic_func = nullptr;
            }
        }
        else {
            rec.Error("topic_func is not a function");
        }
    }
    else if ( ! rec.HasField(topic_offset) && ! rec.HasField(topic_func_offset) )
        // Actual topic will be determined during InitPostScript() and populated
        // via SetTopic(). See below in static InitPostScript() function.
        topic = std::nullopt;
    else
        rec.Error("only one of topic or topic_func can be set for &publish_on_change");

    zeek_uint_t max_batch_size = rec.GetField<CountVal>(max_batch_size_offset)->AsCount();
    double max_batch_delay = rec.GetField<IntervalVal>(max_batch_delay_offset)->AsInterval();

    return std::make_unique<PublishOnChangeState>(table_val, change_mask, std::move(topic), std::move(topic_func),
                                                  max_batch_size, max_batch_delay, eh);
}

void PublishOnChangeState::InitPostScript() {
    // Find all top-level global tables with the &publish_on_change attribute.
    for ( const auto& [name, id] : global_scope()->Vars() ) {
        if ( ! id->GetAttr(detail::ATTR_PUBLISH_ON_CHANGE) )
            continue;

        if ( id->GetType()->Tag() != TYPE_TABLE )
            reporter->InternalError("&publish_on_change attribute on non-table?");

        auto tval = cast_intrusive<TableVal>(id->GetVal());

        auto* poc_state = tval->GetPublishOnChangeState();
        if ( ! poc_state )
            continue;

        // Configure the table's identifier.
        poc_state->SetIdentifier(name);

        // topic or topic_func already set? This happens when they were
        // explicitly provided by the user via the record passed to
        // &publish_on_change record.
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

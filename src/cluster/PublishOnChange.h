// See the file "COPYING" in the main distribution directory for copyright.

// Functionality to support &publish_on_change on tables and sets.

#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include "zeek/EventHandler.h"
#include "zeek/IntrusivePtr.h"

namespace zeek {

class Func;
class StringVal;
class RecordVal;
class TableVal;
class Val;
class VectorVal;

using FuncPtr = IntrusivePtr<Func>;
using StringValPtr = IntrusivePtr<StringVal>;
using ValPtr = IntrusivePtr<Val>;
using VectorValPtr = IntrusivePtr<VectorVal>;

namespace detail {

class Timer;

/**
 * Separate TableChange enum where the values are usable in a bitmask.
 */
enum class TableChangeBits : uint8_t {
    New = 1,
    Changed = 1 << 1,
    Removed = 1 << 2,
    Expired = 1 << 3,
};

constexpr uint8_t operator&(uint8_t mask, TableChangeBits v) { return (static_cast<uint8_t>(v) & mask); }

constexpr uint8_t operator|=(uint8_t& mask, TableChangeBits v) {
    mask = static_cast<uint8_t>(v) | mask;
    return mask;
}


class PublishOnChangeState {
public:
    /**
     * Constructor.
     */
    PublishOnChangeState(TableVal* tv, uint8_t change_mask, std::optional<std::string> topic, FuncPtr topic_func,
                         size_t max_batch_size, double max_batch_delay, EventHandlerPtr eh);

    /**
     * Destructor.
     */
    virtual ~PublishOnChangeState();

    /**
     * This method receives all changes done to a TableVal and queues
     * those changes that pass the changes_bitmask.
     *
     * If the change happens while ApplyChanges() is active, this method
     * short-circuits.
     *
     * @param tc
     * @param index
     * @param value
     * @param previous_value
     */
    void OnChange(TableChangeBits change, const Val& index, const ValPtr& value, const ValPtr& previous_value) {
        // If this change is happening due to running ApplyChanges() right now, do not queue the change.
        if ( in_apply_changes )
            return;

        if ( change_mask & change )
            QueueChange(change, index, value, previous_value);
    }

    /**
     * Queue a change for publishing.
     *
     * The key is expected to be a ListVal that will be converted to a vector of any
     * for transporting in an event.
     *
     * If the max_batch_size parameters is reached during queueing, the batch
     * of table changes is publishes using PublishQueuedChanges().
     *
     * If the provided value or previous_value is complex it is cloned such that
     * any subsequent modifications to these from script-land (in case of complex types)
     * are not visible during a delayed publish operation.
     *
     * @param tc
     * @param index  A ListVal representing the index where the change happens
     * @param value
     * @param previous_value
     */
    void QueueChange(TableChangeBits tc, const Val& index, const ValPtr& value, const ValPtr& previous_value);

    /**
     * Publish all queued changes and update last_publish_ts to \a now.
     *
     * @param now The current network time.
     */
    void PublishQueuedChanges(double now);

    /**
     * Apply all changes from TableChangeInfos vector.
     *
     * @param ts The explicit timestamp field from the event parameter.
     * @param changes: TableChangeInfos vector containing all changes to be applied.
     */
    void ApplyChanges(double ts, const VectorVal& changes);

    /**
     * Called from a timer's Dispatch() method to clear timer member.
     */
    void ResetTimer() { timer = nullptr; }

    /**
     * Set a static topic.
     *
     * @param t The topic to publish changes to.
     */
    void SetTopic(std::string t) { topic = std::move(t); }

    /**
     * @return a set optional with the static topic, or std::nullopt if not set.
     */
    std::optional<std::string> GetTopic() const { return topic; }

    /**
     * @return The script-layer function to invoke for determining the topic per change. Returns Func::nil if a static
     * topic is used.
     */
    const FuncPtr& GetTopicFunc() const { return topic_func; }

    /**
     * Store the script-layer identifier.
     *
     * @param id The script-layer identifier.
     */
    void SetIdentifier(const std::string& id);

    /**
     * Interpret the given record value given to &publish_on_change and create a
     * fresh PublishOnChangeState instance for \a table_val.
     *
     * @param table_value The table value this state will be attached to.
     * @param rec The record given to the &publish_on_change attribute.
     *
     * @return PublishOnChangeState
     */
    static std::unique_ptr<PublishOnChangeState> FromRecord(TableVal* table_val, const RecordVal& rec);

    /**
     * InitPostScript() hook for &publish_on_change support.
     *
     * Find all global tables with an attached PublishOnChangeState and
     * if for each that does not have a topic or topic_func set, update
     * it based on the table identifier.
     */
    static void InitPostScript();


private:
    detail::Timer* ArmPublishTimer(double now);
    void CancelPublishTimer();

    uint8_t change_mask = 0;          // Bitmask created from $changes field.
    std::optional<std::string> topic; // Pre-computed topic if topic_func nil.
    FuncPtr topic_func;               // Function to compute topic, can be nil.
    size_t max_batch_size = 0;        // Maximum size of queued_changes.
    double max_batch_delay = 0.0;     // Maximum delay before publishing the batch
    StringValPtr identifier;          // Script-layer identifier as string.

    TableVal* table_val = nullptr; // Pointer back to the table. Modified during ApplyChanges()
    bool in_apply_changes = false; // Set to true why processing remote changes.

    /**
     * Helper class to set in_apply_changes and unset when leaving a scope.
     *
     * Used in ApplyChanges()
     */
    class InApplyChangesScope {
    public:
        InApplyChangesScope(PublishOnChangeState* arg_poc) : poc(arg_poc) { poc->in_apply_changes = true; }
        ~InApplyChangesScope() { poc->in_apply_changes = false; }

        PublishOnChangeState* poc = nullptr;
    };

    size_t queued_changes_total = 0;                    // Number of total changes in queued_changes.
    std::map<std::string, VectorValPtr> queued_changes; // Queued changes to be published per topic.
    double last_publish_ts = 0.0;                       // Timestamp of last publish.
    Timer* timer = nullptr;                             // Timer to flush any queued changes.

    EventHandlerPtr event_handler; // event(id: string, ts: time: changes: vector of TableChangeInfo)
};

} // namespace detail
} // namespace zeek

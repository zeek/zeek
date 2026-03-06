// See the file "COPYING" in the main distribution directory for copyright.

// Functionality to support &publish_on_change for tables and sets.

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
using RecordValPtr = IntrusivePtr<RecordVal>;
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
     *
     * @param identifier The string-level identifier in StringVal form
     * @param tv The associated table value
     * @param change_mask Bitmask of changes to publish.
     * @param topic Optional static topic
     * @param topic_func A Zeek script function to dynamically determine the topic.
     * @param max_batch_size Maximum number of batched changes.
     * @param max_batch_delay Maximum delay for batched changes.
     */
    PublishOnChangeState(StringValPtr identifier, TableVal* tv, uint8_t change_mask, std::optional<std::string> topic,
                         FuncPtr topic_func, size_t max_batch_size, double max_batch_delay);

    /**
     * Destructor.
     */
    virtual ~PublishOnChangeState();

    /**
     * This method receives all changes done to a TableVal and queues
     * those changes that pass the change_bitmask.
     *
     * If OnChange() is called while ApplyChanges() is active, this method
     * short-circuits as to not re-publish changes from remote. Use the
     * script-layer hooks if you want to do something in this direction.
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
     * @param tcheader The TableChangeHeader record with misc information.
     * @param tcinfos TableChangeInfos vector containing all changes to be applied.
     */
    void ApplyChanges(const RecordVal& tcheader, const VectorVal& tcinfos);

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
     * Interpret the given record value given to &publish_on_change and create a
     * fresh PublishOnChangeState instance for \a table_val.
     *
     * @param id The script-level identifier.
     * @param table_val The table value this state will be attached to.
     * @param rec The record evaluated from the &publish_on_change attribute.
     *
     * @return PublishOnChangeState
     */
    static std::unique_ptr<PublishOnChangeState> Instantiate(const std::string& id, TableVal* table_val,
                                                             const RecordVal& rec);

    /**
     * InitPostScript() hook for &publish_on_change support.
     *
     * Find all global tables with an attached PublishOnChangeState and initialize
     * a PublishOnChangeState instance via Instantiate().
     */
    static void InitPostScript();

    /**
     * Called from a BiF to use the forward_table_change_infos() event instead
     * of directly publishing. Needed for Broker.
     *
     * @param topic The topic to send the forwarding events to, usually Cluster::manager_topic.
     */
    static void SetForwardTableChangeInfosTopic(std::string topic);

private:
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

    /**
     * Arm the publish timer for publishing.
     */
    detail::Timer* ArmPublishTimer(double now);

    /**
     * Cancel the publish timer if it is set.
     */
    void CancelPublishTimer();

    /**
     * Helper to publish a single Cluster::table_change_infos() event.
     *
     * @param topic
     * @param tcheader
     * @param tcinfos
     */
    void PublishQueuedChanges(double now, const std::string& topic, const RecordValPtr tcheader,
                              const VectorValPtr tcinfos);

    StringValPtr identifier;       // Global script-layer identifier of the value as StringValPtr.
    TableVal* table_val = nullptr; // Pointer back to the table. Modified during ApplyChanges()
    uint8_t change_mask = 0;       // Bitmask created from $changes field.
    size_t max_batch_size = 0;     // Maximum size of queued_changes.
    double max_batch_delay = 0.0;  // Maximum delay before publishing the batch
    bool in_apply_changes = false; // Set to true when processing remote changes through Apply

    // If topic is set, it is a static topic used for every change and
    // changes are queued in the changes member. The topic_func and
    // topic_changes members below are unused.
    std::optional<std::string> topic;
    VectorValPtr changes;

    // If topic_func is not nil, for every change a new topic is
    // determined by calling topic_func. Changes are queued per
    // topic in the topic_changes map. The topic and changes
    // members above are unused.
    FuncPtr topic_func;
    std::map<std::string, VectorValPtr> topic_changes;

    size_t queued_changes_total = 0; // Number of total queued changes.
    double last_publish_ts = 0.0;    // Timestamp of last publish.
    Timer* timer = nullptr;          // Timer for when to publish out the queued changes.

    static EventHandlerPtr eh_table_change_infos; // event(id: string, ts: time: changes: vector of TableChangeInfo)
    static EventHandlerPtr eh_forward_table_change_infos; // event(..., to: string)
    static std::optional<std::string> forward_topic;      // static topic to forward changes to instead of using topic.

    static StringValPtr local_node_id; // node_id value determined lazily via Cluster::node_id() on the first publish.
};

} // namespace detail
} // namespace zeek

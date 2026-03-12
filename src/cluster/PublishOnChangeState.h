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
#include "zeek/types.bif.netvar_h"

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
 * Convert a TableChange value to a bit.
 */
constexpr uint8_t table_change_to_bit(BifEnum::TableChange change) {
    assert(static_cast<int>(change) <= 7);
    return uint8_t{1} << static_cast<int>(change);
}

/**
 * Class holding state for script-level support of &publish_on_change tables and sets.
 *
 * Instances of this class are attached to TableVal objects during the InitPostScript() phase.
 * The Assign(), Remove() and expiration paths in TableVal call this class's OnChange() method
 * to propagate the table changes. The QueueChange() method will store the modification either
 * in the member changes or topic_changes, depending on whether the topic is static or dynamically
 * computed per modification. This is also calledbatching or queueing of changes. When
 * max_batch_size modifications have been queued, or the max_batch_delay interval expires, all
 * batched modifications are published via PublishQueuedChanges().
 *
 * The published modifications are applied using ApplyChanges() on other Zeek nodes. ApplyChanges()
 * itself never re-publishes the modifications to further cluster nodes.
 */
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
     * This method receives all changes done to a TableVal and collects
     * changes that pass the change_bitmask.
     *
     * If OnChange() is called while ApplyChanges() is active, this method
     * short-circuits as to not re-publish changes from a remote onde. Use
     * the script-layer hooks if you want to modify this behavior.
     *
     * @param change The TableChange value.
     * @param index A ListVal representing the index where the change happens
     * @param value Optional value
     * @param previous_value Optional previous value if change is TABLE_ELEMENT_CHANGED.
     */
    void OnChange(BifEnum::TableChange change, const Val& index, const ValPtr& value, const ValPtr& previous_value) {
        // If this change is happening due to running ApplyChanges() right now, do not queue the change.
        if ( in_apply_changes )
            return;

        if ( change_mask & table_change_to_bit(change) )
            QueueChange(change, index, value, previous_value);
    }

    /**
     * Queue a change for publishing.
     *
     * The key is expected to be a ListVal that will be converted to a vector of any
     * for transporting in a remote event.
     *
     * If the max_batch_size parameters is reached during queueing, the batch
     * of table changes is publishes using PublishQueuedChanges().
     *
     * If the provided value or previous_value is complex it is cloned such that
     * any subsequent modifications to these from script-land (in case of complex types)
     * are not visible during a delayed publish operation.
     *
     * @param change The TableChange value.
     * @param index A ListVal representing the index where the change happens
     * @param value Optional value
     * @param previous_value Optional previous value if change is TABLE_ELEMENT_CHANGED.
     */
    void QueueChange(BifEnum::TableChange change, const Val& index, const ValPtr& value, const ValPtr& previous_value);

    /**
     * Publish all pending changes and update last_publish_ts to \a now.
     *
     * @param now The current network time.
     */
    void PublishQueuedChanges(double now);

    /**
     * Helper to publish a single Cluster::table_change_infos() event.
     *
     * Internally, this looks at the forward_topic member to decide which event to use
     * Cluster::table_change_infos or Cluster::forward_table_change_infos and does the
     * appropriate Publish() call on the cluster backend. Not that this helper does not
     * update last_publish_ts or reset any state.
     *
     * @param topic The topic to publish to.
     * @param tcheader The TableChangeHeader value to publish
     * @param tcinfos The TableChangeInfos vector to publish
     */
    void PublishQueuedChanges(double now, const std::string& topic, RecordValPtr tcheader, VectorValPtr tcinfos) const;

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
     * @return The script-layer identifier as a string.
     */
    const StringValPtr& GetIdentifier() const { return identifier; }

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
     * Called from set_table_change_infos_forward_topic() BIF to use the
     * forward_table_change_infos() event instead of directly publishing.
     *
     * Needed for Broker.
     *
     * @param topic The topic to use for forwarding events to, usually Cluster::manager_topic.
     */
    static void SetTableChangeInfosForwardTopic(std::string topic) { forward_topic = topic; }

    /**
     * @return The Cluster::node_id() value.
     */
    static const StringValPtr& GetLocalNodeId();

    /*
     * InitPostScript() hook for &publish_on_change support.
     *
     * Find all global tables with an attached PublishOnChangeState and initialize
     * a PublishOnChangeState instance via Instantiate().
     */
    static void InitPostScript();

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
     *
     * @param now The current network time to compute the timer expiration.
     */
    detail::Timer* ArmPublishTimer(double now);

    /**
     * Cancel the publish timer if it is set.
     */
    void CancelPublishTimer();

    StringValPtr identifier;       // Global script-layer identifier of the value as StringValPtr.
    TableVal* table_val = nullptr; // Pointer back to the table. Used during ApplyChanges().
    uint8_t change_mask = 0;       // Bitmask created from $changes field.
    size_t max_batch_size = 0;     // Maximum number of queued/batched modifications.
    double max_batch_delay = 0.0;  // Maximum delay before publishing the batch.
    bool in_apply_changes = false; // Set to true when processing remote changes through Apply.

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
    std::map<std::string, VectorValPtr, std::less<>> topic_changes;

    size_t queued_changes = 0;    // Number of total queued changes.
    double last_publish_ts = 0.0; // Timestamp of last publish.
    Timer* timer = nullptr;       // Timer for when to publish out the queued changes.

    // event Cluster::table_change_infos(tcheader: TableChangeHeader, tcinfos: TableChangeInfos)
    static EventHandlerPtr eh_table_change_infos;
    // event Cluster::forward_table_change_infos(tcheader: TableChangeHeader, tcinfos: TableChangeInfo,
    //                                           to_topic: string)
    static EventHandlerPtr eh_forward_table_change_infos;
    // Forwarding topic - Set to Cluster::manager_topic via BIF on workers when Broker is used.
    static std::optional<std::string> forward_topic;

    static StringValPtr local_node_id; // node_id value determined lazily via Cluster::node_id() on the first publish.
};


/**
 * Function implementing the the Cluster::publish_table() builtin function.
 *
 * This sends table_val as multiple Cluster::table_change_infos() events to the
 * given topic. More concretely, there'll be int(|table_val| / batch_size) + 1
 * events published. That is, the whole table is published in batches. The receiver
 * uses Cluster::apply_change_infos() to populate its version.
 *
 * @param topic The topic to publish to.
 * @param table_val The table value to publish.
 * @param batch_size Number of TableChangeInfo records to place in a single table_change_infos() at most.
 */
bool cluster_publish_table(const std::string& topic, const zeek::TableVal& table_val, size_t batch_size);

} // namespace detail
} // namespace zeek

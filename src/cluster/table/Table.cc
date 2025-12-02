// See the file "COPYING" in the main distribution directory for copyright.
//
#include "zeek/cluster/table/Table.h"

#include <string_view>
#include <vector>

#include "zeek/DebugLogger.h"
#include "zeek/Desc.h"
#include "zeek/Event.h"
#include "zeek/EventRegistry.h"
#include "zeek/ID.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/Reporter.h"
#include "zeek/RunState.h"
#include "zeek/Scope.h"
#include "zeek/Val.h"
#include "zeek/broker/Data.h" // for data_to_val()
#include "zeek/cluster/Backend.h"
#include "zeek/cluster/table/Plugin.h"
#include "zeek/util-types.h"

namespace {

struct ActiveInsert {
    zeek::Val* table;
};

static std::vector<ActiveInsert> active_inserts;


const std::string* lookup_table_id(const zeek::TableValPtr& tbl) {
    // TODO: Cache this lookup
    const auto& global_scope = zeek::detail::global_scope();

    for ( const auto& [name, id] : global_scope->Vars() ) {
        if ( id->GetVal() == tbl )
            return &name;
    }

    return nullptr;
}

} // namespace


namespace zeek::cluster::table {

class Plugin;
extern Plugin plugin;

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define CLUSTER_TABLE_DEBUG(...) PLUGIN_DBG_LOG(plugin, __VA_ARGS__)
// NOLINTEND(cppcoreguidelines-macro-usage)

namespace detail::bif {


// Signature: tbl, tpe, key..., val
//
//
void publish_element_new(zeek::ArgsSpan args) {
    // The event used to send new elements around.
    static auto* elements_new_internal = zeek::event_registry->Lookup("Cluster::Table::elements_new_internal");
    static const auto table_element_new_val = zeek::id::find("TABLE_ELEMENT_NEW")->GetVal();
    static const auto any_vec_type = zeek::id::find_type<zeek::VectorType>("any_vec");
    static const auto new_element_type = zeek::id::find_type<zeek::RecordType>("Cluster::Table::NewElement");
    static const auto topic_separator =
        zeek::id::find_val<zeek::StringVal>("Cluster::Table::topic_separator")->ToStdString();

    if ( args.size() < 3 ) {
        zeek::reporter->Error("Cluster::Table: bad publish_element_new: %zu", args.size());
        return;
    }

    // If we're currently running insert_elements_new() on this table, skip.
    //
    // This prevents re-publishing elements that are currently being inserted
    // into the table published from another node.
    if ( ! active_inserts.empty() && (args[0].get() == active_inserts.back().table) )
        return;

    const auto& tpe = args[1];

    // If this isn't a TABLE_ELEMENT_NEW, ignore it.
    if ( tpe != table_element_new_val )
        return;

    const auto tbl = zeek::TableValPtr{zeek::NewRef{}, args[0]->AsTableVal()};

    const auto& tt = tbl->GetType<zeek::TableType>();
    const auto key_size = tt->GetIndexTypes().size();
    const auto val_size = tt->IsSet() ? 0 : 1;
    const auto* id = lookup_table_id(tbl);

    // Not nice, but this really needs to be used correctly, so we
    // make a lot of noise if it isn't.
    if ( ! id || args.size() != (2 + key_size + val_size) ) {
        zeek::reporter->Error("Cluster::Table: bad publish_element_new() usage for table %s", id->c_str());
        return;
    }

    // Value to store in NewElement record. Use T for sets.
    zeek::ValPtr val = tt->IsSet() ? zeek::val_mgr->True() : args.back();

    auto key_vec = zeek::make_intrusive<zeek::VectorVal>(any_vec_type);
    key_vec->Reserve(key_size);

    for ( const auto& key_val : args.subspan(2, key_size) )
        key_vec->Append(key_val);

    auto rec = zeek::make_intrusive<zeek::RecordVal>(new_element_type);
    rec->Assign(0, std::move(key_vec));
    rec->Assign(1, std::move(val));


    // Construct a new vector of NewElement and publish it.
    //
    // This is where we could/should add batching and timer
    // functionality to make it more efficient out of the box.
    auto vec = zeek::make_intrusive<zeek::VectorVal>(any_vec_type);
    vec->Append(std::move(rec));


    // TODO: These are trivially cacheable.
    auto topic = "zeek" + topic_separator + "table" + topic_separator + *id + topic_separator;
    auto idval = zeek::make_intrusive<zeek::StringVal>(*id);


    CLUSTER_TABLE_DEBUG("publish for %s %s (new_elements=%d) on topic %s handler %p", tt->IsSet() ? "set" : "table",
                        id->c_str(), vec->Size(), topic.c_str(), elements_new_internal);

    zeek::EventHandlerPtr event_handler{elements_new_internal};
    zeek::Args event_args{std::move(idval), std::move(vec)};
    zeek::detail::EventMetadataVectorPtr event_meta = nullptr;
    if ( zeek::BifConst::EventMetadata::add_network_timestamp )
        event_meta = zeek::detail::MakeEventMetadataVector(run_state::network_time);
    zeek::cluster::Event ev{event_handler, std::move(event_args), std::move(event_meta)};

    if ( ! zeek::cluster::backend->PublishEvent(topic, ev) )
        zeek::reporter->Error("Cluster::Table: Failed to publish");
}

bool insert_elements_new(std::string_view id, const VectorVal& new_elements) {
    const auto tbl = zeek::id::find_val<zeek::TableVal>(id);
    if ( ! tbl ) {
        zeek::reporter->Error("Cluster::Table: %s not found", std::string{id}.c_str());
        return false;
    }

    const auto& tt = tbl->GetType<zeek::TableType>();
    if ( tt->Tag() != zeek::TYPE_TABLE ) {
        zeek::reporter->Error("Cluster::Table: Ignoring %d inserts for table %s. Wrong type: %s", new_elements.Size(),
                              std::string{id}.c_str(), obj_desc_short(tt).c_str());

        return false;
    }

    // Mark as active insert.
    active_inserts.emplace_back(tbl.get());
    zeek::util::Deferred defer([]() { active_inserts.pop_back(); });

    const auto& index_types = tt->GetIndexTypes();
    const auto& yield_type = tt->Yield();

    CLUSTER_TABLE_DEBUG("%d new elements for %s (%p) received", new_elements.Size(), std::string{id}.c_str(),
                        tbl.get());

    for ( unsigned int i = 0; i < new_elements.Size(); i++ ) {
        const auto* new_element = new_elements.RecordValAt(i);
        const auto* key_vec = new_element->GetFieldAs<zeek::VectorVal>(0);

        if ( key_vec->Size() != index_types.size() ) {
            zeek::reporter->Error("Cluster::Table: Ignoring wrong sized key_vec for table %s", std::string{id}.c_str());
            return false;
        }

        // Ugh is this so annoying:
        //
        // 1) Assign takes a ListVal for the key. We have a VectorVal
        //    from the NewElement record, so we copy over into a new
        //    ListVal.
        //
        // 2) Because we use vector of any for the key, the broker de-serialization
        //    puts everything into a vector of Broker::Data records that then contain
        //    the broker::data values and we have to do the conversion by hand. This
        //    is because the cluster/broker layer has no knowledge about the potentially
        //    mixed index keys and boxes everything into broker::data, so that makes
        //    some sense, but it's still annoying because technically we should know the
        //    right types during de-serialization.
        auto key_list = zeek::make_intrusive<zeek::ListVal>(zeek::TYPE_ANY);
        for ( unsigned int j = 0; j < key_vec->Size(); j++ ) {
            auto key_val = key_vec->ValAt(j);
            auto* key_val_type = index_types[j].get();


            CLUSTER_TABLE_DEBUG("key_vec[%d] val=%s type=%s", j, zeek::obj_desc_short(key_val).c_str(),
                                zeek::obj_desc_short(key_val->GetType()).c_str());

            if ( key_val->GetType() == zeek::Broker::detail::DataVal::ScriptDataType() ) {
                auto ov = key_val->AsRecordVal()->GetField<zeek::OpaqueVal>(0);
                if ( ov->GetType() != zeek::Broker::detail::opaque_of_data_type ) {
                    zeek::reporter->Error("Cluster::Table: bad broker::data wrapping");
                    return false;
                }

                auto* data_val = static_cast<zeek::Broker::detail::DataVal*>(ov.get());

                if ( ! data_val->canCastTo(key_val_type) ) {
                    zeek::reporter->Error("Cluster::Table: %s, cannot cast %s to %s", std::string{id}.c_str(),
                                          broker::to_string(data_val->data).c_str(),
                                          obj_desc_short(key_val_type).c_str());
                    return false;
                }

                key_val = data_val->castTo(key_val_type);
            }
            key_list->Append(std::move(key_val));
        }

        zeek::ValPtr val = new_element->GetField(1);
        if ( tt->IsSet() ) {
            val = nullptr;
        }
        else if ( val->GetType() == zeek::Broker::detail::DataVal::ScriptDataType() ) {
            // Same as above, unwrap the value from Broker::Data to what is expected.
            auto ov = val->AsRecordVal()->GetField<zeek::OpaqueVal>(0);
            if ( ov->GetType() != zeek::Broker::detail::opaque_of_data_type ) {
                zeek::reporter->Error("Cluster::Table: bad broker::data wrapping");
                return false;
            }

            auto* data_val = static_cast<zeek::Broker::detail::DataVal*>(ov.get());

            if ( ! data_val->canCastTo(yield_type.get()) ) {
                zeek::reporter->Error("Cluster::Table: %s, cannot cast %s to %s", std::string{id}.c_str(),
                                      broker::to_string(data_val->data).c_str(),
                                      obj_desc_short(yield_type.get()).c_str());
                return false;
            }

            val = data_val->castTo(yield_type.get());
        }

        tbl->Assign(std::move(key_list), std::move(val), /*broker_forward=*/false);
    }

    return true;
}
} // namespace detail::bif
} // namespace zeek::cluster::table

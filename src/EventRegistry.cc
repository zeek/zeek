// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/EventRegistry.h"

#include <algorithm>
#include <cinttypes>

#include "zeek/Desc.h"
#include "zeek/EventHandler.h"
#include "zeek/Func.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/Traverse.h"
#include "zeek/TraverseTypes.h"
#include "zeek/Type.h"

namespace zeek {

EventRegistry::EventRegistry() = default;
EventRegistry::~EventRegistry() noexcept = default;

EventHandlerPtr EventRegistry::Register(std::string_view name, bool is_from_script) {
    // If there already is an entry in the registry, we have a
    // local handler on the script layer.
    EventHandler* h = event_registry->Lookup(name);

    if ( h ) {
        if ( ! is_from_script )
            not_only_from_script.insert(std::string(name));

        return h;
    }

    h = new EventHandler(std::string(name));
    event_registry->Register(h, is_from_script);

    return h;
}

void EventRegistry::Register(EventHandlerPtr handler, bool is_from_script) {
    std::string name = handler->Name();

    handlers[name] = std::unique_ptr<EventHandler>(handler.Ptr());

    if ( ! is_from_script )
        not_only_from_script.insert(std::move(name));
}

EventHandler* EventRegistry::Lookup(std::string_view name) {
    auto it = handlers.find(name);
    if ( it != handlers.end() )
        return it->second.get();

    return nullptr;
}

bool EventRegistry::NotOnlyRegisteredFromScript(std::string_view name) {
    return not_only_from_script.count(std::string(name)) > 0;
}

EventRegistry::string_list EventRegistry::Match(RE_Matcher* pattern) {
    string_list names;

    for ( const auto& entry : handlers ) {
        EventHandler* v = entry.second.get();
        if ( v->GetFunc() && pattern->MatchExactly(v->Name()) )
            names.push_back(entry.first);
    }

    return names;
}

EventRegistry::string_list EventRegistry::AllHandlers() {
    string_list names;

    for ( const auto& entry : handlers ) {
        names.push_back(entry.first);
    }

    return names;
}

void EventRegistry::PrintDebug() {
    for ( const auto& entry : handlers ) {
        EventHandler* v = entry.second.get();
        fprintf(stderr, "Registered event %s (%s handler / %s)\n", v->Name(), v->GetFunc() ? "local" : "no",
                *v ? "active" : "not active");
    }
}

void EventRegistry::SetErrorHandler(std::string_view name) {
    EventHandler* eh = Lookup(name);

    if ( eh ) {
        eh->SetErrorHandler();
        return;
    }

    reporter->InternalWarning("unknown event handler '%s' in SetErrorHandler()", std::string(name).c_str());
}

void EventRegistry::ActivateAllHandlers() {
    auto event_names = AllHandlers();
    for ( const auto& name : event_names ) {
        if ( auto event = Lookup(name) )
            event->SetGenerateAlways();
    }
}

EventGroupPtr EventRegistry::RegisterGroup(EventGroupKind kind, std::string_view name) {
    auto key = std::pair{kind, std::string{name}};
    if ( const auto& it = event_groups.find(key); it != event_groups.end() )
        return it->second;

    auto group = std::make_shared<EventGroup>(kind, name);
    return event_groups.emplace(key, group).first->second;
}

EventGroupPtr EventRegistry::LookupGroup(EventGroupKind kind, std::string_view name) {
    auto key = std::pair{kind, std::string{name}};
    if ( const auto& it = event_groups.find(key); it != event_groups.end() )
        return it->second;

    return nullptr;
}

EventGroup::EventGroup(EventGroupKind kind, std::string_view name) : kind(kind), name(name) {}

// Run through all ScriptFunc instances associated with this group and
// update their bodies after a group's enable/disable state has changed.
// Once that has completed, also update the Func's has_enabled_bodies
// setting based on the new state of its bodies.
//
// EventGroup is private friend with Func, so fiddling with the bodies
// and private members works and keeps the logic out of Func and away
// from the public zeek:: namespace.
void EventGroup::UpdateFuncBodies() {
    static auto is_group_disabled = [](const auto& g) { return g->IsDisabled(); };
    static auto is_body_enabled = [](const auto& b) { return ! b.disabled; };

    for ( auto& func : funcs ) {
        func->has_enabled_bodies = false;
        func->all_bodies_enabled = true;
        for ( auto& b : func->bodies ) {
            b.disabled = std::ranges::any_of(b.groups, is_group_disabled);
            func->has_enabled_bodies |= is_body_enabled(b);
            func->all_bodies_enabled &= is_body_enabled(b);
        }
    }
}

void EventGroup::Enable() {
    if ( enabled )
        return;

    enabled = true;

    UpdateFuncBodies();
}

void EventGroup::Disable() {
    if ( ! enabled )
        return;

    enabled = false;

    UpdateFuncBodies();
}

void EventGroup::AddFunc(detail::ScriptFuncPtr f) { funcs.insert(f); }

namespace {

class EventMetadataTypeRejector : public detail::TraversalCallback {
public:
    detail::TraversalCode PreType(const Type* t) override {
        if ( visited.count(t) > 0 )
            return detail::TC_ABORTSTMT;

        visited.insert(t);

        if ( reject.count(t->Tag()) )
            rejected.push_back(t);

        return detail::TC_CONTINUE;
    };

    std::set<const zeek::Type*> visited;
    std::vector<const zeek::Type*> rejected;

    std::set<zeek::TypeTag> reject = {TYPE_ANY, TYPE_FUNC, TYPE_FILE, TYPE_OPAQUE};
};

} // namespace

bool EventRegistry::RegisterMetadata(EnumValPtr id, TypePtr type) {
    static const auto& metadata_id_type = id::find_type<EnumType>("EventMetadata::ID");

    if ( metadata_id_type != id->GetType() )
        return false;

    auto id_int = id->Get();
    if ( id_int < 0 ) {
        zeek::reporter->InternalError("Negative enum value %s: %" PRId64, obj_desc_short(id.get()).c_str(), id_int);
    }

    zeek_uint_t id_uint = static_cast<zeek_uint_t>(id_int);

    if ( auto it = event_metadata_types.find(id_uint); it != event_metadata_types.end() )
        return same_type(it->second.Type(), type);

    EventMetadataTypeRejector cb;
    type->Traverse(&cb);

    if ( cb.rejected.size() > 0 )
        return false;

    event_metadata_types.insert({id_uint, EventMetadataDescriptor{id_uint, std::move(id), std::move(type)}});

    return true;
}

const EventMetadataDescriptor* EventRegistry::LookupMetadata(zeek_uint_t id) const {
    const auto it = event_metadata_types.find(id);
    if ( it == event_metadata_types.end() )
        return nullptr;

    if ( it->second.Id() != id ) {
        zeek::reporter->InternalError("inconsistent metadata descriptor: %" PRIu64 " vs %" PRId64, it->second.Id(), id);
    }

    return &(it->second);
}

} // namespace zeek

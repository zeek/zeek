// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Frame.h"

#include <broker/error.hh>

#include "zeek/Desc.h"
#include "zeek/Func.h"
#include "zeek/ID.h"
#include "zeek/Trigger.h"
#include "zeek/Val.h"
#include "zeek/broker/Data.h"

std::vector<zeek::detail::Frame*> g_frame_stack;

namespace zeek::detail {

Frame::Frame(int arg_size, const ScriptFunc* func, const zeek::Args* fn_args) {
    size = arg_size;
    frame = std::make_unique<Element[]>(size);
    function = func;
    func_args = fn_args;

    // We could Ref()/Unref() the captures frame, but there's really
    // no need because by definition this current frame exists to
    // enable execution of the function, and its captures frame won't
    // go away until the function itself goes away, which can only be
    // after this frame does.
    captures = function ? function->GetCapturesFrame() : nullptr;
    captures_offset_map = function ? function->GetCapturesOffsetMap() : nullptr;
}

void Frame::SetElement(int n, ValPtr v) {
    n += current_offset;
    ASSERT(n >= 0 && n < size);
    frame[n] = std::move(v);
}

void Frame::SetElement(const ID* id, ValPtr v) {
    if ( captures ) {
        auto cap_off = captures_offset_map->find(id->Name());
        if ( cap_off != captures_offset_map->end() ) {
            captures->SetElement(cap_off->second, std::move(v));
            return;
        }
    }

    SetElement(id->Offset(), std::move(v));
}

const ValPtr& Frame::GetElementByID(const ID* id) const {
    if ( captures ) {
        auto cap_off = captures_offset_map->find(id->Name());
        if ( cap_off != captures_offset_map->end() )
            return captures->GetElement(cap_off->second);
    }

    return frame[id->Offset() + current_offset];
}

void Frame::Reset(int startIdx) {
    for ( int i = startIdx + current_offset; i < size; ++i )
        frame[i] = nullptr;
}

void Frame::Describe(ODesc* d) const {
    if ( ! d->IsBinary() )
        d->AddSP("frame");

    if ( ! d->IsReadable() ) {
        d->Add(size);

        for ( int i = 0; i < size; ++i ) {
            d->Add(frame[i] != nullptr);
            d->SP();
        }
    }

    for ( int i = 0; i < size; ++i )
        if ( frame[i] )
            frame[i]->Describe(d);
        else if ( d->IsReadable() )
            d->Add("<nil>");
}

Frame* Frame::Clone() const {
    Frame* other = new Frame(size, function, func_args);

    other->call = call;
    other->assoc = assoc;
    other->trigger = trigger;

    for ( int i = 0; i < size; i++ )
        if ( frame[i] )
            other->frame[i] = frame[i]->Clone();

    // Note, there's no need to clone "captures" or "captures_offset_map"
    // since those get created fresh when constructing "other".

    return other;
}

Frame* Frame::CloneForTrigger() const {
    Frame* other = new Frame(0, function, func_args);

    other->call = call;
    other->assoc = assoc;
    other->trigger = trigger;

    return other;
}

static bool val_is_func(const ValPtr& v, ScriptFunc* func) {
    if ( v->GetType()->Tag() != TYPE_FUNC )
        return false;

    return v->AsFunc() == func;
}

std::optional<BrokerData> Frame::Serialize() {
    BrokerListBuilder body;

    for ( int i = 0; i < size; ++i ) {
        BrokerListBuilder val_tuple;

        const auto& val = frame[i];
        if ( ! val_tuple.Add(val) )
            return std::nullopt;

        val_tuple.Add(static_cast<int64_t>(val->GetType()->Tag()));

        body.Add(std::move(val_tuple));
    }

    BrokerListBuilder rval;
    rval.Add(std::move(body));

    return std::move(rval).Build();
}

std::pair<bool, FramePtr> Frame::Unserialize(BrokerListView data) {
    if ( data.IsEmpty() )
        return std::make_pair(true, nullptr);

    if ( ! data.Front().IsList() )
        return std::make_pair(false, nullptr);

    auto body = data.Front().ToList();

    auto frame_size = body.Size();
    auto rf = make_intrusive<Frame>(static_cast<int>(frame_size), nullptr, nullptr);

    for ( size_t index = 0; index < frame_size; ++index ) {
        if ( ! body[index].IsList() )
            continue;

        auto val_tuple = body[index].ToList();

        if ( val_tuple.Size() != 2 )
            return std::make_pair(false, nullptr);

        auto type_int = val_tuple[1].ToInteger(-1);
        if ( type_int < 0 || type_int >= NUM_TYPES )
            return std::make_pair(false, nullptr);

        Type t{static_cast<TypeTag>(type_int)};
        auto val = val_tuple[0].ToVal(&t);
        if ( ! val )
            return std::make_pair(false, nullptr);

        rf->frame[index] = std::move(val);
    }

    return std::make_pair(true, std::move(rf));
}

const detail::Location* Frame::GetCallLocation() const {
    // This is currently trivial, but we keep it as an explicit
    // method because it can provide flexibility for compiled code.
    return call->GetLocationInfo();
}

void Frame::SetTrigger(trigger::TriggerPtr arg_trigger) { trigger = std::move(arg_trigger); }

void Frame::ClearTrigger() { trigger = nullptr; }

} // namespace zeek::detail

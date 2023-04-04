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

namespace zeek::detail
	{

Frame::Frame(int arg_size, const ScriptFunc* func, const zeek::Args* fn_args)
	{
	size = arg_size;
	frame = std::make_unique<Element[]>(size);
	function = func;
	func_args = fn_args;

	next_stmt = nullptr;
	break_before_next_stmt = false;
	break_on_return = false;

	call = nullptr;
	delayed = false;

	// We could Ref()/Unref() the captures frame, but there's really
	// no need because by definition this current frame exists to
	// enable execution of the function, and its captures frame won't
	// go away until the function itself goes away, which can only be
	// after this frame does.
	captures = function ? function->GetCapturesFrame() : nullptr;
	captures_offset_map = function ? function->GetCapturesOffsetMap() : nullptr;
	current_offset = 0;
	}

void Frame::SetElement(int n, ValPtr v)
	{
	n += current_offset;
	frame[n] = std::move(v);
	}

void Frame::SetElement(const ID* id, ValPtr v)
	{
	if ( captures )
		{
		auto cap_off = captures_offset_map->find(id->Name());
		if ( cap_off != captures_offset_map->end() )
			{
			captures->SetElement(cap_off->second, std::move(v));
			return;
			}
		}

	SetElement(id->Offset(), std::move(v));
	}

const ValPtr& Frame::GetElementByID(const ID* id) const
	{
	if ( captures )
		{
		auto cap_off = captures_offset_map->find(id->Name());
		if ( cap_off != captures_offset_map->end() )
			return captures->GetElement(cap_off->second);
		}

	return frame[id->Offset() + current_offset];
	}

void Frame::Reset(int startIdx)
	{
	for ( int i = startIdx + current_offset; i < size; ++i )
		frame[i] = nullptr;
	}

void Frame::Describe(ODesc* d) const
	{
	if ( ! d->IsBinary() )
		d->AddSP("frame");

	if ( ! d->IsReadable() )
		{
		d->Add(size);

		for ( int i = 0; i < size; ++i )
			{
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

Frame* Frame::Clone() const
	{
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

Frame* Frame::CloneForTrigger() const
	{
	Frame* other = new Frame(0, function, func_args);

	other->call = call;
	other->assoc = assoc;
	other->trigger = trigger;

	return other;
	}

static bool val_is_func(const ValPtr& v, ScriptFunc* func)
	{
	if ( v->GetType()->Tag() != TYPE_FUNC )
		return false;

	return v->AsFunc() == func;
	}

broker::expected<broker::data> Frame::SerializeCopyFrame()
	{
	broker::vector rval;
	rval.emplace_back(std::string("CopyFrame"));

	broker::vector body;

	for ( int i = 0; i < size; ++i )
		{
		const auto& val = frame[i];
		auto expected = Broker::detail::val_to_data(val.get());
		if ( ! expected )
			return broker::ec::invalid_data;

		TypeTag tag = val->GetType()->Tag();
		broker::vector val_tuple{std::move(*expected), static_cast<broker::integer>(tag)};
		body.emplace_back(std::move(val_tuple));
		}

	rval.emplace_back(std::move(body));

	return {std::move(rval)};
	}

std::pair<bool, FramePtr> Frame::Unserialize(const broker::vector& data,
                                             const std::optional<FuncType::CaptureList>& captures)
	{
	if ( data.size() == 0 )
		return std::make_pair(true, nullptr);

	auto where = data.begin();

	auto has_name = broker::get_if<std::string>(*where);
	if ( ! has_name )
		return std::make_pair(false, nullptr);

	std::advance(where, 1);

	if ( captures )
		ASSERT(*has_name == "CopyFrame");

	auto has_body = broker::get_if<broker::vector>(*where);
	if ( ! has_body )
		return std::make_pair(false, nullptr);

	broker::vector body = *has_body;
	int frame_size = body.size();
	auto rf = make_intrusive<Frame>(frame_size, nullptr, nullptr);

	for ( int i = 0; i < frame_size; ++i )
		{
		auto has_vec = broker::get_if<broker::vector>(body[i]);
		if ( ! has_vec )
			continue;

		broker::vector val_tuple = *has_vec;
		if ( val_tuple.size() != 2 )
			return std::make_pair(false, nullptr);

		auto has_type = broker::get_if<broker::integer>(val_tuple[1]);
		if ( ! has_type )
			return std::make_pair(false, nullptr);

		broker::integer g = *has_type;
		Type t(static_cast<TypeTag>(g));

		auto val = Broker::detail::data_to_val(std::move(val_tuple[0]), &t);
		if ( ! val )
			return std::make_pair(false, nullptr);

		rf->frame[i] = std::move(val);
		}

	return std::make_pair(true, std::move(rf));
	}

const detail::Location* Frame::GetCallLocation() const
	{
	// This is currently trivial, but we keep it as an explicit
	// method because it can provide flexibility for compiled code.
	return call->GetLocationInfo();
	}

void Frame::SetTrigger(trigger::TriggerPtr arg_trigger)
	{
	trigger = std::move(arg_trigger);
	}

void Frame::ClearTrigger()
	{
	trigger = nullptr;
	}

	}

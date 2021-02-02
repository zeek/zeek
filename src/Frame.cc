// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek/Frame.h"

#include <broker/error.hh>

#include "zeek/broker/Data.h"
#include "zeek/Func.h"
#include "zeek/Desc.h"
#include "zeek/Trigger.h"
#include "zeek/Val.h"
#include "zeek/ID.h"

std::vector<zeek::detail::Frame*> g_frame_stack;

namespace zeek::detail {

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

	closure = nullptr;

	// We could Ref()/Unref() the captures frame, but there's really
	// no need because by definition this current frame exists to
	// enable execution of the function, and its captures frame won't
	// go away until the function itself goes away, which can only be
	// after this frame does.
	captures = function ? function->GetCapturesFrame() : nullptr;
	captures_offset_map =
		function ? function->GetCapturesOffsetMap() : nullptr;
	current_offset = 0;
	}

Frame::~Frame()
	{
	if ( functions_with_closure_frame_reference )
		{
		for ( auto& func : *functions_with_closure_frame_reference )
			{
			func->StrengthenClosureReference(this);
			Unref(func);
			}
		}

	if ( ! weak_closure_ref )
		Unref(closure);

	for ( auto& i : outer_ids )
		Unref(i);

	for ( int i = 0; i < size; ++i )
		ClearElement(i);
	}

void Frame::AddFunctionWithClosureRef(ScriptFunc* func)
	{
	Ref(func);

	if ( ! functions_with_closure_frame_reference )
		functions_with_closure_frame_reference = std::make_unique<std::vector<ScriptFunc*>>();

	functions_with_closure_frame_reference->emplace_back(func);
	}

void Frame::SetElement(int n, ValPtr v)
	{
	n += current_offset;

	ClearElement(n);
	frame[n] = {std::move(v), false};
	}

void Frame::SetElementWeak(int n, Val* v)
	{
	n += current_offset;

	ClearElement(n);
	frame[n] = {{AdoptRef{}, v}, true};
	}

void Frame::SetElement(const ID* id, ValPtr v)
	{
	if ( closure && IsOuterID(id) )
		{
		closure->SetElement(id, std::move(v));
		return;
		}

	if ( captures )
		{
		auto cap_off = captures_offset_map->find(id->Name());
		if ( cap_off != captures_offset_map->end() )
			{
			captures->SetElement(cap_off->second, std::move(v));
			return;
			}
		}

	// do we have an offset for it?
	if ( offset_map && ! offset_map->empty() )
		{
		auto where = offset_map->find(std::string(id->Name()));

		if ( where != offset_map->end() )
			{
			// Need to add a Ref to 'v' since the SetElement() for
			// id->Offset() below is otherwise responsible for keeping track
			// of the implied reference count of the passed-in 'v' argument.
			// i.e. if we end up storing it twice, we need an addition Ref.
			SetElement(where->second, v);
			}
		}

	SetElement(id->Offset(), std::move(v));
	}

const ValPtr& Frame::GetElementByID(const ID* id) const
	{
	if ( closure && IsOuterID(id) )
		return closure->GetElementByID(id);

	if ( captures )
		{
		auto cap_off = captures_offset_map->find(id->Name());
		if ( cap_off != captures_offset_map->end() )
			return captures->GetElement(cap_off->second);
		}

	// do we have an offset for it?
	if ( offset_map && ! offset_map->empty() )
		{
		auto where = offset_map->find(std::string(id->Name()));
		if ( where != offset_map->end() )
			return frame[where->second + current_offset].val;
		}

	return frame[id->Offset() + current_offset].val;
	}

void Frame::Reset(int startIdx)
	{
	if ( functions_with_closure_frame_reference )
		{
		for ( auto& func : *functions_with_closure_frame_reference )
			{
			// A lambda could be escaping its enclosing Frame at this point so
			// it needs to claim some ownership (or copy) of the Frame in
			// order to be of any further use.
			func->StrengthenClosureReference(this);
			Unref(func);
			}

		functions_with_closure_frame_reference.reset();
		}

	for ( int i = startIdx + current_offset; i < size; ++i )
		ClearElement(i);
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
			 d->Add(frame[i].val != nullptr);
			 d->SP();
			 }
		}

	for ( int i = 0; i < size; ++i )
		if ( frame[i].val )
			frame[i].val->Describe(d);
		else if ( d->IsReadable() )
			d->Add("<nil>");
	}

Frame* Frame::Clone() const
	{
	Frame* other = new Frame(size, function, func_args);

	if ( offset_map )
		other->offset_map = std::make_unique<OffsetMap>(*offset_map);

	other->CaptureClosure(closure, outer_ids);

	other->call = call;
	other->trigger = trigger;

	for ( int i = 0; i < size; i++ )
		if ( frame[i].val )
			other->frame[i].val = frame[i].val->Clone();

	// Note, there's no need to clone "captures" or "captures_offset_map"
	// since those get created fresh when constructing "other".

	return other;
	}

static bool val_is_func(const ValPtr& v, ScriptFunc* func)
	{
	if ( v->GetType()->Tag() != TYPE_FUNC )
		return false;

	return v->AsFunc() == func;
	}

void Frame::CloneNonFuncElement(int offset, ScriptFunc* func, Frame* other) const
	{
	const auto& v = frame[offset].val;

	if ( ! v )
		return;

	if ( val_is_func(v, func) )
		{
		other->SetElementWeak(offset, v.get());
		return;
		}

	auto rval = v->Clone();
	other->SetElement(offset, std::move(rval));
	}

Frame* Frame::SelectiveClone(const IDPList& selection, ScriptFunc* func) const
	{
	if ( selection.length() == 0 )
		return nullptr;

	IDPList us;
	// and
	IDPList them;

	for ( const auto& we : selection )
		{
		if ( ! IsOuterID(we) )
			us.append(we);
		else
			them.append(we);
		}

	Frame* other = new Frame(size, function, func_args);

	for ( const auto& id : us )
		{
		if ( offset_map && ! offset_map->empty() )
			{
			auto where = offset_map->find(std::string(id->Name()));
			if ( where != offset_map->end() )
				{
				CloneNonFuncElement(where->second, func, other);
				continue;
				}
			}

		if ( ! frame[id->Offset() + current_offset].val )
			reporter->InternalError("Attempted to clone an id ('%s') with no associated value.", id->Name());

		CloneNonFuncElement(id->Offset(), func, other);
		}

	/**
	 * What to do here depends on what the expected behavior of a copy
	 * operation on a function with a closure is. As we let functions
	 * mutate their closures, it seems reasonable that when cloned, the
	 * clone should continue to mutate the same closure as the function
	 * doesn't **own** the closure. Uncommenting the below if statement
	 * will change that behavior such that the function also copies the
	 * closure frame.
	 */
	// if ( closure )
	// 	other->closure = closure->SelectiveClone(them);
	// other->outer_ids = outer_ids;

	if ( closure )
		other->CaptureClosure(closure, outer_ids);

	if ( offset_map )
		{
		if ( ! other->offset_map )
			other->offset_map = std::make_unique<OffsetMap>(*offset_map);
		else
			*(other->offset_map) = *offset_map;
		}
	else
		other->offset_map.reset();

	return other;
	}

broker::expected<broker::data> Frame::SerializeClosureFrame(const IDPList& selection)
	{
	broker::vector rval;

	if ( selection.length() == 0 )
		// Easy - no captures, so frame is irrelvant.
		return {std::move(rval)};

	IDPList us;
	// and
	IDPList them;

	OffsetMap new_map;
	if ( offset_map )
		new_map = *offset_map;

	for ( const auto& we : selection )
		{
		if ( IsOuterID(we) )
			them.append(we);
		else
			{
			us.append(we);
			new_map.insert(std::make_pair(std::string(we->Name()), we->Offset()));
			}
		}

	if ( them.length() )
		{
		if ( ! closure )
			reporter->InternalError("Attempting to serialize values from a frame that does not exist.");

		rval.emplace_back(std::string("ClosureFrame"));

		auto ids = SerializeIDList(outer_ids);
		if ( ! ids )
			return broker::ec::invalid_data;

		rval.emplace_back(*ids);

		auto serialized = closure->SerializeClosureFrame(them);
		if ( ! serialized )
			return broker::ec::invalid_data;

		rval.emplace_back(*serialized);
		}
	else
		rval.emplace_back(std::string("Frame"));

	auto map = SerializeOffsetMap(new_map);
	if ( ! map )
		return broker::ec::invalid_data;

	rval.emplace_back(*map);

	broker::vector body;

	for ( int i = 0; i < size; ++i )
		body.emplace_back(broker::none());

	for ( const auto& id : us )
		{
		int location = id->Offset();

		auto where = new_map.find(std::string(id->Name()));
		if ( where != new_map.end() )
			location = where->second;

		const auto& val = frame[location].val;

		TypeTag tag = val->GetType()->Tag();

		auto expected = Broker::detail::val_to_data(val.get());
		if ( ! expected )
			return broker::ec::invalid_data;

		broker::vector val_tuple {std::move(*expected), static_cast<broker::integer>(tag)};
		body[location] = val_tuple;
		}

	rval.emplace_back(body);

	return {std::move(rval)};
	}

broker::expected<broker::data> Frame::SerializeCopyFrame()
	{
	broker::vector rval;
	rval.emplace_back(std::string("CopyFrame"));

	broker::vector body;

	for ( int i = 0; i < size; ++i )
		{
		const auto& val = frame[i].val;
		auto expected = Broker::detail::val_to_data(val.get());
		if ( ! expected )
			return broker::ec::invalid_data;

		TypeTag tag = val->GetType()->Tag();
		broker::vector val_tuple {std::move(*expected),
				static_cast<broker::integer>(tag)};
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

	if ( captures || *has_name == "CopyFrame" )
		{
		ASSERT(captures && *has_name == "CopyFrame");

		auto has_body = broker::get_if<broker::vector>(*where);
		if ( ! has_body )
			return std::make_pair(false, nullptr);

		broker::vector body = *has_body;
		int frame_size = body.size();
		auto rf = make_intrusive<Frame>(frame_size, nullptr, nullptr);

		rf->closure = nullptr;

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
			Type t( static_cast<TypeTag>(g) );

			auto val = Broker::detail::data_to_val(std::move(val_tuple[0]), &t);
			if ( ! val )
				return std::make_pair(false, nullptr);

			rf->frame[i].val = std::move(val);
			}

		return std::make_pair(true, std::move(rf));
		}


	// Code to support deprecated semantics:

	IDPList outer_ids;
	OffsetMap offset_map;
	FramePtr closure;

	if ( *has_name == "ClosureFrame" )
		{
		auto has_vec = broker::get_if<broker::vector>(*where);
		if ( ! has_vec )
			return std::make_pair(false, nullptr);

		std::advance(where, 1);

		auto list_pair = UnserializeIDList(*has_vec);
		if ( ! list_pair.first )
			return std::make_pair(false, nullptr);

		outer_ids = std::move(list_pair.second);

		has_vec = broker::get_if<broker::vector>(*where);
		if ( ! has_vec )
			{
			for ( auto& i : outer_ids )
				Unref(i);

			return std::make_pair(false, nullptr);
			}

		std::advance(where, 1);

		auto closure_pair = Frame::Unserialize(*has_vec, {});
		if ( ! closure_pair.first )
			{
			for ( auto& i : outer_ids )
				Unref(i);

			return std::make_pair(false, nullptr);
			}

		closure = std::move(closure_pair.second);
		}

	auto has_vec = broker::get_if<broker::vector>(*where);
	if ( ! has_vec )
		{
		for ( auto& i : outer_ids )
			Unref(i);

		return std::make_pair(false, nullptr);
		}

	std::advance(where, 1);

	auto map_pair = UnserializeOffsetMap(*has_vec);
	if ( ! map_pair.first )
		{
		for ( auto& i : outer_ids )
			Unref(i);

		return std::make_pair(false, nullptr);
		}

	offset_map = std::move(map_pair.second);

	auto has_body = broker::get_if<broker::vector>(*where);
	if ( ! has_body )
		{
		for ( auto& i : outer_ids )
			Unref(i);

		return std::make_pair(false, nullptr);
		}

	broker::vector body = *has_body;
	int frame_size = body.size();

	// We'll associate this frame with a function later.
	auto rf = make_intrusive<Frame>(frame_size, nullptr, nullptr);
	rf->offset_map = std::make_unique<OffsetMap>(std::move(offset_map));

	// Frame takes ownership of unref'ing elements in outer_ids
	rf->outer_ids = std::move(outer_ids);
	rf->closure = closure.release();
	rf->weak_closure_ref = false;

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
		Type t( static_cast<TypeTag>(g) );

		auto val = Broker::detail::data_to_val(std::move(val_tuple[0]), &t);
		if ( ! val )
			return std::make_pair(false, nullptr);

		rf->frame[i].val = std::move(val);
		}

	return std::make_pair(true, std::move(rf));
	}

void Frame::AddKnownOffsets(const IDPList& ids)
	{
	if ( ! offset_map )
		offset_map = std::make_unique<OffsetMap>();

	std::transform(ids.begin(), ids.end(), std::inserter(*offset_map, offset_map->end()),
		       [] (const ID* id) -> std::pair<std::string, int>
		       {
		       return std::make_pair(std::string(id->Name()), id->Offset());
		       });
	}

void Frame::CaptureClosure(Frame* c, IDPList arg_outer_ids)
	{
	if ( closure || outer_ids.length() )
		reporter->InternalError("Attempted to override a closure.");

	outer_ids = std::move(arg_outer_ids);

	for ( auto& i : outer_ids )
		Ref(i);

	closure = c;
	if ( closure )
		weak_closure_ref = true;

	/**
	 * Want to capture closures by copy?
	 * You'll also need to remove the Unref in the destructor.
	 */
	// if (c) closure = c->SelectiveClone(outer_ids);
	}

void Frame::SetTrigger(trigger::TriggerPtr arg_trigger)
	{
	trigger = std::move(arg_trigger);
	}

void Frame::ClearTrigger()
	{
	trigger = nullptr;
	}

void Frame::ClearElement(int n)
	{
	if ( frame[n].weak_ref )
		frame[n].val.release();
	else
		frame[n] = {nullptr, false};
	}

bool Frame::IsOuterID(const ID* in) const
	{
	return std::any_of(outer_ids.begin(), outer_ids.end(),
		[&in](ID* id)-> bool { return strcmp(id->Name(), in->Name()) == 0; });
	}

broker::expected<broker::data> Frame::SerializeIDList(const IDPList& in)
	{
	broker::vector rval;

	for ( const auto& id : in )
		{
		// name
		rval.emplace_back(std::string(id->Name()));
		// offset
		rval.emplace_back(id->Offset());
		}

	return {std::move(rval)};
	}

broker::expected<broker::data>
Frame::SerializeOffsetMap(const OffsetMap& in)
	{
	broker::vector rval;

	std::for_each(in.begin(), in.end(),
		[&rval] (const std::pair<std::string, int>& e)
			{ rval.emplace_back(e.first); rval.emplace_back(e.second);});

	return {std::move(rval)};
	}

std::pair<bool, IDPList>
Frame::UnserializeIDList(const broker::vector& data)
	{
	IDPList rval;
	if ( data.size() % 2 != 0 )
		return std::make_pair(false, std::move(rval));

	auto where = data.begin();
	while ( where < data.end() )
		{
		auto has_name = broker::get_if<std::string>(*where);
		if ( ! has_name )
			{
			for ( auto& i : rval )
				Unref(i);

			rval = IDPList{};
			return std::make_pair(false, std::move(rval));
			}

		std::advance(where, 1);

		auto has_offset = broker::get_if<broker::integer>(*where);
		if ( ! has_offset )
			{
			for ( auto& i : rval )
				Unref(i);

			rval = IDPList{};
			return std::make_pair(false, std::move(rval));
			}

		auto* id = new ID(has_name->c_str(), SCOPE_FUNCTION, false);
		id->SetOffset(*has_offset);
		rval.push_back(id);
		std::advance(where, 1);
		}

	return std::make_pair(true, std::move(rval));
	}

std::pair<bool, std::unordered_map<std::string, int>>
Frame::UnserializeOffsetMap(const broker::vector& data)
	{
	OffsetMap rval;

	for ( broker::vector::size_type i = 0; i < data.size(); i += 2 )
		{
		auto key = broker::get_if<std::string>(data[i]);
		if ( ! key )
			return std::make_pair(false, std::move(rval));

		auto offset = broker::get_if<broker::integer>(data[i+1]);
		if ( ! offset )
			return std::make_pair(false, std::move(rval));

		rval.insert( {std::move(*key), std::move(*offset)} );
		}

	return std::make_pair(true, std::move(rval));
	}

}

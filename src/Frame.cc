// See the file "COPYING" in the main distribution directory for copyright.

#include "Frame.h"

#include <broker/error.hh>
#include "broker/Data.h"

#include "Func.h"
#include "Desc.h"
#include "Trigger.h"
#include "Val.h"
#include "ID.h"

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
	zeek::Ref(func);

	if ( ! functions_with_closure_frame_reference )
		functions_with_closure_frame_reference = std::make_unique<std::vector<ScriptFunc*>>();

	functions_with_closure_frame_reference->emplace_back(func);
	}

void Frame::SetElement(int n, zeek::Val* v)
	{ SetElement(n, {zeek::AdoptRef{}, v}); }

void Frame::SetElement(int n, zeek::ValPtr v)
	{
	ClearElement(n);
	frame[n] = {std::move(v), false};
	}

void Frame::SetElementWeak(int n, zeek::Val* v)
	{
	ClearElement(n);
	frame[n] = {{zeek::AdoptRef{}, v}, true};
	}

void Frame::SetElement(const zeek::detail::ID* id, zeek::ValPtr v)
	{
	if ( closure )
		{
		if ( IsOuterID(id) )
			{
			closure->SetElement(id, std::move(v));
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

const zeek::ValPtr& Frame::GetElementByID(const zeek::detail::ID* id) const
	{
	if ( closure )
		{
		if ( IsOuterID(id) )
			return closure->GetElementByID(id);
		}

	// do we have an offset for it?
	if ( offset_map && ! offset_map->empty() )
		{
		auto where = offset_map->find(std::string(id->Name()));
		if ( where != offset_map->end() )
			return frame[where->second].val;
		}

	return frame[id->Offset()].val;
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

	for ( int i = startIdx; i < size; ++i )
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

	return other;
	}

static bool val_is_func(const zeek::ValPtr& v, ScriptFunc* func)
	{
	if ( v->GetType()->Tag() != zeek::TYPE_FUNC )
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

Frame* Frame::SelectiveClone(const id_list& selection, ScriptFunc* func) const
	{
	if ( selection.length() == 0 )
		return nullptr;

	id_list us;
	// and
	id_list them;

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

		if ( ! frame[id->Offset()].val )
			zeek::reporter->InternalError("Attempted to clone an id ('%s') with no associated value.", id->Name());

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

	if( closure )
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

broker::expected<broker::data> Frame::Serialize(const Frame* target, const id_list& selection)
	{
	broker::vector rval;

	if ( selection.length() == 0 )
		return {std::move(rval)};

	id_list us;
	// and
	id_list them;

	std::unordered_map<std::string, int> new_map;
	if ( target->offset_map )
		new_map = *(target->offset_map);

	for (const auto& we : selection)
		{
		if ( target->IsOuterID(we) )
			them.append(we);
		else
			{
			us.append(we);
			new_map.insert(std::make_pair(std::string(we->Name()), we->Offset()));
			}
		}

	if ( them.length() )
		{
		if ( ! target->closure )
			zeek::reporter->InternalError("Attempting to serialize values from a frame that does not exist.");

		rval.emplace_back(std::string("ClosureFrame"));

		auto ids = SerializeIDList(target->outer_ids);
		if ( ! ids )
			return broker::ec::invalid_data;

		rval.emplace_back(*ids);

		auto serialized = Frame::Serialize(target->closure, them);
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

	for ( int i = 0; i < target->size; ++i )
		body.emplace_back(broker::none());

	for ( const auto& id : us )
		{
		int location = id->Offset();

		auto where = new_map.find(std::string(id->Name()));
		if (where != new_map.end())
			location = where->second;

		const auto& val = target->frame[location].val;

		zeek::TypeTag tag = val->GetType()->Tag();

		auto expected = zeek::Broker::detail::val_to_data(val.get());
		if ( ! expected )
			return broker::ec::invalid_data;

		broker::vector val_tuple {std::move(*expected), static_cast<broker::integer>(tag)};
		body[location] = val_tuple;
		}

	rval.emplace_back(body);

	return {std::move(rval)};
	}

std::pair<bool, FramePtr> Frame::Unserialize(const broker::vector& data)
	{
	if ( data.size() == 0 )
		return std::make_pair(true, nullptr);

	id_list outer_ids;
	OffsetMap offset_map;
	FramePtr closure;

	auto where = data.begin();

	auto has_name = broker::get_if<std::string>(*where);
	if ( ! has_name )
		return std::make_pair(false, nullptr);

	std::advance(where, 1);

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

		auto closure_pair = Frame::Unserialize(*has_vec);
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
	auto rf = zeek::make_intrusive<Frame>(frame_size, nullptr, nullptr);
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
		zeek::Type t( static_cast<zeek::TypeTag>(g) );

		auto val = zeek::Broker::detail::data_to_val(std::move(val_tuple[0]), &t);
		if ( ! val )
			return std::make_pair(false, nullptr);

		rf->frame[i].val = std::move(val);
		}

	return std::make_pair(true, std::move(rf));
	}

void Frame::AddKnownOffsets(const id_list& ids)
	{
	if ( ! offset_map )
		offset_map = std::make_unique<OffsetMap>();

	std::transform(ids.begin(), ids.end(), std::inserter(*offset_map, offset_map->end()),
		       [] (const zeek::detail::ID* id) -> std::pair<std::string, int>
		       {
		       return std::make_pair(std::string(id->Name()), id->Offset());
		       });
	}

void Frame::CaptureClosure(Frame* c, id_list arg_outer_ids)
	{
	if ( closure || outer_ids.length() )
		zeek::reporter->InternalError("Attempted to override a closure.");

	outer_ids = std::move(arg_outer_ids);

	for ( auto& i : outer_ids )
		zeek::Ref(i);

	closure = c;
	if ( closure )
		weak_closure_ref = true;

	/**
	 * Want to capture closures by copy?
	 * You'll also need to remove the Unref in the destructor.
	 */
	// if (c) closure = c->SelectiveClone(outer_ids);
	}

void Frame::SetTrigger(zeek::detail::trigger::TriggerPtr arg_trigger)
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

bool Frame::IsOuterID(const zeek::detail::ID* in) const
	{
	return std::any_of(outer_ids.begin(), outer_ids.end(),
		[&in](zeek::detail::ID* id)-> bool { return strcmp(id->Name(), in->Name()) == 0; });
	}

broker::expected<broker::data> Frame::SerializeIDList(const id_list& in)
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
Frame::SerializeOffsetMap(const std::unordered_map<std::string, int>& in)
	{
	broker::vector rval;

	std::for_each(in.begin(), in.end(),
		[&rval] (const std::pair<std::string, int>& e)
			{ rval.emplace_back(e.first); rval.emplace_back(e.second);});

	return {std::move(rval)};
	}

std::pair<bool, id_list>
Frame::UnserializeIDList(const broker::vector& data)
	{
	id_list rval;
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

			rval = id_list{};
			return std::make_pair(false, std::move(rval));
			}

		std::advance(where, 1);

		auto has_offset = broker::get_if<broker::integer>(*where);
		if ( ! has_offset )
			{
			for ( auto& i : rval )
				Unref(i);

			rval = id_list{};
			return std::make_pair(false, std::move(rval));
			}

		auto* id = new zeek::detail::ID(has_name->c_str(), zeek::detail::SCOPE_FUNCTION, false);
		id->SetOffset(*has_offset);
		rval.push_back(id);
		std::advance(where, 1);
		}

	return std::make_pair(true, std::move(rval));
	}

std::pair<bool, std::unordered_map<std::string, int>>
Frame::UnserializeOffsetMap(const broker::vector& data)
	{
	std::unordered_map<std::string, int> rval;

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

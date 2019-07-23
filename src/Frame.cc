// See the file "COPYING" in the main distribution directory for copyright.

#include <broker/error.hh>
#include "broker/Data.h"

#include "Frame.h"
#include "Trigger.h"

vector<Frame*> g_frame_stack;

Frame::Frame(int arg_size, const BroFunc* func, const val_list *fn_args)
	{
	size = arg_size;
	frame = new Val*[size];
	function = func;
	func_args = fn_args;

	next_stmt = nullptr;
	break_before_next_stmt = false;
	break_on_return = false;

	trigger = nullptr;
	call = nullptr;
	delayed = false;

    closure = nullptr;

    for (int i = 0; i < size; ++i)
        frame[i] = nullptr;
	}

Frame::~Frame()
	{
	// Deleting a Frame that is a view is a no-op.
    Unref(trigger);
	if (closure) Unref(closure);
    Release();
	}

void Frame::SetElement(int n, Val* v)
	{
	Unref(frame[n]);
	frame[n] = v;
	}

void Frame::SetElement(const ID* id, Val* v)
	{
    if (closure)
        if ( IsOuterID(id) )
            {
            closure->SetElement(id, v);
            return;
            }

    // do we have an offset for it?
    if (offset_map.size())
        {
        auto where = offset_map.find(std::string(id->Name()));
        if ( where != offset_map.end() )
            {
            SetElement(where->second, v);
            }
        }

	SetElement(id->Offset(), v);
	}

Val* Frame::GetElement(const ID* id) const
	{
    if (closure)
        if ( IsOuterID(id) )
			{
            return closure->GetElement(id);
			}
    // do we have an offset for it?
	if ( offset_map.size() )
		{
		auto where = offset_map.find(std::string(id->Name()));
		if ( where != offset_map.end() )
			{
			return frame[where->second];\
			}
		}
	return frame[id->Offset()];
	}

void Frame::Reset(int startIdx)
	{
	for ( int i = startIdx; i < size; ++i )
		{
		Unref(frame[i]);
		frame[i] = 0;
		}
	}

void Frame::Release()
	{
	for ( int i = 0; i < size; ++i )
		Unref(frame[i]);

	delete [] frame;
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
			 d->Add(frame[i] != 0);
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
	other->offset_map = offset_map;
	other->CaptureClosure(closure, outer_ids);

	other->trigger = trigger;
	if (trigger) Ref(trigger);
	other->call = call;

	for (int i = 0; i < size; i++)
		{
		other->frame[i] = frame[i] ? frame[i]->Clone() : nullptr;
		}

	return other;
	}

Frame* Frame::SelectiveClone(const id_list& selection) const
	{
	if (selection.length() == 0)
		return nullptr;

	id_list us;
	// and
	id_list them;

	for (const auto& we : selection)
		{
		if ( ! IsOuterID(we) )
			us.append(we);
		else
			them.append(we);
		}

	Frame* other = new Frame(size, function, func_args);

	for (const auto& id : us)
		{
		if ( offset_map.size() )
			{
			auto where = offset_map.find(std::string(id->Name()));
			if ( where != offset_map.end() )
				{
				other->frame[where->second] = frame[where->second]->Clone();
				continue;
				}
			}
		if ( ! frame[id->Offset()] )
			reporter->InternalError("Attempted to clone an id ('%s') with no associated value.", id->Name());

		other->frame[id->Offset()] = frame[id->Offset()]->Clone();
		}

	/**
	 * What to do here depends on what the expected behavior of a copy
	 * operation on a function with a closure is. As we let function's
	 * mutate their closures, it seems reasonable that when cloned, the
	 * clone should continue to mutate the same closure as the function
	 * doesn't **own** the closure. Uncommenting the below if statement
	 * will change that behavior such that the function also copies the
	 * closure frame.
	 */
	// if (closure)
	// 	other->closure = closure->SelectiveClone(them);
	// other->outer_ids = outer_ids;

	if(closure)
		other->CaptureClosure(closure, outer_ids);

	other->offset_map = offset_map;

	return other;
	}

broker::expected<broker::data> Frame::Serialize(const Frame* target, id_list selection)
    {
	broker::vector rval;

	if (selection.length() == 0)
		return {std::move(rval)};

	id_list us;
	// and
	id_list them;

	std::unordered_map<std::string, int> new_map(target->offset_map);

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

	if (them.length())
		{
		if ( ! target->closure )
			reporter->InternalError("Attempting to serialize values from a frame that does not exist.");

		rval.emplace_back(std::string("ClosureFrame"));

		auto ids = SerializeIDList(target->outer_ids);
		if ( ! ids ) return broker::ec::invalid_data;
		rval.emplace_back(*ids);

		auto serialized = Frame::Serialize(target->closure, them);
		if ( ! serialized ) return broker::ec::invalid_data;

		rval.emplace_back(*serialized);
		}
	else
		rval.emplace_back(std::string("Frame"));

	auto map = SerializeOffsetMap(new_map);
	if ( ! map ) return broker::ec::invalid_data;
	rval.emplace_back(*map);

	broker::vector body;

	for (int i = 0; i < target->size; ++i)
		{
		body.emplace_back(broker::none());
		}
	for (const auto& id : us)
		{
		int location = id->Offset();

		auto where = new_map.find(std::string(id->Name()));
		if (where != new_map.end())
			{
			location = where->second;
			}

		Val* val = target->frame[location];

		TypeTag tag = val->Type()->Tag();

		auto expected = bro_broker::val_to_data(val);
		if ( ! expected ) return broker::ec::invalid_data;

		broker::vector val_tuple {std::move(*expected), static_cast<broker::integer>(tag)};

		body[location] = val_tuple;
		}

	rval.emplace_back(body);

	return {std::move(rval)};
    }

std::pair<bool, Frame*> Frame::Unserialize(const broker::vector& data)
    {
	if (data.size() == 0)
		return std::make_pair(true, nullptr);

	id_list outer_ids;
	std::unordered_map<std::string, int> offset_map;
	Frame* closure = nullptr;

	auto where = data.begin();

	auto has_name = broker::get_if<std::string>(*where);
	if ( ! has_name ) return std::make_pair(false, nullptr);
	std::advance(where, 1);

	if (*has_name == "ClosureFrame")
		{
		auto has_vec = broker::get_if<broker::vector>(*where);
		if ( ! has_vec ) return std::make_pair(false, nullptr);
		std::advance(where, 1);

		auto list_pair = UnserializeIDList(*has_vec);
		if ( ! list_pair.first ) return std::make_pair(false, nullptr);
		outer_ids = std::move(list_pair.second);

		has_vec = broker::get_if<broker::vector>(*where);
		if ( ! has_vec ) return std::make_pair(false, nullptr);
		std::advance(where, 1);

		auto closure_pair = Frame::Unserialize(*has_vec);
		if ( ! closure_pair.first ) return std::make_pair(false, nullptr);
		closure = closure_pair.second;
		}

	auto has_vec = broker::get_if<broker::vector>(*where);
	if ( ! has_vec ) return std::make_pair(false, nullptr);
	std::advance(where, 1);

	auto map_pair = UnserializeOffsetMap(*has_vec);
	if ( ! map_pair.first ) return std::make_pair(false, nullptr);
	offset_map = std::move(map_pair.second);

	auto has_body = broker::get_if<broker::vector>(*where);
	if ( ! has_body ) return std::make_pair(false, nullptr);
	broker::vector body = *has_body;

	int frame_size = body.size();

	// We'll associate this frame with a function later.
	Frame* rf = new Frame(frame_size, nullptr, nullptr);
	rf->offset_map = std::move(offset_map);
	rf->outer_ids = std::move(outer_ids);
	rf->closure = closure;

	for (int i = 0; i < frame_size; ++i)
		{
		auto has_vec = broker::get_if<broker::vector>(body[i]);
		if ( ! has_vec ) continue;

		broker::vector val_tuple = *has_vec;
		if (val_tuple.size() != 2) return std::make_pair(false, nullptr);

		auto has_type = broker::get_if<broker::integer>(val_tuple[1]);
		if ( ! has_type ) return std::make_pair(false, nullptr);

		broker::integer g = *has_type;
		BroType t( static_cast<TypeTag>(g) );

		Val* val = bro_broker::data_to_val(std::move(val_tuple[0]), &t);
		if ( ! val ) return std::make_pair(false, nullptr);

		rf->frame[i] = val;
		}

	return std::make_pair(true, rf);
    }

void Frame::AddKnownOffsets(const id_list& ids)
    {
    std::transform(ids.begin(), ids.end(), std::inserter(offset_map, offset_map.end()),
        [] (const ID* id) -> std::pair<std::string, int>
        {
        return std::make_pair( std::string(id->Name()), id->Offset() );
        });
    }

void Frame::CaptureClosure(Frame* c, id_list arg_outer_ids)
    {
    if (closure) reporter->InternalError("Attempted to override a closure.");

    outer_ids = std::move(arg_outer_ids);
	closure = c;
	if (closure) Ref(closure);

	/**
	 * Want to capture closures by copy?
	 * You'll also need to remove the Unref in the destructor.
	 */
	// if (c) closure = c->SelectiveClone(outer_ids);
    }

void Frame::SetTrigger(Trigger* arg_trigger)
	{
	ClearTrigger();

	if ( arg_trigger )
		Ref(arg_trigger);

	trigger = arg_trigger;
	}

void Frame::ClearTrigger()
	{
	Unref(trigger);
	trigger = nullptr;
	}

bool Frame::IsOuterID(const ID* in) const
	{
	return std::any_of(outer_ids.begin(), outer_ids.end(),
		[&in](ID* id)-> bool { return strcmp(id->Name(), in->Name()) == 0; });
	}

broker::expected<broker::data> Frame::SerializeIDList(const id_list& in)
	{
	broker::vector rval;

	for (const auto& id : in)
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
	if (data.size() % 2 != 0) return std::make_pair(false, std::move(rval));

	auto where = data.begin();
	while (where < data.end())
		{
		auto has_name = broker::get_if<std::string>(*where);
		if ( ! has_name ) return std::make_pair(false, std::move(rval));

		ID* id = new ID(has_name->c_str(), SCOPE_FUNCTION, false);

		std::advance(where, 1);
		auto has_offset = broker::get_if<broker::integer>(*where);
		if ( ! has_offset ) return std::make_pair(false, std::move(rval));

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

	for (broker::vector::size_type i = 0; i < data.size(); i += 2)
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

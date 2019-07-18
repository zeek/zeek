// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include <string>
#include <algorithm>
#include <broker/error.hh>

#include "Frame.h"
#include "Stmt.h"
#include "Func.h"
#include "Trigger.h"

#include "broker/Data.h"

vector<Frame*> g_frame_stack;

Frame::Frame(int arg_size, const BroFunc* func, const val_list* fn_args)
	{
	size = arg_size;
	frame = new Val*[size];
	function = func;
	func_args = fn_args;

	next_stmt = 0;
	break_before_next_stmt = false;
	break_on_return = false;

	trigger = 0;
	call = 0;
	delayed = false;

	is_view = false;

	Clear();
	}

Frame::Frame(const Frame* other, bool view)
	{
	is_view = view;

	size = other->size;
	trigger = other->trigger;
	call = other->call;

	function = other->function;
	func_args = other->func_args;

	next_stmt = 0;
	break_before_next_stmt = false;
        break_on_return = false;
	delayed = false;

	if ( is_view )
		frame = other->frame;
	else
		{
		if  ( trigger )
			Ref(trigger);

		for ( int i = 0; i < size; ++i )
			frame[i] = other->frame[i] ? other->frame[i]->Clone() : 0;
		}
	}

Frame::~Frame()
	{
	// Deleting a Frame that is a view is a no-op.
	if ( ! is_view )
		{
		Unref(trigger);
		Release();
		}
	}

void Frame::SetElement(int n, Val* v)
	{
	Unref(frame[n]);
	frame[n] = v;
	}

void Frame::SetElement(const ID* id, Val* v)
	{
	SetElement(id->Offset(), v);
	}

Val* Frame::GetElement(const ID* id) const
	{
	if ( HasOuterIDs() )
		{
		auto where = offset_map.find(std::string(id->Name()));
		if ( where != offset_map.end() )
			return frame[where->second];
		}

	return frame[id->Offset()];
	}

void Frame::AddElement(const ID* id, Val* v)
	{
	this->SetElement(id, v);
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

void Frame::Clear()
	{
	for ( int i = 0; i < size; ++i )
		frame[i] = 0;
	}

Frame* Frame::Clone()
	{
	Frame* f = new Frame(size, function, func_args);
	f->Clear();

	for ( int i = 0; i < size; ++i )
		f->frame[i] = frame[i] ? frame[i]->Clone() : 0;

	if ( trigger )
		Ref(trigger);
	f->trigger = trigger;

	f->call = call;

	return f;
	}

Frame* Frame::SelectiveClone(id_list* selection)
	{
	Frame* other = new Frame(size, function, func_args);

	loop_over_list(*selection, i)
	  {
	  ID* current = (*selection)[i];
	  Val* v = this->frame[current->Offset()];
	  other->frame[current->Offset()] = v ? v->Clone() : 0;
	  }

	return other;
	}

broker::expected<broker::data> Frame::Serialize() const
	{
	broker::vector rval;
	rval.emplace_back(std::string("Frame"));

	auto om = SerializeOffsetMap();
	if ( ! om ) return broker::ec::invalid_data;
	rval.emplace_back( *om );

	for (int i = 0; i < size; ++i)
		{
		if ( ! frame[i] )
			{
			// data
			rval.emplace_back(broker::none());
			// type
			rval.emplace_back(broker::none());
			}
		else
			{
			auto expected = bro_broker::val_to_data(frame[i]);
			if ( ! expected )
				return broker::ec::invalid_data;
			else
				{
				// data
				rval.emplace_back(std::move(*expected));
				// type
				rval.emplace_back(static_cast<broker::integer>(frame[i]->Type()->Tag()));
				}
			}
		}

	return {std::move(rval)};
	}

std::pair<bool, Frame*> Frame::Unserialize(const broker::vector& data)
	{
	#define FAIL std::make_pair(false, nullptr)
	#define GET_OR_RETURN(type, name, index)							\
		if (auto __##name##__ = broker::get_if<type>(data[index]))		\
			name = *__##name##__;										\
		else															\
			return FAIL;												\

	std::string pivot;
	GET_OR_RETURN(std::string, pivot, 0)

	if (pivot == "Frame")
		{

		int frame_size = (data.size() - 2) / 2;
		// Cool -> We serialized a function with a null frame.
		if (frame_size == 0) return std::make_pair(true, nullptr);

		// Unserialize the offset map.
		broker::vector o_map;
		GET_OR_RETURN(broker::vector, o_map, 1)

		std::unordered_map<std::string, int> offset_map;
		bool status = ClosureFrame::UnserializeIntoOffsetMap(o_map, offset_map);

		// Function / arg information updated later as needed.
		Frame* f = new Frame(frame_size, nullptr, nullptr);
		f->offset_map = std::move(offset_map);

		for (int i = 0, j = 2; i < frame_size; ++i, j += 2)
			{
			// Null values in the serialized frame are stored as broker::none.
			if ( ! broker::get_if<broker::none>(data[j]) )
				{
				broker::integer g;
				GET_OR_RETURN(broker::integer, g, (j+1))

				BroType t( static_cast<TypeTag>(g) );

				auto val = bro_broker::data_to_val(std::move(data[j]), &t);
				if ( ! val ) return FAIL;

				f->frame[i] = val;
				}
			}

		return std::make_pair(true, f);
		}

	else if (pivot == "ClosureFrame")
		{

		broker::vector o_map;
		broker::vector v_closure;
		broker::vector v_body;

		GET_OR_RETURN(broker::vector, o_map, 1)
		GET_OR_RETURN(broker::vector, v_closure, 2)
		GET_OR_RETURN(broker::vector, v_body, 3)

		std::unordered_map<std::string, int> offset_map;
		bool status = ClosureFrame::UnserializeIntoOffsetMap(o_map, offset_map);

		if ( ! status ) return FAIL;

		auto result = Frame::Unserialize(v_closure);
		if ( ! result.first )
			return FAIL;
		Frame* closure = result.second;

		result = Frame::Unserialize(v_body);
		if ( ! result.first )
			return FAIL;
		Frame* body = result.second;

		ClosureFrame* c = new ClosureFrame(closure, body, nullptr);
		c->offset_map = std::move(offset_map);

		return std::make_pair(true, c);
		}

	return FAIL;
	#undef GET_OR_RETURN
	#undef FAIL
	}

void Frame::SetOuterIDs (std::shared_ptr<id_list> outer_ids)
	{
	// When cloning we bypass this step and just directly copy over the map,
	// hence the check.
	if ( ! outer_ids ) return;

	if (offset_map.size()) return;

	id_list tmp = *(outer_ids.get());
	loop_over_list(tmp, i)
	  {
	    ID* id = tmp[i];
	    if (id)
	      offset_map.emplace(id->Name(), id->Offset());
	  }
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
	trigger = 0;
	}

bool Frame::CaptureContains(const ID* i) const
	{
	auto where = offset_map.find(std::string(i->Name()));
	return where != offset_map.end();
	}

ClosureFrame::ClosureFrame(Frame* arg_closure, Frame* not_closure,
	std::shared_ptr<id_list> outer_ids) : Frame(not_closure, true)
	{
	assert(arg_closure);

	closure = arg_closure;
	body = not_closure;

	SetOuterIDs(outer_ids);
	}

ClosureFrame::~ClosureFrame()
	{
	// No need to Unref the closure. BroFunc handles this.
	// Unref body though. When the ClosureFrame is done, so is
	// the frame that is is wrapped around.

	// TODO(robin): It would be good handle body & closure the same in
	// terms needing to ref/unref; it's easy to get confused otherwise.
	Unref(body);
	}

Val* ClosureFrame::GetElement(const ID* id) const
	{
	if ( CaptureContains(id) )
		{
		int my_offset = offset_map.at(std::string(id->Name()));
		return ClosureFrame::GatherFromClosure(this, id, my_offset);
		}

	return NthElement(id->Offset());
	}

void ClosureFrame::SetElement(const ID* id, Val* v)
	{
	if ( CaptureContains(id) )
		{
		int my_offset = offset_map.at(std::string(id->Name()));
		ClosureFrame::SetInClosure(this, id, v, my_offset);
		return;
		}

	Frame::SetElement(id->Offset(), v);
	}

Frame* ClosureFrame::Clone()
	{
	Frame* new_closure = closure->Clone();
	Frame* new_regular = body->Clone();

	ClosureFrame* cf = new ClosureFrame(new_closure, new_regular, nullptr);
	cf->offset_map = offset_map;
	return cf;
	}

Frame* ClosureFrame::SelectiveClone(id_list* choose)
	{
	id_list us;
	// and
	id_list them;

	for (const auto& we : *choose)
		{
		if ( CaptureContains(we) )
			us.append(we);
		else
			them.append(we);
		}

	Frame* me = closure->SelectiveClone(&us);
	// and
	Frame* you = body->SelectiveClone(&them);

	ClosureFrame* who = new ClosureFrame(me, you, nullptr);
	who->offset_map = offset_map;

	return who;
	}

broker::expected<broker::data> ClosureFrame::Serialize() const
	{
	broker::vector rval;
	rval.emplace_back(std::string("ClosureFrame"));

	auto om = SerializeOffsetMap();
	if ( ! om )
		return broker::ec::invalid_data;

	rval.emplace_back( *om );

	auto cl = closure->Serialize();
	if ( ! cl )
		return broker::ec::invalid_data;

	rval.emplace_back( *cl );

	auto bo = body->Serialize();
	if ( ! bo )
		return broker::ec::invalid_data;

	rval.emplace_back(*bo);
	return {std::move(rval)};
	}

broker::expected<broker::data> Frame::SerializeOffsetMap() const
	{
	broker::vector rval;

	std::for_each(offset_map.begin(), offset_map.end(),
		[&rval] (const std::pair<std::string, int>& e)
			{ rval.emplace_back(e.first); rval.emplace_back(e.second);});

	return {std::move(rval)};
	}

bool ClosureFrame::UnserializeIntoOffsetMap(const broker::vector& data, std::unordered_map<std::string, int>& target)
	{
	assert(target.size() == 0);

	std::unordered_map<std::string, int> rval;

	for (broker::vector::size_type i = 0; i < data.size(); i += 2)
		{
		auto key = broker::get_if<std::string>(data[i]);
		if ( ! key )
			return false;

		auto offset = broker::get_if<broker::integer>(data[i+1]);
		if ( ! offset )
			return false;

		target.insert( {std::move(*key), std::move(*offset)} );
		}

	return true;
	}

// Each ClosureFrame knows all of the outer IDs that are used inside of it.
// This is known at parse time. These leverage that. If frame_1 encloses
// frame_2 then the location of a lookup for an outer id in frame_2 can be
// determined by checking if that id is also an outer id in frame_2. If it is
// not, then frame_2 owns the id and the lookup is done there, otherwise, go
// deeper.
Val* ClosureFrame::GatherFromClosure(const Frame* start, const ID* id, const int offset)
	{
	const ClosureFrame* conductor = dynamic_cast<const ClosureFrame*>(start);

	// If a subframe has outer IDs then it was serialized and passed around before this frame
	// was born. We differ to its maping as it is older and wiser. Otherwise, we use our own.
	if ( ! conductor )
		{
		if ( start->HasOuterIDs() )
			return start->GetElement(id);

		return start->NthElement(offset);
		}

	if ( conductor->CaptureContains(id) )
		return ClosureFrame::GatherFromClosure(conductor->closure, id, offset);

	return conductor->NthElement(offset);
	}

void ClosureFrame::SetInClosure(Frame* start, const ID* id, Val* val, const int offset)
	{
	ClosureFrame* conductor = dynamic_cast<ClosureFrame*>(start);

	if ( ! conductor )
		start->SetElement(offset, val);

	else if ( conductor->CaptureContains(id) )
		ClosureFrame::SetInClosure(conductor->closure, id, val, offset);

	else
		conductor->Frame::SetElement(offset, val);
	}

// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Frame.h"
#include "Stmt.h"
#include "Func.h"
#include "Trigger.h"

#include <string>

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

	Clear();
	}

Frame::Frame(const Frame* other)
	{
	this->size = other->size;
	this->frame = other->frame;
	this->function = other->function;
	this->func_args = other->func_args;

	this->next_stmt = 0;
	this->break_before_next_stmt = false;
	this->break_on_return = false;
	this->delayed = false;

	// We need to Ref this because the
	// destructor will Unref.
	if ( other->trigger )
		Ref(other->trigger);

	this->trigger = other->trigger;
	this->call = other->call;
	}

Frame::~Frame()
	{
	Unref(trigger);
	Release();
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


Val* Frame::GetElement(ID* id) const
	{
	return this->frame[id->Offset()];
	}

void Frame::AddElement(ID* id, Val* v)
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
	  other->frame[current->Offset()] = this->frame[current->Offset()];
	  }

        return other;
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

ClosureFrame::ClosureFrame(Frame* closure, Frame* not_closure,
	std::shared_ptr<id_list> outer_ids) : Frame(not_closure)
	{
	assert(closure);

	this->closure = closure;
	Ref(this->closure);
	this->body = not_closure;
	Ref(this->body);

	// To clone a ClosureFrame we null outer_ids and then copy
	// the set over directly, hence the check.
	if (outer_ids)
		{
		// Install the closure IDs
		id_list* tmp = outer_ids.get();
		loop_over_list(*tmp, i)
			{
			ID* id = (*tmp)[i];
			if (id)
				this->closure_elements.insert(id->Name());
			}
		}
	}

ClosureFrame::~ClosureFrame()
	{
	Unref(this->closure);
	Unref(this->body);
	}

Val* ClosureFrame::GetElement(ID* id) const
	{
	if (this->closure_elements.find(id->Name()) != this->closure_elements.end())
		return ClosureFrame::GatherFromClosure(this, id);

	return this->NthElement(id->Offset());
	}

void ClosureFrame::SetElement(const ID* id, Val* v)
	{
	if (this->closure_elements.find(id->Name()) != this->closure_elements.end())
	  ClosureFrame::SetInClosure(this, id, v);
	else
	  this->Frame::SetElement(id->Offset(), v);
	}

Frame* ClosureFrame::Clone()
	{
	Frame* new_closure = this->closure->Clone();
	Frame* new_regular = this->body->Clone();

	ClosureFrame* cf = new ClosureFrame(new_closure, new_regular, nullptr);
	cf->closure_elements = this->closure_elements;
	return cf;
	}

Frame* ClosureFrame::SelectiveClone(id_list* choose)
        {
	id_list us;
	// and
	id_list them;
	
	loop_over_list(*choose, i)
	  {
	    ID* we = (*choose)[i];
	    if (closure_contains(we))
	      us.append(we);
	    else
	      them.append(we);
	  }
	
	Frame* me = this->closure->SelectiveClone(&us);
	// and
	Frame* you  = this->body->SelectiveClone(&them);

	ClosureFrame* who = new ClosureFrame(me, you, nullptr);
	who->closure_elements = this->closure_elements;

	return who;
	}

// Each ClosureFrame knows all of the outer IDs that are used inside of it. This is known at
// parse time. These leverage that. If frame_1 encloses frame_2 then the location of a lookup
// for an outer id in frame_2 can be determined by checking if that id is also an outer id in
// frame_2. If it is not, then frame_2 owns the id and the lookup is done there, otherwise, 
// go deeper.

// Note the useage of dynamic_cast.


Val* ClosureFrame::GatherFromClosure(const Frame* start, const ID* id)
	{
	const ClosureFrame* conductor = dynamic_cast<const ClosureFrame*>(start);

	if ( ! conductor )
		return start->NthElement(id->Offset());

	if (conductor->closure_contains(id))
		return ClosureFrame::GatherFromClosure(conductor->closure, id);

	return conductor->NthElement(id->Offset());
        }

void ClosureFrame::SetInClosure(Frame* start, const ID* id, Val* val)
        {
	ClosureFrame* conductor = dynamic_cast<ClosureFrame*>(start);

	if ( ! conductor )
	  start->SetElement(id->Offset(), val);

	else if (conductor->closure_contains(id))
	  ClosureFrame::SetInClosure(conductor->closure, id, val);

	else
	  conductor->Frame::SetElement(id->Offset(), val);
	}

// See the file "COPYING" in the main distribution directory for copyright.

#include "zeek-config.h"

#include "Frame.h"
#include "Stmt.h"
#include "Func.h"
#include "Trigger.h"

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

Frame::~Frame()
	{
	Unref(trigger);
	Release();
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

	for ( int i = 0; i < size; ++i )
		f->frame[i] = frame[i] ? frame[i]->Clone() : 0;

	if ( trigger )
		Ref(trigger);
	f->trigger = trigger;
	f->call = call;

	return f;
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

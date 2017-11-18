// See the file "COPYING" in the main distribution directory for copyright.

#include "bro-config.h"

#include "Frame.h"
#include "Stmt.h"
#include "Func.h"

vector<Frame*> g_frame_stack;

Frame::Frame(int arg_size, const BroFunc* func, const val_list* fn_args)
	{
	size = arg_size;
	frame = new Val*[size];
	function = func;
	func_args = fn_args;
	delete_func_args = false;

	next_stmt = 0;
	break_before_next_stmt = false;
	break_on_return = false;

	call = 0;
	delayed = false;

	fiber = 0;

	Clear();
	}

Frame::~Frame()
	{
	Release();

	if ( delete_func_args )
		delete_vals(const_cast<val_list *>(func_args));
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
	Frame* f = new Frame(size, function, 0);

	for ( int i = 0; i < size; ++i )
		f->frame[i] = frame[i] ? frame[i]->Clone() : 0;

	auto new_func_args = new val_list;
	f->func_args = new_func_args;
	f->delete_func_args = true;

	loop_over_list((*func_args), j)
		{
		auto arg = (*func_args)[j];
		if ( arg )
			arg = arg->Clone();
  		new_func_args->append(arg);
		}

	// Don't copy other fields.

	return f;
	}


Frame* Frame::ShallowCopy()
	{
	Frame* f = new Frame(size, function, nullptr);

	for ( int i = 0; i < size; ++i )
		f->frame[i] = frame[i] ? frame[i]->Ref() : 0;

	auto new_func_args = new val_list;
	f->func_args = new_func_args;
	f->delete_func_args = true;

	loop_over_list((*func_args), j)
		{
		auto arg = (*func_args)[j];
		if ( arg )
			Ref(arg);
  		new_func_args->append(arg);
		}

	// Don't copy other fields.

	return f;
	}

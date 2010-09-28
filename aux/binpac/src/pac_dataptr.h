#ifndef pac_dataptr_h
#define pac_dataptr_h

#include <string>
#include "pac_common.h"

// A data pointer is represented by an data pointer variable
// plus a constant offset.

class DataPtr
{
public:
	DataPtr(Env* env, const ID* arg_id, const int arg_off);

	DataPtr const &operator=(DataPtr const &x)
		{
		id_ = x.id();
		offset_ = x.offset();
		ptr_expr_ = x.ptr_expr();

		return *this;
		}

	const ID* id() const 	{ return id_; }
	int offset() const 	{ return offset_; }

	const char* ptr_expr() const
		{
		ASSERT(id_); 
		return ptr_expr_.c_str(); 
		}

	int AbsOffset(const ID* base_ptr) const;
	char* AbsOffsetExpr(Env* env, const ID* base_ptr) const;

	void GenBoundaryCheck(Output* out, 
                              Env* env, 
                              const char* data_size, 
                              const char* data_name) const;

protected:
	const ID* id_;
	int offset_;
	string ptr_expr_;
};

#endif  // pac_dataptr_h

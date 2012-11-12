#include "pac_exception.h"
#include "pac_id.h"
#include "pac_output.h"
#include "pac_utils.h"

#include "pac_dataptr.h"

DataPtr::DataPtr(Env* env, const ID* id, const int offset)
	: id_(id), offset_(offset)
	{
	if ( id_ )
		{
		if ( ! env->Evaluated(id_) )
			throw ExceptionIDNotEvaluated(id_);

		if ( offset_ == 0 )
			ptr_expr_ = strfmt("%s", env->RValue(id_));
		else
			ptr_expr_ = strfmt("(%s + %d)", env->RValue(id_), offset_);
		}
	else
		ptr_expr_ = "(null id)";
	}

int DataPtr::AbsOffset(const ID* base_ptr) const
	{
	return ( id() == base_ptr ) ? offset() : -1;
	}

char* DataPtr::AbsOffsetExpr(Env* env, const ID* base_ptr) const
	{
	if ( AbsOffset(base_ptr) >= 0 )
		return nfmt("%d", offset());
	else
		return nfmt("(%s - %s)", ptr_expr(), env->RValue(base_ptr));
	}

void DataPtr::GenBoundaryCheck(Output* out_cc, Env* env,
		const char* data_size, const char* data_name) const
	{
	ASSERT(id_);

	out_cc->println("// Checking out-of-bound for \"%s\"", data_name);
	out_cc->println("if ( %s + (%s) > %s )",
		ptr_expr(),
		data_size,
		env->RValue(end_of_data));

	out_cc->inc_indent(); 
	out_cc->println("{");

	char* data_offset = AbsOffsetExpr(env, begin_of_data); 

	out_cc->println("// Handle out-of-bound condition");
	out_cc->println("throw binpac::ExceptionOutOfBound(\"%s\",", data_name);
	out_cc->println("	(%s) + (%s), ", 
		data_offset, data_size);
	out_cc->println("	(%s) - (%s));", 
		env->RValue(end_of_data), env->RValue(begin_of_data));

	delete [] data_offset;

	out_cc->println("}");
	out_cc->dec_indent(); 
	}


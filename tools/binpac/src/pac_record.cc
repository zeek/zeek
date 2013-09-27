#include "pac_attr.h"
#include "pac_dataptr.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_field.h"
#include "pac_output.h"
#include "pac_record.h"
#include "pac_type.h"
#include "pac_typedecl.h"
#include "pac_utils.h"
#include "pac_varfield.h"


RecordType::RecordType(RecordFieldList* record_fields)
	: Type(RECORD)
	{
	// Here we assume that the type is a standalone type.
	value_var_ = 0;

	// Put all fields in fields_
	foreach (i, RecordFieldList, record_fields)
		AddField(*i);

	// Put RecordField's in record_fields_
	record_fields_ = record_fields;

	parsing_dataptr_var_field_ = 0;
	}

RecordType::~RecordType()
	{
	// Do not delete_list(RecordFieldList, record_fields_)
	// because the fields are also in fields_.
	delete record_fields_;
	delete parsing_dataptr_var_field_;
	}

const ID *RecordType::parsing_dataptr_var() const
	{ 
	return parsing_dataptr_var_field_ ?
		parsing_dataptr_var_field_->id() : 0;
	}

bool RecordType::DefineValueVar() const
	{
	return false;
	}

string RecordType::DataTypeStr() const
	{
	ASSERT(type_decl());
	return strfmt("%s *", type_decl()->class_name().c_str());
	}

void RecordType::Prepare(Env* env, int flags)
	{
	ASSERT(flags & TO_BE_PARSED);

	RecordField *prev = 0;
	int offset = 0;
	int seq = 0;
	foreach (i, RecordFieldList, record_fields_)
		{
		RecordField *f = *i;
		f->set_record_type(this);
		f->set_prev(prev);
		if ( prev )
			prev->set_next(f);
		prev = f;
		if ( offset >= 0 )
			{
			f->set_static_offset(offset);
			int w = f->StaticSize(env, offset);
			if ( w < 0 )
				offset = -1;
			else
				offset += w;
			}
		++seq;
		f->set_parsing_state_seq(seq);
		}

	if ( incremental_parsing() )
		{
#if 0
		ASSERT(! parsing_state_var_field_);
		ID *parsing_state_var_id = new ID("parsing_state");
		parsing_state_var_field_ = new PrivVarField(
			parsing_state_var_id, extern_type_int->Clone());
		AddField(parsing_state_var_field_);

		ID *parsing_dataptr_var_id = new ID("parsing_dataptr");
		parsing_dataptr_var_field_ = new TempVarField(
			parsing_dataptr_var_id, extern_type_const_byteptr->Clone());
		parsing_dataptr_var_field_->Prepare(env);
#endif
		}

	Type::Prepare(env, flags);
	}

void RecordType::GenPubDecls(Output* out_h, Env* env)
	{
	Type::GenPubDecls(out_h, env);
	}

void RecordType::GenPrivDecls(Output* out_h, Env* env)
	{
	Type::GenPrivDecls(out_h, env);
	}

void RecordType::GenInitCode(Output* out_cc, Env* env)
	{
	Type::GenInitCode(out_cc, env);
	}

void RecordType::GenCleanUpCode(Output* out_cc, Env* env)
	{
	Type::GenCleanUpCode(out_cc, env);
	}

void RecordType::DoGenParseCode(Output* out_cc, Env* env, 
		const DataPtr& data, int flags)
	{
	  if ( !incremental_input() && StaticSize(env) >= 0 )
		GenBoundaryCheck(out_cc, env, data);

	if ( incremental_parsing() )
		{
		out_cc->println("switch ( %s ) {",
			env->LValue(parsing_state_id));

		out_cc->println("case 0:");
		out_cc->inc_indent();
		foreach (i, RecordFieldList, record_fields_)
			{
			RecordField *f = *i;
			f->GenParseCode(out_cc, env);
			out_cc->println("");
			}
		out_cc->println("");
		out_cc->println("%s = true;", 
			env->LValue(parsing_complete_var()));
		out_cc->dec_indent();
		out_cc->println("}");
		}
	else
		{
		ASSERT(	data.id() == begin_of_data && 
			data.offset() == 0 );
		foreach (i, RecordFieldList, record_fields_)
			{
			RecordField *f = *i;
			f->GenParseCode(out_cc, env);
			out_cc->println("");
			}
		if ( incremental_input() )
			{
			ASSERT(parsing_complete_var());
			out_cc->println("%s = true;", 
				env->LValue(parsing_complete_var()));
			}
		}

	if ( ! incremental_input() && AddSizeVar(out_cc, env) )
		{
		const DataPtr& end_of_record_dataptr = 
			record_fields_->back()->getFieldEnd(out_cc, env);

		out_cc->println("%s = %s - %s;", 
			env->LValue(size_var()), 
			end_of_record_dataptr.ptr_expr(), 
			env->RValue(begin_of_data));
		env->SetEvaluated(size_var());
		}

	if ( ! boundary_checked() )
		{
		RecordField *last_field = record_fields_->back();
		if ( ! last_field->BoundaryChecked() )
			GenBoundaryCheck(out_cc, env, data);
		}
	}

void RecordType::GenDynamicSize(Output* out_cc, Env* env,
		const DataPtr& data)
	{
	GenParseCode(out_cc, env, data, 0);
	}

int RecordType::StaticSize(Env* env) const
	{
	int tot_w = 0;
	foreach (i, RecordFieldList, record_fields_)
		{
		RecordField *f = *i;
		int w = f->StaticSize(env, tot_w);
		if ( w < 0 )
			return -1;
		tot_w += w;
		}
	return tot_w;
	}

void RecordType::SetBoundaryChecked()
	{
	Type::SetBoundaryChecked();
	foreach (i, RecordFieldList, record_fields_)
		{
		RecordField *f = *i;
		f->SetBoundaryChecked();
		}
	}

void RecordType::DoMarkIncrementalInput()
	{
	foreach (i, RecordFieldList, record_fields_)
		{
		RecordField *f = *i;
		f->type()->MarkIncrementalInput();
		}
	}

bool RecordType::DoTraverse(DataDepVisitor *visitor)
	{
	return Type::DoTraverse(visitor);
	}

bool RecordType::ByteOrderSensitive() const
	{
	foreach (i, RecordFieldList, record_fields_)
		{
		RecordField *f = *i;
		if ( f->RequiresByteOrder() )
			return true;
		}
	return false;
	}

RecordField::RecordField(FieldType tof, ID *id, Type *type)
	: Field(tof, 
		TYPE_TO_BE_PARSED | CLASS_MEMBER | PUBLIC_READABLE,
		id, type)
	{
	begin_of_field_dataptr = 0;
	end_of_field_dataptr = 0;
	field_size_expr = 0;
	field_offset_expr = 0;
	end_of_field_dataptr_var = 0;
	record_type_ = 0;
	prev_ = 0;
	next_ = 0;
	static_offset_ = -1;
	parsing_state_seq_ = 0;
	boundary_checked_ = false;
	}

RecordField::~RecordField()
	{
	delete begin_of_field_dataptr;
	delete end_of_field_dataptr;
	delete [] field_size_expr;
	delete [] field_offset_expr;
	delete end_of_field_dataptr_var;
	}

const DataPtr& RecordField::getFieldBegin(Output* out_cc, Env* env)
	{
	if ( prev() )
		return prev()->getFieldEnd(out_cc, env);
	else
		{
		// The first field
		if ( ! begin_of_field_dataptr )
			{
			begin_of_field_dataptr = 
				new DataPtr(env, begin_of_data, 0);
			}
		return *begin_of_field_dataptr;
		}	
	}

const DataPtr& RecordField::getFieldEnd(Output* out_cc, Env* env)
	{
	if ( end_of_field_dataptr )
		return *end_of_field_dataptr;

	const DataPtr& begin_ptr = getFieldBegin(out_cc, env);

	if ( record_type()->incremental_parsing() )
		{
		ASSERT(0);
		if ( ! end_of_field_dataptr )
			{
			const ID *dataptr_var = 
				record_type()->parsing_dataptr_var();
			ASSERT(dataptr_var);

			end_of_field_dataptr = 
				new DataPtr(env, dataptr_var, 0);
			}
		}
	else
		{
		int field_offset;
		if ( begin_ptr.id() == begin_of_data )
			field_offset = begin_ptr.offset();
		else
			field_offset = -1;	// unknown
			
		int field_size = StaticSize(env, field_offset);
		if ( field_size >= 0 ) // can be statically determinted 
			{
			end_of_field_dataptr = new DataPtr(
				env,
				begin_ptr.id(), 
				begin_ptr.offset() + field_size);
			}
		else
			{
			// If not, we add a variable for the offset after the field
			end_of_field_dataptr_var = new ID(
				fmt("dataptr_after_%s", id()->Name()));
			env->AddID(end_of_field_dataptr_var, 
		           	TEMP_VAR, 
		           	extern_type_const_byteptr);

			GenFieldEnd(out_cc, env, begin_ptr);

			end_of_field_dataptr = new DataPtr(
				env, 
				end_of_field_dataptr_var, 
				0);
			}
		}

	return *end_of_field_dataptr;
	}

const char* RecordField::FieldSize(Output* out_cc, Env* env)
	{
	if ( field_size_expr )
		return field_size_expr;

	const DataPtr& begin = getFieldBegin(out_cc, env);
	const DataPtr& end = getFieldEnd(out_cc, env);
	if ( begin.id() == end.id() )
		field_size_expr = nfmt("%d", end.offset() - begin.offset());
	else
		field_size_expr = nfmt("(%s - %s)", end.ptr_expr(), begin.ptr_expr());
	return field_size_expr;
	}

const char* RecordField::FieldOffset(Output* out_cc, Env* env)
	{
	if ( field_offset_expr )
		return field_offset_expr;

	const DataPtr& begin = getFieldBegin(out_cc, env);
	if ( begin.id() == begin_of_data )
		field_offset_expr = nfmt("%d", begin.offset());
	else
		field_offset_expr = nfmt("(%s - %s)", 
			begin.ptr_expr(), env->RValue(begin_of_data));
	return field_offset_expr;
	}

// The reasoning behind AttemptBoundaryCheck is: "If my next field
// can check its boundary, then I don't have to check mine, and it
// will save me a boundary-check."
bool RecordField::AttemptBoundaryCheck(Output* out_cc, Env* env)
	{
	if ( boundary_checked_ )
		return true;

	// If I do not even know my size till I parse the data, my
	// next field won't be able to check its boundary now.  

	const DataPtr& begin = getFieldBegin(out_cc, env);
	if ( StaticSize(env, begin.AbsOffset(begin_of_data)) < 0 )
		return false;

	// Now we ask the next field to check its boundary. 
	if ( next() && next()->AttemptBoundaryCheck(out_cc, env) ) 
		{
		// If it works, we are all set
		SetBoundaryChecked();
		return true;
		}
	else
		// If it fails, then I can still try to do it by myself
		return GenBoundaryCheck(out_cc, env);
	}

RecordDataField::RecordDataField(ID* id, Type* type)
	: RecordField(RECORD_FIELD, id, type)
	{
	ASSERT(type_);
	}

RecordDataField::~RecordDataField()
	{
	}

void RecordDataField::Prepare(Env* env)
	{
	Field::Prepare(env);
	env->SetEvalMethod(id_, this);
	env->SetField(id_, this);
	}

void RecordDataField::GenParseCode(Output* out_cc, Env* env)
	{
	if ( env->Evaluated(id()) )
		return;

	// Always evaluate record fields in order if parsing
	// is incremental.
	if ( record_type()->incremental_parsing() && prev() )
		prev()->GenParseCode(out_cc, env);

	DataPtr data(env, 0, 0);
	if ( ! record_type()->incremental_parsing() )
		{
		data = getFieldBegin(out_cc, env);	
		AttemptBoundaryCheck(out_cc, env);
		}

	out_cc->println("// Parse \"%s\"", id_->Name());
#if 0
	out_cc->println("DEBUG_MSG(\"%%.6f Parse %s\\n\", network_time());", 
		id_->Name());
#endif
	type_->GenPreParsing(out_cc, env);
	if ( type_->incremental_input() )
		{
		// The enclosing record type must be incrementally parsed
		out_cc->println("%s = %d;", 
			env->LValue(parsing_state_id),
			parsing_state_seq());
		out_cc->dec_indent();
		out_cc->println("case %d:", parsing_state_seq());
		out_cc->inc_indent();
		out_cc->println("{");
		}

	type_->GenParseCode(out_cc, env, data, 0);

	if ( record_type()->incremental_parsing() )
		{
		ASSERT(type_->incremental_input());

		out_cc->println("if ( ! (%s) )", 
			type_->parsing_complete(env).c_str());
		out_cc->inc_indent();
		out_cc->println("goto %s;", kNeedMoreData);
		out_cc->dec_indent();
		}

	if ( record_type()->incremental_parsing() )
		{
#if 0
		const ID *dataptr_var = 
			record_type()->parsing_dataptr_var();
		ASSERT(dataptr_var);
		out_cc->println("%s += (%s);",
			env->LValue(dataptr_var),
			type_->DataSize(out_cc, env, data).c_str());
#endif
		out_cc->println("}");
		}

	SetBoundaryChecked();
	}

void RecordDataField::GenEval(Output* out_cc, Env* env)
	{
	GenParseCode(out_cc, env);
	}

void RecordDataField::GenFieldEnd(Output* out_cc, Env* env, 
		const DataPtr& field_begin)
	{
	out_cc->println("const_byteptr const %s = %s + (%s);", 
		env->LValue(end_of_field_dataptr_var),
		field_begin.ptr_expr(),
		type_->DataSize(out_cc, env, field_begin).c_str());
	env->SetEvaluated(end_of_field_dataptr_var);

	out_cc->println("BINPAC_ASSERT(%s <= %s);",
		env->RValue(end_of_field_dataptr_var),
		env->RValue(end_of_data));
	}

void RecordDataField::SetBoundaryChecked()
	{
	RecordField::SetBoundaryChecked();
	type_->SetBoundaryChecked();
	}

bool RecordDataField::GenBoundaryCheck(Output* out_cc, Env* env)
	{
	if ( boundary_checked_ )
		return true;

	type_->GenBoundaryCheck(out_cc, env, getFieldBegin(out_cc, env));

	SetBoundaryChecked();
	return true;
	}

bool RecordDataField::DoTraverse(DataDepVisitor *visitor)
	{ 
	return Field::DoTraverse(visitor);
	}

bool RecordDataField::RequiresAnalyzerContext() const 
	{ 
	return Field::RequiresAnalyzerContext() ||
	       type()->RequiresAnalyzerContext(); 
	}

RecordPaddingField::RecordPaddingField(ID* id, PaddingType ptype, Expr* expr)
	: RecordField(PADDING_FIELD, id, 0), ptype_(ptype), expr_(expr)
	{
	wordsize_ = -1;
	}

RecordPaddingField::~RecordPaddingField()
	{
	}

void RecordPaddingField::Prepare(Env* env)
	{
	Field::Prepare(env);
	if ( ptype_ == PAD_TO_NEXT_WORD )
		{
		if ( ! expr_->ConstFold(env, &wordsize_) )
			throw ExceptionPaddingError(this, 
				fmt("padding word size not a constant"));
		}
	}

void RecordPaddingField::GenParseCode(Output* out_cc, Env* env)
	{
	// Always evaluate record fields in order if parsing
	// is incremental.
	if ( record_type()->incremental_parsing() && prev() )
		prev()->GenParseCode(out_cc, env);
	}

int RecordPaddingField::StaticSize(Env* env, int offset) const
	{
	int length;
	int target_offset;
	int offset_in_word;

	switch ( ptype_ )
		{
		case PAD_BY_LENGTH:
			return expr_->ConstFold(env, &length) ? length : -1;

		case PAD_TO_OFFSET:
			// If the current offset cannot be statically
			// determined, we need to Generate code to
			// check the offset
			if ( offset == -1 )
				return -1;

			if ( ! expr_->ConstFold(env, &target_offset) )
				return -1;

			// If both the current and target offsets
			// can be statically computed, we can get its
			// static size
			if ( offset > target_offset )
				throw ExceptionPaddingError(
					this,
					fmt("current offset = %d, "
					    "target offset = %d", 
					    offset, target_offset));
			return target_offset - offset;

		case PAD_TO_NEXT_WORD:
			if ( offset == -1 || wordsize_ == -1 )
				return -1;

			offset_in_word = offset % wordsize_;
			return ( offset_in_word == 0 ) ? 
				0 : wordsize_ - offset_in_word;
		}

	return -1;
	}

void RecordPaddingField::GenFieldEnd(Output* out_cc, Env* env, const DataPtr& field_begin)
	{
	ASSERT(! env->Evaluated(end_of_field_dataptr_var));

	char* padding_var;
	switch ( ptype_ )
		{
		case PAD_BY_LENGTH:
			out_cc->println("const_byteptr const %s = %s + (%s);",
				env->LValue(end_of_field_dataptr_var),
				field_begin.ptr_expr(),
				expr_->EvalExpr(out_cc, env));
			break;

		case PAD_TO_OFFSET:
			out_cc->println("const_byteptr %s = %s + (%s);",
				env->LValue(end_of_field_dataptr_var),
				env->RValue(begin_of_data),
				expr_->EvalExpr(out_cc, env));
			out_cc->println("if ( %s < %s )",
				env->LValue(end_of_field_dataptr_var),
				field_begin.ptr_expr());
			out_cc->inc_indent();
			out_cc->println("{");
			out_cc->println("// throw binpac::ExceptionInvalidOffset(\"%s\", %s - %s, %s);",
				id_->LocName(), 
				field_begin.ptr_expr(),
				env->RValue(begin_of_data),
				expr_->EvalExpr(out_cc, env));
			out_cc->println("%s = %s;", 
				env->LValue(end_of_field_dataptr_var),
				field_begin.ptr_expr());
			out_cc->println("}");
			out_cc->dec_indent();
			break;

		case PAD_TO_NEXT_WORD:
			padding_var = nfmt("%s__size", id()->Name());
			out_cc->println("int %s = (%s - %s) %% %d;",
				padding_var, 
				field_begin.ptr_expr(),
				env->RValue(begin_of_data),
				wordsize_);
			out_cc->println("%s = (%s == 0) ? 0 : %d - %s;",
				padding_var,
				padding_var,
				wordsize_,
				padding_var);
			out_cc->println("const_byteptr const %s = %s + %s;",
				env->LValue(end_of_field_dataptr_var), 
				field_begin.ptr_expr(),
				padding_var);
			delete [] padding_var;
			break;
		}

	env->SetEvaluated(end_of_field_dataptr_var);
	}

bool RecordPaddingField::GenBoundaryCheck(Output* out_cc, Env* env)
	{
	if ( boundary_checked_ )
		return true;

	const DataPtr& begin = getFieldBegin(out_cc, env);

	char* size;
	int ss = StaticSize(env, begin.AbsOffset(begin_of_data));
	ASSERT ( ss >= 0 );
 	size = nfmt("%d", ss);
	
	begin.GenBoundaryCheck(out_cc, env, size, field_id_str_.c_str());

	delete [] size;

	SetBoundaryChecked();
	return true;
	}

bool RecordPaddingField::DoTraverse(DataDepVisitor *visitor)
	{ 
	return Field::DoTraverse(visitor) && 
	       (! expr_ || expr_->Traverse(visitor));
	}


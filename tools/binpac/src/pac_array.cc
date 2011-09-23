#include "pac_attr.h"
#include "pac_dataptr.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_id.h"
#include "pac_number.h"
#include "pac_output.h"
#include "pac_utils.h"
#include "pac_varfield.h"

#include "pac_array.h"

ArrayType::ArrayType(Type *elemtype, Expr *length)
	: Type(ARRAY), elemtype_(elemtype), length_(length)
	{
	init();

	switch ( elemtype_->tot() )
		{
		case BUILTIN:
		case PARAMETERIZED:
		case STRING:
		case EXTERN:
			break;

		case ARRAY:
		case CASE:
		case DUMMY:
		case EMPTY:
		case RECORD:
		case UNDEF:
			ASSERT(0);
			break;
		}
	}

void ArrayType::init()
	{
	arraylength_var_field_ = 0;
	elem_it_var_field_ = 0;
	elem_var_field_ = 0;
	elem_dataptr_var_field_ = 0;
	elem_input_var_field_ = 0;

	elem_dataptr_until_expr_ = 0;

	end_of_array_loop_label_ = "@@@";

	vector_str_ = strfmt("vector<%s>", elemtype_->DataTypeStr().c_str());

	datatype_str_ = strfmt("%s *", vector_str_.c_str());

	attr_generic_until_expr_ = 0;
	attr_until_element_expr_ = 0;
	attr_until_input_expr_ = 0;
	}

ArrayType::~ArrayType()
	{
	delete arraylength_var_field_;
	delete elem_it_var_field_;
	delete elem_var_field_;
	delete elem_dataptr_var_field_;
	delete elem_input_var_field_;

	delete elem_dataptr_until_expr_;
	}

Type *ArrayType::DoClone() const
	{
	Type *elemtype = elemtype_->Clone();
	if ( ! elemtype )
		return 0;
	return new ArrayType(elemtype, length_);
	}

bool ArrayType::DefineValueVar() const
	{
	return true;
	}

string ArrayType::DataTypeStr() const
	{
	return datatype_str_;
	}

Type *ArrayType::ElementDataType() const
	{
	return elemtype_;
	}

string ArrayType::EvalElement(const string &array, const string &index) const
	{
	if ( attr_transient_ )
	    throw Exception(this, "cannot access element in &transient array");

	return strfmt("(*(%s))[%s]", array.c_str(), index.c_str());
	}

const ID *ArrayType::arraylength_var() const
	{
	return arraylength_var_field_ ? arraylength_var_field_->id() : 0;
	}

const ID *ArrayType::elem_it_var() const
	{
	return elem_it_var_field_ ? elem_it_var_field_->id() : 0;
	}

const ID *ArrayType::elem_var() const
	{
	return elem_var_field_ ? elem_var_field_->id() : 0;
	}

const ID *ArrayType::elem_dataptr_var() const
	{
	return elem_dataptr_var_field_ ? elem_dataptr_var_field_->id() : 0;
	}

const ID *ArrayType::elem_input_var() const
	{
	return elem_input_var_field_ ? elem_input_var_field_->id() : 0;
	}

void ArrayType::ProcessAttr(Attr *a)
	{
	Type::ProcessAttr(a);

	switch ( a->type() )
		{
		case ATTR_RESTOFDATA:
			{
			if ( elemtype_->StaticSize(env()) != 1 )
				{
				throw Exception(elemtype_,
					"&restofdata can be applied"
					" to only byte arrays");
				}
			if ( length_ )
				{
				throw Exception(length_,
					"&restofdata cannot be applied"
					" to arrays with specified length");
				}
			attr_restofdata_ = true;
			// As the array automatically extends to the end of
			// data, we do not have to check boundary.
			SetBoundaryChecked();
			}
			break;

		case ATTR_RESTOFFLOW:
			attr_restofflow_ = true;
			// TODO: handle &restofflow
			break;

		case ATTR_UNTIL:
			{
			bool ref_element = a->expr()->HasReference(element_macro_id);
			bool ref_input = a->expr()->HasReference(input_macro_id);
			if ( ref_element && ref_input )
				{
				throw Exception(a->expr(),
					"cannot reference both $element and $input "
					"in the same &until---please separate them.");
				}

			if ( ref_element )
				{
				if ( attr_until_element_expr_ )
					{
					throw Exception(a->expr(),
						"multiple &until on $element");
					}
				attr_until_element_expr_ = a->expr();
				}
			else if ( ref_input )
				{
				if ( attr_until_input_expr_ )
					{
					throw Exception(a->expr(),
						"multiple &until on $input");
					}
				attr_until_input_expr_ = a->expr();
				}
			else
				{
				if ( attr_generic_until_expr_ )
					{
					throw Exception(a->expr(),
						"multiple &until condition");
					}
				attr_generic_until_expr_ = a->expr();
				}
			}
			break;

		default:
			break;
		}
	}

void ArrayType::Prepare(Env *env, int flags)
	{
	if ( flags & TO_BE_PARSED )
		{
		ID *arraylength_var = new ID(fmt("%s__arraylength", value_var()->Name()));
		ID *elem_var = new ID(fmt("%s__elem", value_var()->Name()));
		ID *elem_it_var = new ID(fmt("%s__it", elem_var->Name()));

		elem_var_field_ =
			new ParseVarField(Field::CLASS_MEMBER, elem_var, elemtype_);
		AddField(elem_var_field_);

		if ( incremental_parsing() )
			{
			arraylength_var_field_ =
				new PrivVarField(arraylength_var, extern_type_int->Clone());
			elem_it_var_field_ =
				new PrivVarField(elem_it_var, extern_type_int->Clone());

			AddField(arraylength_var_field_);
			AddField(elem_it_var_field_);
			}
		else
			{
			arraylength_var_field_ =
				new TempVarField(arraylength_var, extern_type_int->Clone());
			elem_it_var_field_ =
				new TempVarField(elem_it_var, extern_type_int->Clone());

			arraylength_var_field_->Prepare(env);
			elem_it_var_field_->Prepare(env);

			// Add elem_dataptr_var only when not parsing incrementally
			ID *elem_dataptr_var =
				new ID(fmt("%s__dataptr", elem_var->Name()));
			elem_dataptr_var_field_ = new TempVarField(
				elem_dataptr_var,
				extern_type_const_byteptr->Clone());
			elem_dataptr_var_field_->Prepare(env);

			// until(dataptr >= end_of_data)
			elem_dataptr_until_expr_ = new Expr(
				Expr::EXPR_GE,
				new Expr(elem_dataptr_var->clone()),
				new Expr(end_of_data->clone()));
			}

		if ( attr_until_input_expr_ )
			{
			elemtype_->SetUntilCheck(this);
			}

		end_of_array_loop_label_ = strfmt("end_of_%s", value_var()->Name());
		}

	Type::Prepare(env, flags);
	}

void ArrayType::GenArrayLength(Output *out_cc, Env *env, const DataPtr& data)
	{
	if ( env->Evaluated(arraylength_var()) )
		return;

	if ( ! incremental_parsing() )
		{
		arraylength_var_field_->GenTempDecls(out_cc, env);
		arraylength_var_field_->GenInitCode(out_cc, env);
		}

	if ( length_ )
		{
		out_cc->println("%s = %s;",
			env->LValue(arraylength_var()),
			length_->EvalExpr(out_cc, env));

		env->SetEvaluated(arraylength_var());

		// Check for overlong array length. We cap it at the
		// maximum data size as we won't store more elements.
		out_cc->println("if ( t_begin_of_data + %s > t_end_of_data + 1 )",
			env->LValue(arraylength_var()));
		out_cc->inc_indent();
		out_cc->println("{");
		out_cc->println("%s = t_end_of_data - t_begin_of_data + 1;",
			env->LValue(arraylength_var()));
		out_cc->println("}");
		out_cc->dec_indent();

		// Check negative array length
		out_cc->println("if ( %s < 0 )",
			env->LValue(arraylength_var()));
		out_cc->inc_indent();
		out_cc->println("{");
		out_cc->println("%s = 0;",
			env->LValue(arraylength_var()));
		out_cc->println("}");
		out_cc->dec_indent();
		}
	else if ( attr_restofdata_ )
		{
		ASSERT(elemtype_->StaticSize(env) == 1);
		out_cc->println("%s = (%s) - (%s);",
			env->LValue(arraylength_var()),
			env->RValue(end_of_data),
			data.ptr_expr());
		env->SetEvaluated(arraylength_var());
		}
	}

void ArrayType::GenPubDecls(Output *out_h, Env *env)
	{
	Type::GenPubDecls(out_h, env);

	if ( declared_as_type() )
		{
		if ( attr_transient_ )
		    throw Exception(this, "cannot access element in &transient array");

		out_h->println("int size() const	{ return %s ? %s->size() : 0; }",
			env->RValue(value_var()),
			env->RValue(value_var()));
		out_h->println("%s operator[](int index) const { BINPAC_ASSERT(%s); return (*%s)[index]; }",
			elemtype_->DataTypeConstRefStr().c_str(),
			env->RValue(value_var()),
			env->RValue(value_var()));
		}
	}

void ArrayType::GenPrivDecls(Output *out_h, Env *env)
	{
	ASSERT(elem_var_field_->type() == elemtype_);
	ASSERT(elemtype_->value_var());
	Type::GenPrivDecls(out_h, env);
	}

void ArrayType::GenInitCode(Output *out_cc, Env *env)
	{
	// Do not initiate the array here
	// out_cc->println("%s = new %s;", lvalue(), vector_str_.c_str());
	out_cc->println("%s = 0;", lvalue());

	Type::GenInitCode(out_cc, env);
	if ( incremental_parsing() )
		{
		out_cc->println("%s = -1;",
			env->LValue(elem_it_var()));
		}
	}

void ArrayType::GenCleanUpCode(Output *out_cc, Env *env)
	{
	Type::GenCleanUpCode(out_cc, env);
	if ( elemtype_->NeedsCleanUp() )
		{
		if ( ! elem_var_field_ )
			{
			ID *elem_var = new ID(fmt("%s__elem", value_var()->Name()));
			elem_var_field_ =
				new ParseVarField(
					Field::NOT_CLASS_MEMBER,
					elem_var,
					elemtype_);
			elem_var_field_->Prepare(env);
			}

		out_cc->println("if ( %s )", env->RValue(value_var()));
		out_cc->inc_indent();
		out_cc->println("{");

		out_cc->println("for ( int i = 0; i < (int) %s->size(); ++i )",
			env->RValue(value_var()));
		out_cc->inc_indent();
		out_cc->println("{");
		out_cc->println("%s %s = (*%s)[i];",
			elemtype_->DataTypeStr().c_str(),
			env->LValue(elem_var()),
			lvalue());
		elemtype_->GenCleanUpCode(out_cc, env);
		out_cc->println("}");
		out_cc->dec_indent();

		out_cc->println("}");
		out_cc->dec_indent();
		}
	out_cc->println("delete %s;", lvalue());
	}

string ArrayType::GenArrayInit(Output *out_cc, Env *env, bool known_array_length)
	{
	string array_str;

	array_str = lvalue();
	if ( incremental_parsing() )
		{
		out_cc->println("if ( %s < 0 )",
			env->LValue(elem_it_var()));
		out_cc->inc_indent();
		out_cc->println("{");
		out_cc->println("// Initialize only once");
		out_cc->println("%s = 0;", env->LValue(elem_it_var()));
		}

	out_cc->println("%s = new %s;",
		lvalue(), vector_str_.c_str());

	if ( known_array_length )
		{
		out_cc->println("%s->reserve(%s);",
			lvalue(), env->RValue(arraylength_var()));
		}

	if ( incremental_parsing() )
		{
		out_cc->println("}");
		out_cc->dec_indent();
		}

	return array_str;
	}

void ArrayType::GenElementAssignment(Output *out_cc, Env *env,
		string const &array_str, bool use_vector)
	{
	if ( attr_transient_ )
	    {
	    // Just discard.
	    out_cc->println("delete %s;", env->LValue(elem_var()));
	    return;
	    }

	// Assign the element
	if ( ! use_vector )
		{
		out_cc->println("%s[%s] = %s;",
			array_str.c_str(),
			env->LValue(elem_it_var()),
			env->LValue(elem_var()));
		}
	else
		{
		out_cc->println("%s->push_back(%s);",
			array_str.c_str(),
			env->LValue(elem_var()));
		}
	}

void ArrayType::DoGenParseCode(Output *out_cc, Env *env,
		const DataPtr& data, int flags)
	{
	GenArrayLength(out_cc, env, data);

	// Otherwise these variables are declared as member variables
	if ( ! incremental_parsing() )
		{
		// Declare and initialize temporary variables
		elem_var_field_->GenInitCode(out_cc, env);
		elem_it_var_field_->GenTempDecls(out_cc, env);
		out_cc->println("%s = 0;", env->LValue(elem_it_var()));
		env->SetEvaluated(elem_it_var());
		}

	/*
	If the input length can be determined without parsing
	individual elements, generate the boundary checking before
	parsing (unless in the case of incremental parsing).

	There are two cases when the input length can be determined:
	1. The array has a static size;
	2. The array length can be computed before parsing and
   	each element is of constant size.
	*/

	bool compute_size_var = false;

	if ( incremental_input() )
		{
		// Do not compute size_var on incremental input
		compute_size_var = false;

		if ( ! incremental_parsing() &&
		     ( StaticSize(env) >= 0 ||
		       ( env->Evaluated(arraylength_var()) &&
		         elemtype_->StaticSize(env) >= 0 ) ) )
			{
			GenBoundaryCheck(out_cc, env, data);
			}
		}
	else
		{
		compute_size_var = AddSizeVar(out_cc, env);
		}

	bool known_array_length = env->Evaluated(arraylength_var());
	string array_str = GenArrayInit(out_cc, env, known_array_length);

	bool use_vector = true;

	ASSERT(elem_it_var());

	DataPtr elem_data(env, 0, 0);

	if ( elem_dataptr_var() )
		{
		out_cc->println("const_byteptr %s = %s;",
			env->LValue(elem_dataptr_var()), data.ptr_expr());
		env->SetEvaluated(elem_dataptr_var());

		elem_data = DataPtr(env, elem_dataptr_var(), 0);
		}

	string for_condition = known_array_length ?
		strfmt("%s < %s",
			env->LValue(elem_it_var()),
			env->RValue(arraylength_var())) :
		"/* forever */";

	out_cc->println("for (; %s; ++%s)",
		for_condition.c_str(),
		env->LValue(elem_it_var()));
	out_cc->inc_indent();
	out_cc->println("{");

	if ( attr_generic_until_expr_ )
		GenUntilCheck(out_cc, env, attr_generic_until_expr_, true);

	if ( elem_dataptr_var() )
		GenUntilCheck(out_cc, env, elem_dataptr_until_expr_, false);

	elemtype_->GenPreParsing(out_cc, env);
	elemtype_->GenParseCode(out_cc, env, elem_data, flags);

	if ( incremental_parsing() )
		{
		out_cc->println("if ( ! %s )",
			elemtype_->parsing_complete(env).c_str());
		out_cc->inc_indent();
		out_cc->println("goto %s;", kNeedMoreData);
		out_cc->dec_indent();
		}

	GenElementAssignment(out_cc, env, array_str, use_vector);

	if ( elem_dataptr_var() )
		{
		out_cc->println("%s += %s;",
			env->LValue(elem_dataptr_var()),
			elemtype_->DataSize(0, env, elem_data).c_str());
		out_cc->println("BINPAC_ASSERT(%s <= %s);",
			env->RValue(elem_dataptr_var()),
			env->RValue(end_of_data));
		}

	if ( attr_until_element_expr_ )
		GenUntilCheck(out_cc, env, attr_until_element_expr_, false);

	if ( elemtype_->IsPointerType() )
		out_cc->println("%s = 0;", env->LValue(elem_var()));

	out_cc->println("}");
	out_cc->dec_indent();

	out_cc->dec_indent();
	out_cc->println("%s: ;", end_of_array_loop_label_.c_str());
	out_cc->inc_indent();

	if ( compute_size_var && elem_dataptr_var() && ! env->Evaluated(size_var()) )
		{
		// Compute the data size
		out_cc->println("%s = %s - (%s);",
			env->LValue(size_var()),
			env->RValue(elem_dataptr_var()),
			data.ptr_expr());
		env->SetEvaluated(size_var());
		}
	}

void ArrayType::GenUntilInputCheck(Output *out_cc, Env *env)
	{
	ID *elem_input_var_id = new ID(
		fmt("%s__elem_input", value_var()->Name()));
	elem_input_var_field_ = new TempVarField(
		elem_input_var_id, extern_type_const_bytestring->Clone());
	elem_input_var_field_->Prepare(env);

	out_cc->println("%s %s(%s, %s);",
		extern_type_const_bytestring->DataTypeStr().c_str(),
		env->LValue(elem_input_var()),
		env->RValue(begin_of_data),
		env->RValue(end_of_data));
	env->SetEvaluated(elem_input_var());

	GenUntilCheck(out_cc, env, attr_until_input_expr_, true);
	}

void ArrayType::GenUntilCheck(Output *out_cc, Env *env,
		Expr *until_expr, bool delete_elem)
	{
	ASSERT(until_expr);

	Env check_env(env, this);
	check_env.AddMacro(element_macro_id,
		new Expr(elem_var()->clone()));
	if ( elem_input_var() )
		{
		check_env.AddMacro(input_macro_id,
			new Expr(elem_input_var()->clone()));
		}

	out_cc->println("// Check &until(%s)", until_expr->orig());
	out_cc->println("if ( %s )",
		until_expr->EvalExpr(out_cc, &check_env));
	out_cc->inc_indent();
	out_cc->println("{");
	if ( parsing_complete_var() )
		{
		out_cc->println("%s = true;",
			env->LValue(parsing_complete_var()));
		}

	if ( elemtype_->IsPointerType() )
		{
		if ( delete_elem )
			elemtype_->GenCleanUpCode(out_cc, env);
		else
			out_cc->println("%s = 0;", env->LValue(elem_var()));
		}

	out_cc->println("goto %s;", end_of_array_loop_label_.c_str());
	out_cc->println("}");
	out_cc->dec_indent();
	}

void ArrayType::GenDynamicSize(Output *out_cc, Env *env,
		const DataPtr& data)
	{
	ASSERT(! incremental_input());
	DEBUG_MSG("Generating dynamic size for array `%s'\n",
		value_var()->Name());

	int elem_w = elemtype_->StaticSize(env);
	if ( elem_w >= 0 &&
	     ! attr_until_element_expr_ &&
	     ! attr_until_input_expr_ &&
	     ( length_ || attr_restofdata_ ) )
		{
		// If the elements have a fixed size,
		// we only need to compute the number of elements
		bool compute_size_var = AddSizeVar(out_cc, env);
		ASSERT(compute_size_var);
		GenArrayLength(out_cc, env, data);
		ASSERT(env->Evaluated(arraylength_var()));
		out_cc->println("%s = %d * %s;",
			env->LValue(size_var()), elem_w, env->RValue(arraylength_var()));
		env->SetEvaluated(size_var());
		}
	else
		{
		// Otherwise we need parse the array dynamically
		GenParseCode(out_cc, env, data, 0);
		}
	}

int ArrayType::StaticSize(Env *env) const
	{
	int num = 0;

	if ( ! length_ || ! length_->ConstFold(env, &num) )
		return -1;

	int elem_w = elemtype_->StaticSize(env);
	if ( elem_w < 0 )
		return -1;

	DEBUG_MSG("static size of %s:%s = %d * %d\n",
		decl_id()->Name(), lvalue(), elem_w, num);

	return num * elem_w;
	}

void ArrayType::SetBoundaryChecked()
	{
	Type::SetBoundaryChecked();
	elemtype_->SetBoundaryChecked();
	}

void ArrayType::DoMarkIncrementalInput()
	{
	elemtype_->MarkIncrementalInput();
	}

bool ArrayType::RequiresAnalyzerContext()
	{
	return Type::RequiresAnalyzerContext() ||
	       ( length_ && length_->RequiresAnalyzerContext() ) ||
	       elemtype_->RequiresAnalyzerContext();
	}

bool ArrayType::DoTraverse(DataDepVisitor *visitor)
	{
	if ( ! Type::DoTraverse(visitor) )
		return false;

	if ( length_ && ! length_->Traverse(visitor) )
		return false;

	if ( ! elemtype_->Traverse(visitor) )
		return false;

	return true;
	}

#include "pac_action.h"
#include "pac_array.h"
#include "pac_attr.h"
#include "pac_btype.h"
#include "pac_context.h"
#include "pac_dataptr.h"
#include "pac_decl.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_field.h"
#include "pac_id.h"
#include "pac_let.h"
#include "pac_output.h"
#include "pac_paramtype.h"
#include "pac_strtype.h"
#include "pac_type.h"
#include "pac_utils.h"
#include "pac_varfield.h"
#include "pac_withinput.h"


Type::type_map_t Type::type_map_;

Type::Type(TypeType tot) 
	: DataDepElement(DataDepElement::TYPE), tot_(tot)
	{ 
	type_decl_ = 0;
	type_decl_id_ = current_decl_id;
	declared_as_type_ = false;
	env_ = 0;
	value_var_ = default_value_var; 
	ASSERT(value_var_);
	value_var_type_ = MEMBER_VAR;
	anonymous_value_var_ = false;
	size_var_field_ = 0;
	size_expr_ = 0;
	boundary_checked_ = false;
	parsing_complete_var_field_ = 0;
	parsing_state_var_field_ = 0;
	buffering_state_var_field_ = 0;
	has_value_field_ = 0;

	array_until_input_ = 0;

	incremental_input_ = false;
	buffer_input_ = false;
	incremental_parsing_ = false;

	fields_ = new FieldList();

	attrs_ = new AttrList();
	attr_byteorder_expr_ = 0;
	attr_checks_ = new ExprList();
	attr_chunked_ = false;
	attr_exportsourcedata_ = false;
	attr_if_expr_ = 0;
	attr_length_expr_ = 0;
	attr_letfields_ = 0;
	attr_multiline_end_ = 0;
	attr_oneline_ = false;
	attr_refcount_ = false;
	attr_requires_ = 0;
	attr_restofdata_ = false;
	attr_restofflow_ = false;
	attr_transient_ = false;
	}

Type::~Type()
	{
	delete size_var_field_;
	delete parsing_complete_var_field_;
	delete parsing_state_var_field_;
	delete buffering_state_var_field_;
	delete has_value_field_;
	delete [] size_expr_;
	delete_list(FieldList, fields_);
	delete attrs_;
	delete attr_byteorder_expr_;
	delete attr_if_expr_;
	delete attr_length_expr_;
	delete_list(ExprList, attr_checks_);
	delete attr_requires_;
	}

Type *Type::Clone() const
	{
	Type *clone = DoClone();
	if ( clone )
		{
		foreach(i, FieldList, fields_)
			{
			Field *f = *i;
			clone->AddField(f);
			}

		foreach(i, AttrList, attrs_)
			{
			Attr *a = *i;
			clone->ProcessAttr(a);
			}
		}
	return clone;
	}

string Type::EvalMember(const ID *member_id) const
	{
	ASSERT(0);
	return "@@@";
	}

string Type::EvalElement(const string &array, const string &index) const
	{
	return strfmt("%s[%s]", array.c_str(), index.c_str());
	}

const ID *Type::decl_id() const
	{ 
	return type_decl_id_;
	}

void Type::set_type_decl(const TypeDecl *decl, bool declared_as_type)	
	{ 
	type_decl_ = decl; 
	type_decl_id_ = decl->id();
	declared_as_type_ = declared_as_type;
	}

void Type::set_value_var(const ID* arg_id, int arg_id_type)
 	{ 
	value_var_ = arg_id; 
	value_var_type_ = arg_id_type; 

	if ( value_var_ )
		anonymous_value_var_ = value_var_->is_anonymous();
	}

const ID *Type::size_var() const
	{
	return size_var_field_ ? size_var_field_->id() : 0;
	}

void Type::AddField(Field *f)
	{
	ASSERT(f);
	fields_->push_back(f);
	}

void Type::ProcessAttr(Attr* a)
	{
	switch ( a->type() )
		{
		case ATTR_BYTEORDER:
			attr_byteorder_expr_ = a->expr();
			break;

		case ATTR_CHECK:
			attr_checks_->push_back(a->expr());
			break;

		case ATTR_EXPORTSOURCEDATA:
			attr_exportsourcedata_ = true;
			break;

		case ATTR_LENGTH:
			attr_length_expr_ = a->expr();
			break;

		case ATTR_IF:
			attr_if_expr_ = a->expr();
			break;

		case ATTR_LET:
			{
			LetAttr *letattr = static_cast<LetAttr *>(a);
			if ( ! attr_letfields_ )
				attr_letfields_ = letattr->letfields();
			else
				{
				// Append to attr_letfields_
				attr_letfields_->insert(
					attr_letfields_->end(),
					letattr->letfields()->begin(),
					letattr->letfields()->end());
				}
			}
			break;

		case ATTR_LINEBREAKER:
			ASSERT(0);
			break;

		case ATTR_MULTILINE:
			attr_multiline_end_ = a->expr();
			break;

		case ATTR_ONELINE:
			attr_oneline_ = true;
			break;

		case ATTR_REFCOUNT:
			attr_refcount_ = true;
			break;

		case ATTR_REQUIRES:
			attr_requires_ = a->expr();
			break;

		case ATTR_TRANSIENT:
			attr_transient_ = true;
			break;
		
		case ATTR_CHUNKED:
		case ATTR_UNTIL:
		case ATTR_RESTOFDATA:
		case ATTR_RESTOFFLOW:
			// Ignore 
			// ... these are processed by {
			// {ArrayType, StringType}::ProcessAttr
			break;
		}

	attrs_->push_back(a);
	}

string Type::EvalByteOrder(Output *out_cc, Env *env) const
	{
	// If &byteorder is specified for a field, rather
	// than a type declaration, we do not add a byteorder variable
	// to the class, but instead evaluate it directly.
	if ( attr_byteorder_expr() && ! declared_as_type() )
		return attr_byteorder_expr()->EvalExpr(out_cc, global_env());
	env->Evaluate(out_cc, byteorder_id);
	return env->RValue(byteorder_id);
	}

void Type::Prepare(Env* env, int flags)
	{
	env_ = env;
	ASSERT(env_);

	// The name of the value variable
	if ( value_var() )	
		{
		data_id_str_ = strfmt("%s:%s", 
			decl_id()->Name(), value_var()->Name());
		}
	else
		{
		data_id_str_ = strfmt("%s", decl_id()->Name());
		}

	if ( value_var() )
		{
		env_->AddID(value_var(), 
			static_cast<IDType>(value_var_type_), 
			this);
		lvalue_ = strfmt("%s", env_->LValue(value_var()));
		}

	foreach(i, FieldList, attr_letfields_)
		{
		AddField(*i);
		}

	if ( attr_exportsourcedata_ )
		{
		ASSERT(flags & TO_BE_PARSED);
		AddField(new PubVarField(sourcedata_id->clone(),
			extern_type_const_bytestring->Clone()));
		}

	// An optional field
	if ( attr_if_expr() )
		{
		ASSERT(value_var());
		ID *has_value_id = new ID(fmt("has_%s", value_var()->Name()));
		has_value_field_ = new LetField(has_value_id, 
			extern_type_bool->Clone(),
			attr_if_expr());
		AddField(has_value_field_);
		}

	if ( incremental_input() )
		{
		ASSERT(flags & TO_BE_PARSED);
		ID *parsing_complete_var = 
			new ID(fmt("%s_parsing_complete", 
				value_var() ? value_var()->Name() : "val"));
		DEBUG_MSG("Adding parsing complete var: %s\n",
			parsing_complete_var->Name());
		parsing_complete_var_field_ = new TempVarField(
			parsing_complete_var, extern_type_bool->Clone());
		parsing_complete_var_field_->Prepare(env);

		if ( NeedsBufferingStateVar() && 
		       ! env->GetDataType(buffering_state_id) )
			{
			buffering_state_var_field_ = new PrivVarField(
				buffering_state_id->clone(), 
				extern_type_int->Clone());
			AddField(buffering_state_var_field_);
			}

		if ( incremental_parsing() && tot_ == RECORD )
			{
			ASSERT(! parsing_state_var_field_);
			parsing_state_var_field_ = new PrivVarField(
				parsing_state_id->clone(), 
				extern_type_int->Clone());
			AddField(parsing_state_var_field_);
			}
		}

	foreach (i, FieldList, fields_)
		{
		Field *f = *i;
		f->Prepare(env);
		}
	}

void Type::GenPubDecls(Output* out_h, Env* env)
	{
	if ( DefineValueVar() )
		{
		if ( attr_if_expr_ )
		        out_h->println("%s %s const { BINPAC_ASSERT(%s); return %s; }",
			        DataTypeConstRefStr().c_str(), 
			        env->RValue(value_var()),
			        env->RValue(has_value_var()), lvalue());
		else
		        out_h->println("%s %s const { return %s; }",
			        DataTypeConstRefStr().c_str(), 
			        env->RValue(value_var()), lvalue());
		}

	foreach (i, FieldList, fields_)
		{
		Field *f = *i;
		f->GenPubDecls(out_h, env);
		}
	}

void Type::GenPrivDecls(Output* out_h, Env* env)
	{
	if ( DefineValueVar() )
		{
		out_h->println("%s %s;", 
			DataTypeStr().c_str(), 
			env->LValue(value_var()));
		}

	foreach (i, FieldList, fields_)
		{
		Field *f = *i;
		f->GenPrivDecls(out_h, env);
		}
	}

void Type::GenInitCode(Output* out_cc, Env* env)
	{
	foreach (i, FieldList, fields_)
		{
		Field *f = *i;
		f->GenInitCode(out_cc, env);
		}

	if ( parsing_state_var_field_ )
		{
		out_cc->println("%s = 0;", 
			env->LValue(parsing_state_var_field_->id()));
		}

	if ( buffering_state_var_field_ )
		{
		out_cc->println("%s = 0;", 
			env->LValue(buffering_state_var_field_->id()));
		}
	}

void Type::GenCleanUpCode(Output* out_cc, Env* env)
	{
	foreach (i, FieldList, fields_)
		{
		Field *f = *i;
		if ( f->tof() != CASE_FIELD )
			f->GenCleanUpCode(out_cc, env);
		}
	}

void Type::GenBufferConfiguration(Output *out_cc, Env *env)
	{
	ASSERT(buffer_input());

	string frame_buffer_arg;
	
	switch ( buffer_mode() )
		{
		case BUFFER_NOTHING:
			break;

		case BUFFER_BY_LENGTH:
			if ( ! NeedsBufferingStateVar() )
 				break;
		
			if ( buffering_state_var_field_ )
				{
				out_cc->println("if ( %s == 0 )",
					env->RValue(buffering_state_id));
				out_cc->inc_indent();
				out_cc->println("{");
				}

			if ( attr_length_expr_ )
				{
				// frame_buffer_arg = attr_length_expr_->EvalExpr(out_cc, env);
				frame_buffer_arg = strfmt("%d", InitialBufferLength());
				}
			else if ( attr_restofflow_ )
				{
				ASSERT(attr_chunked());
				frame_buffer_arg = "-1";
				}
			else
				{
				ASSERT(0);
				}

			out_cc->println("%s->NewFrame(%s, %s);",
				env->LValue(flow_buffer_id),
				frame_buffer_arg.c_str(),
				attr_chunked() ? "true" : "false");

			if ( buffering_state_var_field_ )
				{
				out_cc->println("%s = 1;",
					env->LValue(buffering_state_id));
				out_cc->println("}");
				out_cc->dec_indent();
				}
			break;

		case BUFFER_BY_LINE:
			out_cc->println("if ( %s == 0 )",
				env->RValue(buffering_state_id));
			out_cc->inc_indent();
			out_cc->println("{");

			out_cc->println("%s->NewLine();",
				env->LValue(flow_buffer_id));

			out_cc->println("%s = 1;",
				env->LValue(buffering_state_id));
			out_cc->println("}");
			out_cc->dec_indent();
			break;

		default:
			ASSERT(0);
			break;
		}
	}

void Type::GenPreParsing(Output *out_cc, Env *env)
	{
	if ( incremental_input() && IsPointerType() )
		{
		out_cc->println("if ( ! %s )", env->LValue(value_var()));
		out_cc->inc_indent();
		out_cc->println("{");
		GenNewInstance(out_cc, env);
		out_cc->println("}");
		out_cc->dec_indent();
		}
	else
		GenNewInstance(out_cc, env);

	if ( buffer_input() )
		{
		GenBufferConfiguration(out_cc, env);
		}
	}

// Wrappers around DoGenParseCode, which does the real job
void Type::GenParseCode(Output* out_cc, Env* env, const DataPtr& data, int flags)
	{
	if ( value_var() && env->Evaluated(value_var()) )
		return;

	DEBUG_MSG("GenParseCode for %s\n", data_id_str_.c_str());

	if ( attr_if_expr() )
		{
		ASSERT(has_value_var());
		ASSERT(env->Evaluated(has_value_var()));
		}

	if ( value_var() && anonymous_value_var() )
		{
		GenPrivDecls(out_cc, env);
		GenInitCode(out_cc, env);
		}

	if ( incremental_input() )
		{
		parsing_complete_var_field_->GenTempDecls(out_cc, env);

		out_cc->println("%s = false;", 
			env->LValue(parsing_complete_var()));
		env->SetEvaluated(parsing_complete_var());

		if ( buffer_mode() == BUFFER_NOTHING )
			{
			out_cc->println("%s = true;", 
				env->LValue(parsing_complete_var()));
			}
		else if ( buffer_input() )
			{
			if ( declared_as_type() )
				GenParseBuffer(out_cc, env, flags);
			else
				GenBufferingLoop(out_cc, env, flags);
			}
		else
			GenParseCode2(out_cc, env, data, flags);
		}
	else
		{
		if ( attr_length_expr_)
			{
			EvalLengthExpr(out_cc, env);

			GenBoundaryCheck(out_cc, env, data);

			out_cc->println("{");
			out_cc->println("// Setting %s with &length", 
				env->RValue(end_of_data)); 
			out_cc->println("%s %s = %s + %s;",
				extern_type_const_byteptr->DataTypeStr().c_str(),
				env->LValue(end_of_data),
				data.ptr_expr(),
				EvalLengthExpr(out_cc, env).c_str());

			GenParseCode2(out_cc, env, data, flags);

			out_cc->println("}");
			}
		else
			{
			GenParseCode2(out_cc, env, data, flags);
			}
		}
	}

void Type::GenBufferingLoop(Output* out_cc, Env* env, int flags)
	{
	out_cc->println("while ( ! %s && %s->ready() )", 
		env->LValue(parsing_complete_var()),
		env->LValue(flow_buffer_id));

	out_cc->inc_indent();
	out_cc->println("{");

	Env buffer_env(env, this);
	GenParseBuffer(out_cc, &buffer_env, flags);

	out_cc->println("}");
	out_cc->dec_indent();
	}

void Type::GenParseBuffer(Output* out_cc, Env* env, int flags)
	{
	ASSERT(incremental_input());

	const ID *data_begin;

	if ( ! incremental_parsing() )
		{
		env->AddID(begin_of_data, TEMP_VAR, extern_type_const_byteptr);
		env->AddID(end_of_data, TEMP_VAR, extern_type_const_byteptr);

		out_cc->println("%s %s = %s->begin();",
			env->DataTypeStr(begin_of_data).c_str(),
			env->LValue(begin_of_data),
			env->RValue(flow_buffer_id));

		out_cc->println("%s %s = %s->end();",
			env->DataTypeStr(end_of_data).c_str(),
			env->LValue(end_of_data),
			env->RValue(flow_buffer_id));

		env->SetEvaluated(begin_of_data);
		env->SetEvaluated(end_of_data);

		data_begin = begin_of_data;
		}
	else
		data_begin = 0;

	if ( array_until_input_ )
		{
		if ( incremental_parsing() )
			{
			throw Exception(this, 
				"cannot handle &until($input...) "
				"for incrementally parsed type");
			}
		array_until_input_->GenUntilInputCheck(out_cc, env);
		}

	DataPtr data(env, data_begin, 0);

	if ( attr_length_expr() )
		{
		ASSERT(buffer_mode() == BUFFER_BY_LENGTH);
		out_cc->println("switch ( %s )", 
			env->LValue(buffering_state_id));
		out_cc->inc_indent();
		out_cc->println("{");
		out_cc->println("case 0:");
		out_cc->inc_indent();
		GenBufferConfiguration(out_cc, env);
		out_cc->println("%s = 1;", env->LValue(buffering_state_id));
		out_cc->println("break;");
		out_cc->dec_indent();

		out_cc->println("case 1:");
		out_cc->inc_indent();

		out_cc->println("{");

		out_cc->println("%s = 2;", env->LValue(buffering_state_id));

		Env frame_length_env(env, this);
		out_cc->println("%s->GrowFrame(%s);", 
			env->LValue(flow_buffer_id),
			attr_length_expr_->EvalExpr(out_cc, &frame_length_env));
		out_cc->println("}");
		out_cc->println("break;");

		out_cc->dec_indent();
		out_cc->println("case 2:");
		out_cc->inc_indent();

		out_cc->println("BINPAC_ASSERT(%s->ready());", 
			env->RValue(flow_buffer_id));
		out_cc->println("if ( %s->ready() )", 
			env->RValue(flow_buffer_id));
		out_cc->inc_indent();
		out_cc->println("{");

		Env parse_env(env, this);
		GenParseCode2(out_cc, &parse_env, data, 0);
		
		out_cc->println("BINPAC_ASSERT(%s);", 
			parsing_complete(env).c_str());
		out_cc->println("%s = 0;", 
			env->LValue(buffering_state_id));
		out_cc->println("}");
		out_cc->dec_indent();

		out_cc->println("break;");

		out_cc->dec_indent();
		out_cc->println("default:");
		out_cc->inc_indent();

		out_cc->println("BINPAC_ASSERT(%s <= 2);",
			env->LValue(buffering_state_id));
		out_cc->println("break;");
		
		out_cc->dec_indent();
		out_cc->println("}");
		out_cc->dec_indent();
		}
	else if ( attr_restofflow_ )
		{
		out_cc->println("BINPAC_ASSERT(%s->eof());", 
			env->RValue(flow_buffer_id));
		GenParseCode2(out_cc, env, data, 0);
		}
	else if ( buffer_mode() == BUFFER_BY_LINE )
		{
		GenParseCode2(out_cc, env, data, 0);
		out_cc->println("%s = 0;", env->LValue(buffering_state_id));
		}
	else
		GenParseCode2(out_cc, env, data, 0);
	}

void Type::GenParseCode2(Output* out_cc, Env* env, 
		const DataPtr& data, int flags)
	{
	DEBUG_MSG("GenParseCode2 for %s\n", data_id_str_.c_str());

	if ( attr_exportsourcedata_ )
		{
		if ( incremental_parsing() )
			{
			throw Exception(this, 
				"cannot export raw data for incrementally parsed types");
			}

		out_cc->println("%s = const_bytestring(%s, %s);",
			env->LValue(sourcedata_id),
			data.ptr_expr(),
			env->RValue(end_of_data));
		env->SetEvaluated(sourcedata_id);
	
		GenParseCode3(out_cc, env, data, flags);

		string datasize_str = DataSize(out_cc, env, data);
		out_cc->println("%s.set_end(%s + %s);",
			env->LValue(sourcedata_id),
			data.ptr_expr(),
			datasize_str.c_str());
		}
	else
		{
		GenParseCode3(out_cc, env, data, flags);
		}
	}

void Type::GenParseCode3(Output* out_cc, Env* env, const DataPtr& data, int flags)
	{
	if ( attr_requires_ )
		attr_requires_->EvalExpr(out_cc, env);

	foreach(i, FieldList, fields_)
		{
		Field *f = *i;
		f->GenTempDecls(out_cc, env);
		}

	DoGenParseCode(out_cc, env, data, flags);

	if ( incremental_input() )
		{
		out_cc->println("if ( %s )", parsing_complete(env).c_str());
		out_cc->inc_indent();
		out_cc->println("{");
		}

	out_cc->println("// Evaluate 'let' and 'withinput' fields");
	foreach(i, FieldList, fields_)
		{
		Field *f = *i;
		if ( f->tof() == LET_FIELD )
			{
			LetField *lf = static_cast<LetField *>(f);
			lf->GenParseCode(out_cc, env);
			}
		else if ( f->tof() == WITHINPUT_FIELD )
			{
			WithInputField *af = static_cast<WithInputField *>(f);
			af->GenParseCode(out_cc, env);
			}
		}

	if ( value_var() && anonymous_value_var() )
		{
		GenCleanUpCode(out_cc, env);
		}

	if ( incremental_input() )
		{
		out_cc->println("}");
		out_cc->dec_indent();
		}

	if ( value_var() )
		env->SetEvaluated(value_var());

	if ( size_var() )
		ASSERT(env->Evaluated(size_var()));
	}

Type *Type::MemberDataType(const ID *member_id) const
	{
	DEBUG_MSG("MemberDataType: %s::%s\n", type_decl_id_->Name(), member_id->Name());
	ASSERT(env_);
	env_->set_allow_undefined_id(true);
	Type *t = env_->GetDataType(member_id);
	env_->set_allow_undefined_id(false);
	return t;
	}

Type *Type::ElementDataType() const
	{
	return 0;
	}

// Returns false if it is not necessary to add size_var
// (it is already added or the type has a fixed size).
bool Type::AddSizeVar(Output* out_cc, Env* env)
	{
	if ( size_var() )
		{
		DEBUG_MSG("size var `%s' already added\n", size_var()->Name());
		ASSERT(env->Evaluated(size_var()));
		return false;
		}

	if ( StaticSize(env) >= 0 )
		return false;

	ASSERT(! incremental_input());

	ID *size_var_id = new ID(fmt("%s__size", 
		value_var() ? value_var()->Name() : decl_id()->Name()));

	DEBUG_MSG("adding size var `%s' to env %p\n", size_var_id->Name(), env);

	size_var_field_ = new TempVarField(
		size_var_id, extern_type_int->Clone());
	size_var_field_->Prepare(env);
	size_var_field_->GenTempDecls(out_cc, env);

	return true;
	}

string Type::EvalLengthExpr(Output* out_cc, Env* env)
	{
	ASSERT(!incremental_input());
	ASSERT(attr_length_expr_);
	int static_length;
	if ( attr_length_expr_->ConstFold(env, &static_length) )
		return strfmt("%d", static_length);
	// How do we make sure size_var is evaluated with attr_length_expr_?
	if ( AddSizeVar(out_cc, env) )
		{
		out_cc->println("%s = %s;",
			env->LValue(size_var()),
			attr_length_expr_->EvalExpr(out_cc, env));
		env->SetEvaluated(size_var());
		}
	return env->RValue(size_var());
	}

string Type::DataSize(Output* out_cc, Env* env, const DataPtr& data)
	{
	if ( attr_length_expr_ )
		return EvalLengthExpr(out_cc, env);

	int ss = StaticSize(env);
	if ( ss >= 0 )
		{
		return strfmt("%d", ss);
		}
	else
		{
		if ( ! size_var() || ! env->Evaluated(size_var()) )
			{
			ASSERT(out_cc != 0);
			GenDynamicSize(out_cc, env, data);
			ASSERT(size_var());
			}
		return env->RValue(size_var());
		}
	}

void Type::GenBoundaryCheck(Output* out_cc, Env* env,
		const DataPtr& data)
	{
	if ( boundary_checked() )
		return;

	data.GenBoundaryCheck(out_cc, env, 
		DataSize(out_cc, env, data).c_str(),
		data_id_str_.c_str());

	SetBoundaryChecked();
	}

bool Type::NeedsCleanUp() const
	{
	switch ( tot_ )
		{
		case EMPTY:
		case BUILTIN:
			return false;
		case ARRAY:
		case PARAMETERIZED:
		case STRING:
			return true;
		default:
			ASSERT(0);
			return true;
		}
	return true;
	}

bool Type::RequiresByteOrder() const
	{ 
	return ! attr_byteorder_expr() && ByteOrderSensitive(); 
	}

bool Type::NeedsBufferingStateVar() const
	{
	if ( !incremental_input() )
		return false;
	switch ( buffer_mode() )
		{
		case BUFFER_NOTHING:
		case NOT_BUFFERABLE:
			return false;
		case BUFFER_BY_LINE:
			return true;
		case BUFFER_BY_LENGTH:
			return ( attr_length_expr_ || attr_restofflow_ );
		default:
			ASSERT(0);
			return false;
		}
	}

bool Type::DoTraverse(DataDepVisitor *visitor)
	{
	foreach (i, FieldList, fields_)
		{
		if ( ! (*i)->Traverse(visitor) )
			return false;
		}

	foreach(i, AttrList, attrs_)
		{
		if ( ! (*i)->Traverse(visitor) )
			return false;
		}

	return true;
	}

bool Type::RequiresAnalyzerContext()
	{
	ASSERT(0);

	if ( buffer_input() )
		return true;
	
	foreach (i, FieldList, fields_)
		{
		Field *f = *i;
		if ( f->RequiresAnalyzerContext() )
			return true;
		}

	foreach(i, AttrList, attrs_)
		if ( (*i)->RequiresAnalyzerContext() )
			return true;

	return false;
	}

bool Type::IsEmptyType() const
	{
	return ( StaticSize(global_env()) == 0 );
	}

void Type::MarkIncrementalInput()
	{
	DEBUG_MSG("Handle incremental input for %s.%s\n", 
		decl_id()->Name(),
		value_var() ? value_var()->Name() : "*");

	incremental_input_ = true;
	if ( Bufferable() )
		buffer_input_ = true;
	else
		{
		incremental_parsing_ = true;
		DoMarkIncrementalInput();
		}
	}

void Type::DoMarkIncrementalInput()
	{
	throw Exception(this, "cannot handle incremental input");
	}

bool Type::BufferableByLength() const
	{
	// If the input is an "frame buffer" with specified length
	return attr_length_expr_ || attr_restofflow_;
	}

bool Type::BufferableByLine() const
	{
	// If the input is an ASCII line;
	return attr_oneline_;
	}

bool Type::Bufferable() const
	{
	// If the input is an ASCII line or an "frame buffer"
	return IsEmptyType() || BufferableByLength() || BufferableByLine();
	}

Type::BufferMode Type::buffer_mode() const
	{
	if ( IsEmptyType() )
		return BUFFER_NOTHING;
	else if ( BufferableByLength() )
		return BUFFER_BY_LENGTH;
	else if ( BufferableByLine() )
		return BUFFER_BY_LINE;
	return NOT_BUFFERABLE;
	}

const ID *Type::parsing_complete_var() const
	{
	if ( parsing_complete_var_field_ )
		return parsing_complete_var_field_->id();
	else
		return 0;
	}

string Type::parsing_complete(Env *env) const
	{
	ASSERT(parsing_complete_var());
	return env->RValue(parsing_complete_var());
	}

const ID *Type::has_value_var() const
	{
	if ( has_value_field_ )
		return has_value_field_->id();
	else
		return 0;
	}

int Type::InitialBufferLength() const
	{
	if ( ! attr_length_expr_ )
		return 0;
	return attr_length_expr_->MinimalHeaderSize(env());
	}

bool Type::CompatibleTypes(Type *type1, Type *type2)
	{
	// If we cannot deduce one of the data types, assume that
	// they are compatible.
	if ( ! type1 || ! type2 )
		return true;

	// We do not have enough information about extern types
	if ( type1->tot() == EXTERN || type2->tot() == EXTERN )
		return true;

	if ( type1->tot() != type2->tot() )
		{
		if ( type1->IsNumericType() && type2->IsNumericType() )
			return true;
		else
			return false;
		}

	switch( type1->tot() )
		{
		case UNDEF:
		case EMPTY:
			return true;
		case BUILTIN:
			{
			BuiltInType *t1 = 
				static_cast<BuiltInType *>(type1);
			BuiltInType *t2 = 
				static_cast<BuiltInType *>(type2);
			return BuiltInType::CompatibleBuiltInTypes(t1, t2);
			}

		case PARAMETERIZED:
		case RECORD:
		case CASE:
		case EXTERN:
			return type1->DataTypeStr() == type2->DataTypeStr();
			break;
			
		case ARRAY:
			{
			ArrayType *t1 = 
				static_cast<ArrayType *>(type1);
			ArrayType *t2 = 
				static_cast<ArrayType *>(type2);
			return CompatibleTypes(t1->ElementDataType(),
			                       t2->ElementDataType());
			}

		default:
			ASSERT(0);
			return false;
		}
	}

Type *Type::LookUpByID(ID *id)
	{
	// 1. Is it a pre-defined type?
	string name = id->Name();
	if ( type_map_.find(name) != type_map_.end() )
		{
		return type_map_[name]->Clone();
		}

	// 2. Is it a simple declared type?
	Type *type = TypeDecl::LookUpType(id);
	if ( type )
		{
		// Note: as a Type is always associated with a variable, 
		// return a clone.
		switch ( type->tot() )
			{
			case Type::BUILTIN:
			case Type::EXTERN:
	       		case Type::STRING:
				return type->Clone();

	       		case Type::ARRAY:
			default:
				break;
			}
		}

	return new ParameterizedType(id, 0);
	}

void Type::AddPredefinedType(const string &type_name, Type *type)
	{
	ASSERT(type_map_.find(type_name) == type_map_.end());
	type_map_[type_name] = type;
	}

void Type::init()
	{
	BuiltInType::static_init();
	ExternType::static_init();
	StringType::static_init();
	}

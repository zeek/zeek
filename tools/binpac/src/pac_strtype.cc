#include "pac_attr.h"
#include "pac_btype.h"
#include "pac_cstr.h"
#include "pac_dataptr.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_id.h"
#include "pac_output.h"
#include "pac_regex.h"
#include "pac_strtype.h"
#include "pac_varfield.h"

const char *StringType::kStringTypeName = "bytestring";
const char *StringType::kConstStringTypeName = "const_bytestring";

StringType::StringType(StringTypeEnum anystr)
	: Type(STRING), type_(ANYSTR), str_(0), regex_(0)
	{
	ASSERT(anystr == ANYSTR);
	init();
	}

StringType::StringType(ConstString *str)
	: Type(STRING), type_(CSTR), str_(str), regex_(0)
	{
	init();
	}

StringType::StringType(RegEx *regex)
	: Type(STRING), type_(REGEX), str_(0), regex_(regex)
	{
	ASSERT(regex_);
	init();
	}

void StringType::init()
	{
	string_length_var_field_ = 0;
	elem_datatype_ = new BuiltInType(BuiltInType::UINT8);
	}

StringType::~StringType()
	{
	// TODO: Unref for Objects
	// Question: why Unref?
	// 
	// Unref(str_);
	// Unref(regex_);

	delete string_length_var_field_;
	delete elem_datatype_;
	}

Type *StringType::DoClone() const
	{
	StringType *clone;

	switch ( type_ )
		{
		case ANYSTR:
			clone = new StringType(ANYSTR);
			break;
		case CSTR:
			clone = new StringType(str_);
			break;
		case REGEX:
			clone = new StringType(regex_);
			break;
		default:
			ASSERT(0);
			return 0;
		}

	return clone;
	}

bool StringType::DefineValueVar() const
	{
	return true;
	}

string StringType::DataTypeStr() const
	{
	return strfmt("%s", 
		persistent() ? kStringTypeName : kConstStringTypeName);
	}

Type *StringType::ElementDataType() const
	{
	return elem_datatype_;
	}

void StringType::ProcessAttr(Attr *a)
	{
	Type::ProcessAttr(a);

	switch ( a->type() )
		{
		case ATTR_CHUNKED:
			{
			if ( type_ != ANYSTR )
				{
				throw Exception(a, 
					"&chunked can be applied"
					" to only type bytestring");
				}
			attr_chunked_ = true;
			SetBoundaryChecked();
			}
			break;

		case ATTR_RESTOFDATA:
			{
			if ( type_ != ANYSTR )
				{
				throw Exception(a, 
					"&restofdata can be applied"
					" to only type bytestring");
				}
			attr_restofdata_ = true;
			// As the string automatically extends to the end of 
			// data, we do not have to check boundary.
			SetBoundaryChecked();
			}
			break;

		case ATTR_RESTOFFLOW:
			{
			if ( type_ != ANYSTR )
				{
				throw Exception(a, 
					"&restofflow can be applied"
					" to only type bytestring");
				}
			attr_restofflow_ = true;
			// As the string automatically extends to the end of 
			// flow, we do not have to check boundary.
			SetBoundaryChecked();
			}
			break;

		default:
			break;
		}
	}

void StringType::Prepare(Env* env, int flags)
	{
	if ( (flags & TO_BE_PARSED) && StaticSize(env) < 0 )
		{
		ID *string_length_var = new ID(fmt("%s_string_length", 
			value_var() ? value_var()->Name() : "val"));
		string_length_var_field_ = new TempVarField(
			string_length_var, extern_type_int->Clone());
		string_length_var_field_->Prepare(env);
		}
	Type::Prepare(env, flags);
	}

void StringType::GenPubDecls(Output* out_h, Env* env)
	{
	Type::GenPubDecls(out_h, env);
	}

void StringType::GenPrivDecls(Output* out_h, Env* env)
	{
	Type::GenPrivDecls(out_h, env);
	}

void StringType::GenInitCode(Output* out_cc, Env* env)
	{
	Type::GenInitCode(out_cc, env);
	}

void StringType::GenCleanUpCode(Output* out_cc, Env* env)
	{
	Type::GenCleanUpCode(out_cc, env);
	if ( persistent() )
		out_cc->println("%s.free();", env->LValue(value_var()));
	}

void StringType::DoMarkIncrementalInput()
	{
	if ( attr_restofflow_ )
		{
		// Do nothing
		ASSERT(type_ == ANYSTR);
		}
	else
		{
		Type::DoMarkIncrementalInput();
		}
	}

int StringType::StaticSize(Env* env) const
	{
	switch ( type_ )
		{
		case CSTR:
			// Use length of the unescaped string
			return str_->unescaped().length();
		case REGEX:
			// TODO: static size for a regular expression?
		case ANYSTR:
			return -1;

		default:
			ASSERT(0);
			return -1;
		}
	}

const ID *StringType::string_length_var() const
	{
	return string_length_var_field_ ? string_length_var_field_->id() : 0;
	}

void StringType::GenDynamicSize(Output* out_cc, Env* env,
		const DataPtr& data)
	{
	ASSERT(StaticSize(env) < 0);
	DEBUG_MSG("Generating dynamic size for string `%s'\n", 
		value_var()->Name());

	if ( env->Evaluated(string_length_var()) )
		return;

	string_length_var_field_->GenTempDecls(out_cc, env);

	switch ( type_ )
		{
		case ANYSTR:
			GenDynamicSizeAnyStr(out_cc, env, data);
			break;
		case CSTR:
			ASSERT(0);
			break;
		case REGEX:
			// TODO: static size for a regular expression?
			GenDynamicSizeRegEx(out_cc, env, data);
			break;
		}

	if ( ! incremental_input() && AddSizeVar(out_cc, env) )
		{
		out_cc->println("%s = %s;", 
			env->LValue(size_var()),
			env->RValue(string_length_var()));
		env->SetEvaluated(size_var());
		}
	}

string StringType::GenStringSize(Output* out_cc, Env* env, 
		const DataPtr& data)
	{
	int static_size = StaticSize(env);
	if ( static_size >= 0 )
		return strfmt("%d", static_size);
	GenDynamicSize(out_cc, env, data);
	return env->RValue(string_length_var());
	}

void StringType::DoGenParseCode(Output* out_cc, Env* env, 
		const DataPtr& data, int flags)
	{
	string str_size = GenStringSize(out_cc, env, data);

	// Generate additional checking
	switch ( type_ )
		{
		case CSTR:
			GenCheckingCStr(out_cc, env, data, str_size);
			break;
		case REGEX:
		case ANYSTR:
			break;
		}

	if ( ! anonymous_value_var() )
		{
		// Set the value variable

		int len;

		if ( type_ == ANYSTR && attr_length_expr_ &&
		     attr_length_expr_->ConstFold(env, &len) )
			{
			// can check for a negative length now
			if ( len < 0 )
				throw Exception(this, "negative &length on string");
			}
		else
			{
			out_cc->println("// check for negative sizes");
			out_cc->println("if ( %s < 0 )",
				str_size.c_str());
			out_cc->println(
				"throw binpac::ExceptionInvalidStringLength(\"%s\", %s);",
				Location(), str_size.c_str());
			}

		out_cc->println("%s.init(%s, %s);",
			env->LValue(value_var()),
			data.ptr_expr(),
			str_size.c_str());
		}

	if ( parsing_complete_var() )
		{
		out_cc->println("%s = true;", 
			env->LValue(parsing_complete_var()));
		}
	}

void StringType::GenStringMismatch(Output* out_cc, Env* env, 
		const DataPtr& data, const char *pattern)
	{
	out_cc->println("throw binpac::ExceptionStringMismatch(\"%s\", %s, %s);",
		Location(), 
		pattern,
		fmt("string((const char *) (%s), (const char *) %s).c_str()", 
			data.ptr_expr(),
			env->RValue(end_of_data)));
	}

void StringType::GenCheckingCStr(Output* out_cc, Env* env, 
		const DataPtr& data, const string &str_size)
	{
	// TODO: extend it for dynamic strings
	ASSERT(type_ == CSTR);

	GenBoundaryCheck(out_cc, env, data);

	string str_val = str_->str();

	// Compare the string and report error on mismatch
	out_cc->println("if ( memcmp(%s, %s, %s) != 0 )",
		data.ptr_expr(), 
		str_val.c_str(),
		str_size.c_str());
	out_cc->inc_indent();
	out_cc->println("{");
	GenStringMismatch(out_cc, env, data, str_val.c_str());
	out_cc->println("}");
	out_cc->dec_indent();
	}

void StringType::GenDynamicSizeRegEx(Output* out_cc, Env* env, 
		const DataPtr& data)
	{
	// string_length_var = 
	// 	matcher.match_prefix(
	// 		begin,
	//		end);

	out_cc->println("%s = ",
		env->LValue(string_length_var()));
	out_cc->inc_indent();

	out_cc->println("%s.%s(", 
		env->RValue(regex_->matcher_id()),
		RegEx::kMatchPrefix);

	out_cc->inc_indent();
	out_cc->println("%s,",
		data.ptr_expr());
	out_cc->println("%s - %s);", 
		env->RValue(end_of_data),
		data.ptr_expr());

	out_cc->dec_indent();
	out_cc->dec_indent();

	env->SetEvaluated(string_length_var());

	out_cc->println("if ( %s < 0 )", 
		env->RValue(string_length_var()));
	out_cc->inc_indent();
	out_cc->println("{");
	GenStringMismatch(out_cc, env, data, 
		fmt("\"%s\"", regex_->str().c_str()));
	out_cc->println("}");
	out_cc->dec_indent();
	}

void StringType::GenDynamicSizeAnyStr(Output* out_cc, Env* env, 
		const DataPtr& data)
	{
	ASSERT(type_ == ANYSTR);

	if ( attr_restofdata_ || attr_oneline_ )
		{
		out_cc->println("%s = (%s) - (%s);", 
			env->LValue(string_length_var()),
			env->RValue(end_of_data),
			data.ptr_expr());
		}
	else if ( attr_restofflow_ )
		{
		out_cc->println("%s = (%s) - (%s);", 
			env->LValue(string_length_var()),
			env->RValue(end_of_data),
			data.ptr_expr());
		}
	else if ( attr_length_expr_ )
		{
		out_cc->println("%s = %s;", 
			env->LValue(string_length_var()),
			attr_length_expr_->EvalExpr(out_cc, env));
		}
	else
		{
		throw Exception(this,
			"cannot determine length of bytestring");
		}

	env->SetEvaluated(string_length_var());
	}

bool StringType::DoTraverse(DataDepVisitor *visitor)
	{ 
	if ( ! Type::DoTraverse(visitor) )
		return false;

	switch ( type_ )
		{
		case ANYSTR:
		case CSTR:
		case REGEX:
			break;
		}

	return true;
	}

void StringType::static_init()
	{
	Type::AddPredefinedType("bytestring", new StringType(ANYSTR));
	}

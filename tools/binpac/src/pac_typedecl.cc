#include "pac_attr.h"
#include "pac_context.h"
#include "pac_dataptr.h"
#include "pac_embedded.h"
#include "pac_enum.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_id.h"
#include "pac_output.h"
#include "pac_param.h"
#include "pac_paramtype.h"
#include "pac_record.h"
#include "pac_type.h"
#include "pac_typedecl.h"
#include "pac_utils.h"

TypeDecl::TypeDecl(ID* id, ParamList* params, Type* type)
	: Decl(id, TYPE), params_(params), type_(type)
	{
	env_ = 0;
	type_->set_type_decl(this, true);
	}

TypeDecl::~TypeDecl()
	{
	delete env_;
	delete type_;

	delete_list(ParamList, params_);
	}

void TypeDecl::ProcessAttr(Attr* a)
	{
	type_->ProcessAttr(a);
	}

void TypeDecl::AddParam(Param *param)
	{
	// Cannot work after Prepare()
	ASSERT(! env_);
	params_->push_back(param);
	}

void TypeDecl::Prepare()
	{
	DEBUG_MSG("Preparing type %s\n", id()->Name());

	if ( type_->tot() != Type::EXTERN && type_->tot() != Type::DUMMY )
		SetAnalyzerContext();

	// As a type ID can be used in the same way function is, add the
	// id as a FUNC_ID and set it as evaluated.
	global_env()->AddID(id(), FUNC_ID, type_);
	global_env()->SetEvaluated(id());

	env_ = new Env(global_env(), this);

	foreach (i, ParamList, params_)
		{
		Param* p = *i;
		// p->Prepare(env_);
		type_->AddField(p->param_field());
		}

	if ( type_->attr_byteorder_expr() )
		{
		DEBUG_MSG("Adding byteorder field to %s\n",
			id()->Name());
		type_->AddField(new LetField(byteorder_id->clone(), 
		                         extern_type_int, 
		                         type_->attr_byteorder_expr()));
		}

	type_->Prepare(env_, Type::TO_BE_PARSED);
	}

string TypeDecl::class_name() const
	{ 
	return id_->Name(); 
	}

void TypeDecl::GenForwardDeclaration(Output* out_h)
	{
	// Do not generate declaration for external types
	if ( type_->tot() == Type::EXTERN )
		return;
	out_h->println("class %s;", class_name().c_str());
	}

void TypeDecl::GenCode(Output* out_h, Output* out_cc)
	{
	// Do not generate code for external types
	if ( type_->tot() == Type::EXTERN || type_->tot() == Type::STRING )
		return;

	fprintf(stderr, "Generating code for %s\n", class_name().c_str());

	if ( RequiresAnalyzerContext::compute(type_) )
		{
		DEBUG_MSG("%s requires analyzer context\n", 
			id()->Name());
		Type *param_type = analyzer_context()->param_type();
		env_->AddID(analyzer_context_id, TEMP_VAR, param_type);
		env_->SetEvaluated(analyzer_context_id);
		env_->AddMacro(context_macro_id, 
			new Expr(analyzer_context_id->clone()));
		}

	// Add parameter "byteorder"
	if ( type_->RequiresByteOrder() && ! type_->attr_byteorder_expr() )
		{
		env_->AddID(byteorder_id, TEMP_VAR, extern_type_int);
		env_->SetEvaluated(byteorder_id);
		}

	vector<string> base_classes;

	AddBaseClass(&base_classes);

	if ( type_->attr_refcount() )
		base_classes.push_back(kRefCountClass);

	// The first line of class definition
	out_h->println("");
	out_h->print("class %s", class_name().c_str());
	bool first = true;
	foreach(i, vector<string>, &base_classes)
		{
		if ( first )
			{
			out_h->print(" : public %s", i->c_str());
			first = false;
			}
		else
			out_h->print(", public %s", i->c_str());
		}
	out_h->print("\n");

	// Public members
	out_h->println("{");
	out_h->println("public:");
	out_h->inc_indent();

	GenConstructorFunc(out_h, out_cc);
	GenDestructorFunc(out_h, out_cc);

	if ( type_->attr_length_expr() )
		GenInitialBufferLengthFunc(out_h, out_cc);

	GenParseFunc(out_h, out_cc);

	out_h->println("");
	out_h->println("// Member access functions");
	type_->GenPubDecls(out_h, env_);
	out_h->println("");

	GenPubDecls(out_h, out_cc);

	out_h->dec_indent();
	out_h->println("protected:");
	out_h->inc_indent();

	GenPrivDecls(out_h, out_cc);
	type_->GenPrivDecls(out_h, env_);

	out_h->dec_indent();
	out_h->println("};\n");
	}

void TypeDecl::GenPubDecls(Output* out_h, Output *out_cc)
	{
	// GenParamPubDecls(params_, out_h, env_);
	}

void TypeDecl::GenPrivDecls(Output* out_h, Output *out_cc)
	{
	// GenParamPrivDecls(params_, out_h, env_);
	}

void TypeDecl::GenInitCode(Output *out_cc)
	{
	}

void TypeDecl::GenCleanUpCode(Output *out_cc)
	{
	}

void TypeDecl::GenConstructorFunc(Output* out_h, Output* out_cc)
	{
	string params_str = ParamDecls(params_);

	string proto = 
		strfmt("%s(%s)", class_name().c_str(), params_str.c_str());

	out_h->println("%s;", proto.c_str());

	out_cc->println("%s::%s", class_name().c_str(), proto.c_str());
	out_cc->inc_indent();

	out_cc->println("{");

	// GenParamAssignments(params_, out_cc, env_);

	type_->GenInitCode(out_cc, env_);
	GenInitCode(out_cc);

	out_cc->println("}\n");
	out_cc->dec_indent();
	}

void TypeDecl::GenDestructorFunc(Output* out_h, Output* out_cc)
	{
	string proto = strfmt("~%s()", class_name().c_str());

	out_h->println("%s;", proto.c_str());

	out_cc->println("%s::%s", class_name().c_str(), proto.c_str());
	out_cc->inc_indent();
	out_cc->println("{");

	GenCleanUpCode(out_cc);
	type_->GenCleanUpCode(out_cc, env_);

	out_cc->println("}\n");
	out_cc->dec_indent();
	}

string TypeDecl::ParseFuncPrototype(Env* env)
	{
	const char *func_name = 0;
	const char *return_type = 0;
	string params;

	if ( type_->incremental_input() )
		{
		func_name = kParseFuncWithBuffer;
		return_type = "bool";
		params = strfmt("flow_buffer_t %s",
			env->LValue(flow_buffer_id));
		}
	else
		{
		func_name = kParseFuncWithoutBuffer;
		return_type = "int";
		params = strfmt("const_byteptr const %s, const_byteptr const %s",
			env->LValue(begin_of_data), 
			env->LValue(end_of_data));
		}

	if ( RequiresAnalyzerContext::compute(type_) )
		{
		Type *param_type = analyzer_context()->param_type();
		params += fmt(", %s %s", 
			param_type->DataTypeConstRefStr().c_str(),
			env->LValue(analyzer_context_id));
		}

	// Add parameter "byteorder"
	if ( type_->RequiresByteOrder() && ! type_->attr_byteorder_expr() )
		{
		params += fmt(", int %s", env->LValue(byteorder_id));
		}

	// Returns "<return type> %s<func name>(<params>)%s".
	return strfmt("%s %%s%s(%s)%%s", 
		return_type, func_name, params.c_str());
	}

void TypeDecl::GenParsingEnd(Output *out_cc, Env *env, const DataPtr &data)
	{
	string ret_val_0, ret_val_1;

	if ( type_->incremental_input() )
		{
		ret_val_0 = type_->parsing_complete(env).c_str();
		ret_val_1 = "false";
		}
	else
		{
		ret_val_0 = type_->DataSize(0, env, data).c_str();
		ret_val_1 = "@@@";

		out_cc->println("BINPAC_ASSERT(%s + (%s) <= %s);", 
			env->RValue(begin_of_data),
			ret_val_0.c_str(),
			env->RValue(end_of_data));
		}

	if ( type_->incremental_parsing() && 
	     ( type_->tot() == Type::RECORD || type_->tot() == Type::ARRAY ) )
		{
		// In which case parsing may jump to label 
		// "need_more_data" ...
		out_cc->println("BINPAC_ASSERT(%s);",
			type_->parsing_complete(env).c_str());
		out_cc->println("return %s;", ret_val_0.c_str());

		out_cc->println("");
		out_cc->dec_indent();
		out_cc->println("%s:", kNeedMoreData);
		out_cc->inc_indent();
		out_cc->println("BINPAC_ASSERT(!(%s));",
			type_->parsing_complete(env).c_str());
		out_cc->println("return %s;", ret_val_1.c_str());
		}
	else if ( type_->incremental_input() )
		{
		out_cc->println("return %s;", ret_val_0.c_str());
		}
	else	
		{
		out_cc->println("return %s;", ret_val_0.c_str());
		}
	}

void TypeDecl::GenParseFunc(Output* out_h, Output* out_cc)
	{
	if ( type_->tot() == Type::DUMMY )
		return;

	// Env within the parse function
	Env p_func_env(env_, this);
	Env *env = &p_func_env;

	if ( type_->incremental_input() )
		{
		env->AddID(flow_buffer_id, TEMP_VAR, extern_type_flowbuffer);
		env->SetEvaluated(flow_buffer_id);
		}
	else
		{
		env->AddID(begin_of_data, TEMP_VAR, extern_type_const_byteptr);
		env->AddID(end_of_data, TEMP_VAR, extern_type_const_byteptr);

		env->SetEvaluated(begin_of_data);
		env->SetEvaluated(end_of_data);
		}

	string proto;
	proto = ParseFuncPrototype(env);

#if 0
	if ( func_type == PARSE )
		{
		out_h->println("// 1. If the message is completely parsed, returns number of");
		out_h->println("//    input bytes parsed.");
		out_h->println("// 2. If the input is not complete but the type supports");
		out_h->println("//    incremental input, returns number of input bytes + 1");
		out_h->println("//    (%s - %s + 1).",
			env->LValue(end_of_data), 
			env->LValue(begin_of_data)); 
		out_h->println("// 3. An exception will be thrown on error.");
		}
#endif

	out_h->println(proto.c_str(), "", ";");

	out_cc->println(proto.c_str(), fmt("%s::", class_name().c_str()), "");
	out_cc->inc_indent();
	out_cc->println("{");

	DataPtr data(env, 0, 0);

	if ( ! type_->incremental_input() )
		data = DataPtr(env, begin_of_data, 0);
	type_->GenParseCode(out_cc, env, data, 0);
	GenParsingEnd(out_cc, env, data);

	out_cc->println("}\n");
	out_cc->dec_indent();
	}

void TypeDecl::GenInitialBufferLengthFunc(Output* out_h, Output* out_cc)
	{
	string func(kInitialBufferLengthFunc);

	int init_buffer_length = type_->InitialBufferLength();

	if ( init_buffer_length < 0 )  // cannot be statically determined
		{
		throw Exception(type()->attr_length_expr(), 
		                fmt("cannot determine initial buffer length"
		                    " for type %s", id_->Name()));
		}

	out_h->println("int %s() const { return %d; }", 
	               func.c_str(),
	               init_buffer_length);
	}

Type* TypeDecl::LookUpType(const ID *id)
	{
	Decl *decl = LookUpDecl(id);
	if ( ! decl )
		return 0;
	switch ( decl->decl_type() )
		{
		case TYPE:
		case CONN:
		case FLOW:
			return static_cast<TypeDecl *>(decl)->type();
		case ENUM:
			return static_cast<EnumDecl *>(decl)->DataType();
		default:
			return 0;
		}
	}


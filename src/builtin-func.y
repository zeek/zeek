%{
#include <vector>
#include <set>
#include <string>
#include <cstring>

using namespace std;

#include <stdio.h>
#include <stdlib.h>

#include "module_util.h"

using namespace std;

extern int line_number;
extern char* input_filename;
extern char* plugin;

#define print_line_directive(fp) fprintf(fp, "\n#line %d \"%s\"\n", line_number, input_filename)

extern FILE* fp_bro_init;
extern FILE* fp_func_def;
extern FILE* fp_func_h;
extern FILE* fp_func_init;
extern FILE* fp_netvar_h;
extern FILE* fp_netvar_def;
extern FILE* fp_netvar_init;

int in_c_code = 0;
string current_module = GLOBAL_MODULE_NAME;
int definition_type;
string type_name;


enum {
	C_SEGMENT_DEF,
	FUNC_DEF,
	EVENT_DEF,
	TYPE_DEF,
	CONST_DEF,
};

// Holds the name of a declared object (function, enum, record type, event,
// etc. and information about namespaces, etc.
struct decl_struct {
	string module_name;
	string bare_name; // name without module or namespace
	string c_namespace_start; // "opening" namespace for use in netvar_*
	string c_namespace_end;   // closing "}" for all the above namespaces
	string c_fullname; // fully qualified name (namespace::....) for use in netvar_init
	string bro_fullname; // fully qualified bro name, for netvar (and lookup_ID())
	string bro_name;  // the name as we read it from input. What we write into the .bro file

	// special cases for events. Events have an EventHandlerPtr
	// and a generate_* function. This name is for the generate_* function
	string generate_bare_name;
	string generate_c_fullname;
	string generate_c_namespace_start;
	string generate_c_namespace_end;
} decl;

void set_definition_type(int type, const char *arg_type_name)
	{
	definition_type = type;
	if ( type == TYPE_DEF && arg_type_name )
		type_name = string(arg_type_name);
	else
		type_name = "";
	}

void set_decl_name(const char *name)
	{
	decl.bare_name = extract_var_name(name);

	// make_full_var_name prepends the correct module, if any
	// then we can extract the module name again.
	string varname = make_full_var_name(current_module.c_str(), name);
	decl.module_name = extract_module_name(varname.c_str());

	decl.c_namespace_start = "";
	decl.c_namespace_end = "";
	decl.c_fullname = "";
	decl.bro_fullname = "";
	decl.bro_name = "";

	decl.generate_c_fullname = "";
	decl.generate_bare_name = string("generate_") + decl.bare_name;
	decl.generate_c_namespace_start = "";
	decl.generate_c_namespace_end = "";

	switch ( definition_type ) {
	case TYPE_DEF:
		decl.c_namespace_start = "namespace BifType { namespace " + type_name + "{ ";
		decl.c_namespace_end = " } }";
		decl.c_fullname = "BifType::" + type_name + "::";
		break;

	case CONST_DEF:
		decl.c_namespace_start = "namespace BifConst { ";
		decl.c_namespace_end = " } ";
		decl.c_fullname = "BifConst::";
		break;

	case FUNC_DEF:
		decl.c_namespace_start = "namespace BifFunc { ";
		decl.c_namespace_end = " } ";
		decl.c_fullname = "BifFunc::";
		break;

	case EVENT_DEF:
		decl.c_namespace_start = "";
		decl.c_namespace_end = "";
		decl.c_fullname = "::";  // need this for namespace qualified events due do event_c_body
		decl.generate_c_namespace_start = "namespace BifEvent { ";
		decl.generate_c_namespace_end = " } ";
		decl.generate_c_fullname = "BifEvent::";
		break;

	default:
		break;
	}

	if ( decl.module_name != GLOBAL_MODULE_NAME )
		{
		decl.c_namespace_start += "namespace " + decl.module_name + " { ";
		decl.c_namespace_end += string(" }");
		decl.c_fullname += decl.module_name + "::";
		decl.bro_fullname += decl.module_name + "::";

		decl.generate_c_namespace_start  += "namespace " + decl.module_name + " { ";
		decl.generate_c_namespace_end += " } ";
		decl.generate_c_fullname += decl.module_name + "::";
		}

	decl.bro_fullname += decl.bare_name;
	if ( definition_type == FUNC_DEF )
		decl.bare_name = string("bro_") + decl.bare_name;

	decl.c_fullname += decl.bare_name;
	decl.bro_name += name;
	decl.generate_c_fullname += decl.generate_bare_name;

	}

const char* arg_list_name = "BiF_ARGS";

#include "bif_arg.h"

/* Map bif/bro type names to C types for use in const declaration */
static struct {
	const char* bif_type;
	const char* bro_type;
	const char* c_type;
	const char* accessor;
	const char* constructor;
} builtin_types[] = {
#define DEFINE_BIF_TYPE(id, bif_type, bro_type, c_type, accessor, constructor) \
	{bif_type, bro_type, c_type, accessor, constructor},
#include "bif_type.def"
#undef DEFINE_BIF_TYPE
};

int get_type_index(const char *type_name)
	{
	for ( int i = 0; builtin_types[i].bif_type[0] != '\0'; ++i )
		{
		if ( strcmp(builtin_types[i].bif_type, type_name) == 0 )
			return i;
		}
		return TYPE_OTHER;
	}


int var_arg; // whether the number of arguments is variable
std::vector<BuiltinFuncArg*> args;

extern int yyerror(const char[]);
extern int yywarn(const char msg[]);
extern int yylex();

char* concat(const char* str1, const char* str2)
	{
	int len1 = strlen(str1);
	int len2 = strlen(str2);

	char* s = new char[len1 + len2 +1];

	memcpy(s, str1, len1);
	memcpy(s + len1, str2, len2);

	s[len1+len2] = '\0';

	return s;
	}

// Print the bro_event_* function prototype in C++, without the ending ';'
void print_event_c_prototype(FILE *fp, bool is_header)
	{
	if ( is_header )
		fprintf(fp, "%s void %s(analyzer::Analyzer* analyzer%s",
			decl.generate_c_namespace_start.c_str(), decl.generate_bare_name.c_str(),
			args.size() ? ", " : "" );
	else
		fprintf(fp, "void %s(analyzer::Analyzer* analyzer%s",
			decl.generate_c_fullname.c_str(),
			args.size() ? ", " : "" );
	for ( int i = 0; i < (int) args.size(); ++i )
		{
		if ( i > 0 )
			fprintf(fp, ", ");
		args[i]->PrintCArg(fp, i);
		}
	fprintf(fp, ")");
	if ( is_header )
		fprintf(fp, "; %s\n", decl.generate_c_namespace_end.c_str());
	else
		fprintf(fp, "\n");
	}

// Print the bro_event_* function body in C++.
void print_event_c_body(FILE *fp)
	{
	fprintf(fp, "\t{\n");
	fprintf(fp, "\t// Note that it is intentional that here we do not\n");
	fprintf(fp, "\t// check if %s is NULL, which should happen *before*\n",
		decl.c_fullname.c_str());
	fprintf(fp, "\t// %s is called to avoid unnecessary Val\n",
		decl.generate_c_fullname.c_str());
	fprintf(fp, "\t// allocation.\n");
	fprintf(fp, "\n");

	fprintf(fp, "\tval_list* vl = new val_list;\n\n");
	BuiltinFuncArg *connection_arg = 0;

	for ( int i = 0; i < (int) args.size(); ++i )
		{
		fprintf(fp, "\t");
		fprintf(fp, "vl->append(");
		args[i]->PrintBroValConstructor(fp);
		fprintf(fp, ");\n");

		if ( args[i]->Type() == TYPE_CONNECTION )
			{
			if ( connection_arg == 0 )
				connection_arg = args[i];
			else
				{
				// We are seeing two connection type arguments.
				yywarn("Warning: with more than connection-type "
				       "event arguments, bifcl only passes "
				       "the first one to EventMgr as cookie.");
				}
			}
		}

	fprintf(fp, "\n");
	fprintf(fp, "\tmgr.QueueEvent(%s, vl, SOURCE_LOCAL, analyzer->GetID(), timer_mgr",
		decl.c_fullname.c_str());

	if ( connection_arg )
		// Pass the connection to the EventMgr as the "cookie"
		fprintf(fp, ", %s", connection_arg->Name());

	fprintf(fp, ");\n");
	fprintf(fp, "\t} // event generation\n");
	//fprintf(fp, "%s // end namespace\n", decl.generate_c_namespace_end.c_str());
	}

void record_bif_item(const char* id, int type)
	{
	if ( ! plugin )
		return;

	fprintf(fp_func_init, "\tbifs.push_back(std::make_pair(\"%s\", %d));\n", id, type);
	}

%}

%token TOK_LPP TOK_RPP TOK_LPB TOK_RPB TOK_LPPB TOK_RPPB TOK_VAR_ARG
%token TOK_BOOL
%token TOK_FUNCTION TOK_EVENT TOK_CONST TOK_ENUM TOK_OF
%token TOK_TYPE TOK_RECORD TOK_SET TOK_VECTOR TOK_OPAQUE TOK_TABLE TOK_MODULE
%token TOK_ARGS TOK_ARG TOK_ARGC
%token TOK_ID TOK_ATTR TOK_CSTR TOK_LF TOK_WS TOK_COMMENT
%token TOK_ATOM TOK_INT TOK_C_TOKEN

%left ',' ':'

%type <str> TOK_C_TOKEN TOK_ID TOK_CSTR TOK_WS TOK_COMMENT TOK_ATTR TOK_INT opt_ws type attr_list opt_attr_list
%type <val> TOK_ATOM TOK_BOOL

%union	{
	const char* str;
	int val;
}

%%

builtin_lang:	definitions
			{
			fprintf(fp_bro_init, "} # end of export section\n");
			fprintf(fp_bro_init, "module %s;\n", GLOBAL_MODULE_NAME);
			}



definitions:	definitions definition opt_ws
			{
			if ( in_c_code )
				fprintf(fp_func_def, "%s", $3);
			else
				fprintf(fp_bro_init, "%s", $3);
			}
	|	opt_ws
			{
			fprintf(fp_bro_init, "%s", $1);
			fprintf(fp_bro_init, "export {\n");
			}
	;

definition:	event_def
	|	func_def
	|	c_code_segment
	|	enum_def
	|	const_def
	|	type_def
	|   module_def
	;


module_def:	TOK_MODULE opt_ws TOK_ID opt_ws ';'
			{
			current_module = string($3);
			fprintf(fp_bro_init, "module %s;\n", $3);
			}

	 // XXX: Add the netvar glue so that the event engine knows about
	 // the type. One still has to define the type in bro.init.
	 // Would be nice, if we could just define the record type here
	 // and then copy to the .bif.bro file, but type declarations in
	 // Bro can be quite powerful. Don't know whether it's worth it
	 // extend the bif-language to be able to handle that all....
	 // Or we just support a simple form of record type definitions
	 // TODO: add other types (tables, sets)
type_def:	TOK_TYPE opt_ws TOK_ID opt_ws ':' opt_ws type_def_types opt_ws ';'
			{
			set_decl_name($3);

			fprintf(fp_netvar_h, "%s extern %sType * %s; %s\n",
				decl.c_namespace_start.c_str(), type_name.c_str(),
				decl.bare_name.c_str(), decl.c_namespace_end.c_str());
			fprintf(fp_netvar_def, "%s %sType * %s; %s\n",
				decl.c_namespace_start.c_str(), type_name.c_str(),
				decl.bare_name.c_str(), decl.c_namespace_end.c_str());
			fprintf(fp_netvar_init,
				"\t%s = internal_type(\"%s\")->As%sType();\n",
				decl.c_fullname.c_str(), decl.bro_fullname.c_str(),
				type_name.c_str());

			record_bif_item(decl.bro_fullname.c_str(), 5);
			}
	;

type_def_types: TOK_RECORD
			{ set_definition_type(TYPE_DEF, "Record"); }
	| TOK_SET
			{ set_definition_type(TYPE_DEF, "Set"); }
	| TOK_VECTOR
			{ set_definition_type(TYPE_DEF, "Vector"); }
	| TOK_TABLE
			{ set_definition_type(TYPE_DEF, "Table"); }
	;

event_def:	event_prefix opt_ws plain_head opt_attr_list
			{ fprintf(fp_bro_init, "%s", $4); } end_of_head ';'
			{
			print_event_c_prototype(fp_func_h, true);
			print_event_c_prototype(fp_func_def, false);
			print_event_c_body(fp_func_def);
			}

func_def:	func_prefix opt_ws typed_head end_of_head body
	;

enum_def:	enum_def_1 enum_list TOK_RPB
			{
			// First, put an end to the enum type decl.
			fprintf(fp_bro_init, "};\n");
			if ( decl.module_name != GLOBAL_MODULE_NAME )
				fprintf(fp_netvar_h, "}; } }\n");
			else
				fprintf(fp_netvar_h, "}; }\n");

			// Now generate the netvar's.
			fprintf(fp_netvar_h, "%s extern EnumType * %s; %s\n",
				decl.c_namespace_start.c_str(), decl.bare_name.c_str(), decl.c_namespace_end.c_str());
			fprintf(fp_netvar_def, "%s EnumType * %s; %s\n",
				decl.c_namespace_start.c_str(), decl.bare_name.c_str(), decl.c_namespace_end.c_str());
			fprintf(fp_netvar_init,
				"\t%s = internal_type(\"%s\")->AsEnumType();\n",
				decl.c_fullname.c_str(), decl.bro_fullname.c_str());

			record_bif_item(decl.bro_fullname.c_str(), 5);
			}
	;

enum_def_1:	TOK_ENUM opt_ws TOK_ID opt_ws TOK_LPB opt_ws
			{
			set_definition_type(TYPE_DEF, "Enum");
			set_decl_name($3);
			fprintf(fp_bro_init, "type %s: enum %s{%s", decl.bro_name.c_str(), $4, $6);

			// this is the namespace were the enumerators are defined, not where
			// the type is defined.
			// We don't support fully qualified names as enumerators. Use a module name
			fprintf(fp_netvar_h, "namespace BifEnum { ");
			if ( decl.module_name != GLOBAL_MODULE_NAME )
				fprintf(fp_netvar_h, "namespace %s { ", decl.module_name.c_str());
			fprintf(fp_netvar_h, "enum %s {\n", $3);
			}
	;

enum_list:	enum_list TOK_ID opt_ws ',' opt_ws
			{
			fprintf(fp_bro_init, "%s%s,%s", $2, $3, $5);
			fprintf(fp_netvar_h, "\t%s,\n", $2);
			}
	| 		enum_list TOK_ID opt_ws '=' opt_ws TOK_INT opt_ws ',' opt_ws
			{
			fprintf(fp_bro_init, "%s = %s%s,%s", $2, $6, $7, $9);
			fprintf(fp_netvar_h, "\t%s = %s,\n", $2, $6);
			}
	|	/* nothing */
	;


const_def:	TOK_CONST opt_ws TOK_ID opt_ws ':' opt_ws TOK_ID opt_ws ';'
			{
			set_definition_type(CONST_DEF, 0);
			set_decl_name($3);
			int typeidx = get_type_index($7);
			char accessor[1024];

			snprintf(accessor, sizeof(accessor), builtin_types[typeidx].accessor, "");


			fprintf(fp_netvar_h, "%s extern %s %s; %s\n",
					decl.c_namespace_start.c_str(),
					builtin_types[typeidx].c_type, decl.bare_name.c_str(),
					decl.c_namespace_end.c_str());
			fprintf(fp_netvar_def, "%s %s %s; %s\n",
					decl.c_namespace_start.c_str(),
					builtin_types[typeidx].c_type, decl.bare_name.c_str(),
					decl.c_namespace_end.c_str());
			fprintf(fp_netvar_init, "\t%s = internal_const_val(\"%s\")%s;\n",
				decl.c_fullname.c_str(), decl.bro_fullname.c_str(),
				accessor);

			record_bif_item(decl.bro_fullname.c_str(), 3);
			}

attr_list:
		attr_list TOK_ATTR
			{ $$ = concat($1, $2); }
	|
		TOK_ATTR
	;

opt_attr_list:
		attr_list
	|	/* nothing */
		{ $$ = ""; }
	;

func_prefix:	TOK_FUNCTION
			{ set_definition_type(FUNC_DEF, 0); }
	;

event_prefix:	TOK_EVENT
			{ set_definition_type(EVENT_DEF, 0); }
	;

end_of_head:	/* nothing */
			{
			fprintf(fp_bro_init, ";\n");
			}
	;

typed_head:	plain_head return_type
			{
			}
	;

plain_head:	head_1 args arg_end opt_ws
			{
			if ( var_arg )
				fprintf(fp_bro_init, "va_args: any");
			else
				{
				for ( int i = 0; i < (int) args.size(); ++i )
					{
					if ( i > 0 )
						fprintf(fp_bro_init, ", ");
					args[i]->PrintBro(fp_bro_init);
					}
				}

			fprintf(fp_bro_init, ")");

			fprintf(fp_bro_init, "%s", $4);
			fprintf(fp_func_def, "%s", $4);
			}
	;

head_1:		TOK_ID opt_ws arg_begin
			{
			const char* method_type = 0;
			set_decl_name($1);

			if ( definition_type == FUNC_DEF )
				{
				method_type = "function";
				print_line_directive(fp_func_def);
				}
			else if ( definition_type == EVENT_DEF )
				method_type = "event";

			if ( method_type )
				fprintf(fp_bro_init,
					"global %s: %s%s(",
					decl.bro_name.c_str(), method_type, $2);

			if ( definition_type == FUNC_DEF )
				{
				fprintf(fp_func_init,
					"\t(void) new BuiltinFunc(%s, \"%s\", 0);\n",
					decl.c_fullname.c_str(), decl.bro_fullname.c_str());

				fprintf(fp_func_h,
					"%sextern Val* %s(Frame* frame, val_list*);%s\n",
					decl.c_namespace_start.c_str(), decl.bare_name.c_str(), decl.c_namespace_end.c_str());

				fprintf(fp_func_def,
					"Val* %s(Frame* frame, val_list* %s)",
					decl.c_fullname.c_str(), arg_list_name);

				record_bif_item(decl.bro_fullname.c_str(), 1);
				}
			else if ( definition_type == EVENT_DEF )
				{
				// TODO: add namespace for events here
				fprintf(fp_netvar_h,
					"%sextern EventHandlerPtr %s; %s\n",
					decl.c_namespace_start.c_str(), decl.bare_name.c_str(), decl.c_namespace_end.c_str());

				fprintf(fp_netvar_def,
					"%sEventHandlerPtr %s; %s\n",
					decl.c_namespace_start.c_str(), decl.bare_name.c_str(), decl.c_namespace_end.c_str());

				fprintf(fp_netvar_init,
					"\t%s = internal_handler(\"%s\");\n",
					decl.c_fullname.c_str(), decl.bro_fullname.c_str());

				record_bif_item(decl.bro_fullname.c_str(), 2);

				// C++ prototypes of bro_event_* functions will
				// be generated later.
				}
			}
	;

arg_begin:	TOK_LPP
			{ args.clear(); var_arg = 0; }
	;

arg_end:	TOK_RPP
	;

args:		args_1
	|	opt_ws
			{ /* empty, to avoid yacc complaint about type clash */ }
	;

args_1:		args_1 ',' opt_ws arg opt_ws opt_attr_list
			{ if ( ! args.empty() ) args[args.size()-1]->SetAttrStr($6); }
	|	opt_ws arg opt_ws opt_attr_list
			{ if ( ! args.empty() ) args[args.size()-1]->SetAttrStr($4); }
	;

// TODO: Migrate all other compound types to this rule. Once the BiF language
// can parse all regular Bro types, we can throw out the unnecessary
// boilerplate typedefs for addr_set, string_set, etc.
type:
                TOK_OPAQUE opt_ws TOK_OF opt_ws TOK_ID
                        { $$ = concat("opaque of ", $5); }
        |       TOK_ID
                        { $$ = $1; }
        ;

arg:		TOK_ID opt_ws ':' opt_ws type
			{ args.push_back(new BuiltinFuncArg($1, $5)); }
	|	TOK_VAR_ARG
			{
			if ( definition_type == EVENT_DEF )
				yyerror("events cannot have variable arguments");
			var_arg = 1;
			}
	;

return_type:	':' opt_ws type opt_ws
			{
			BuiltinFuncArg* ret = new BuiltinFuncArg("", $3);
			ret->PrintBro(fp_bro_init);
			delete ret;
			fprintf(fp_func_def, "%s", $4);
			}
	;

body:		body_start c_body body_end
			{
			fprintf(fp_func_def, " // end of %s\n", decl.c_fullname.c_str());
			print_line_directive(fp_func_def);
			}
	;

c_code_begin:	/* empty */
			{
			in_c_code = 1;
			print_line_directive(fp_func_def);
			}
	;

c_code_end:	/* empty */
			{ in_c_code = 0; }
	;

body_start:	TOK_LPB c_code_begin
			{
			int implicit_arg = 0;
			int argc = args.size();

			fprintf(fp_func_def, "{");

			if ( argc > 0 || ! var_arg )
				fprintf(fp_func_def, "\n");

			if ( ! var_arg )
				{
				fprintf(fp_func_def, "\tif ( %s->length() != %d )\n", arg_list_name, argc);
				fprintf(fp_func_def, "\t\t{\n");
				fprintf(fp_func_def,
					"\t\treporter->Error(\"%s() takes exactly %d argument(s)\");\n",
					decl.bro_fullname.c_str(), argc);
				fprintf(fp_func_def, "\t\treturn 0;\n");
				fprintf(fp_func_def, "\t\t}\n");
				}
			else if ( argc > 0 )
				{
				fprintf(fp_func_def, "\tif ( %s->length() < %d )\n", arg_list_name, argc);
				fprintf(fp_func_def, "\t\t{\n");
				fprintf(fp_func_def,
					"\t\treporter->Error(\"%s() takes at least %d argument(s)\");\n",
					decl.bro_fullname.c_str(), argc);
				fprintf(fp_func_def, "\t\treturn 0;\n");
				fprintf(fp_func_def, "\t\t}\n");
				}

			for ( int i = 0; i < (int) args.size(); ++i )
				args[i]->PrintCDef(fp_func_def, i + implicit_arg);
			print_line_directive(fp_func_def);
			}
	;

body_end:	TOK_RPB c_code_end
			{
			fprintf(fp_func_def, "}");
			}
	;

c_code_segment: TOK_LPPB c_code_begin c_body c_code_end TOK_RPPB
	;

c_body:		opt_ws
			{ fprintf(fp_func_def, "%s", $1); }
	|	c_body c_atom opt_ws
			{ fprintf(fp_func_def, "%s", $3); }
	;

c_atom:		TOK_ID
			{ fprintf(fp_func_def, "%s", $1); }
	|	TOK_C_TOKEN
			{ fprintf(fp_func_def, "%s", $1); }
	|	TOK_ARG
			{ fprintf(fp_func_def, "(*%s)", arg_list_name); }
	|	TOK_ARGS
			{ fprintf(fp_func_def, "%s", arg_list_name); }
	|	TOK_ARGC
			{ fprintf(fp_func_def, "%s->length()", arg_list_name); }
	|	TOK_CSTR
			{ fprintf(fp_func_def, "%s", $1); }
	|	TOK_ATOM
			{ fprintf(fp_func_def, "%c", $1); }
	|	TOK_INT
			{ fprintf(fp_func_def, "%s", $1); }

	;

opt_ws:		opt_ws TOK_WS
			{ $$ = concat($1, $2); }
	|	opt_ws TOK_LF
			{ $$ = concat($1, "\n"); }
	|	opt_ws TOK_COMMENT
			{
			if ( in_c_code )
				$$ = concat($1, $2);
			else
				if ( $2[1] == '#' )
					// This is a special type of comment that is used to
					// generate bro script documentation, so pass it through.
					$$ = concat($1, $2);
				else
					$$ = $1;
			}
	|	/* empty */
			{ $$ = ""; }
	;

%%

extern char* yytext;
extern char* input_filename;
extern int line_number;
void err_exit(void);

void print_msg(const char msg[])
	{
	int msg_len = strlen(msg) + strlen(yytext) + 64;
	char* msgbuf = new char[msg_len];

	if ( yytext[0] == '\n' )
		snprintf(msgbuf, msg_len, "%s, on previous line", msg);

	else if ( yytext[0] == '\0' )
		snprintf(msgbuf, msg_len, "%s, at end of file", msg);

	else
		snprintf(msgbuf, msg_len, "%s, at or near \"%s\"", msg, yytext);

	/*
	extern int column;
	sprintf(msgbuf, "%*s\n%*s\n", column, "^", column, msg);
	*/

	if ( input_filename )
		fprintf(stderr, "%s:%d: ", input_filename, line_number);
	else
		fprintf(stderr, "line %d: ", line_number);
	fprintf(stderr, "%s\n", msgbuf);

	delete [] msgbuf;
	}

int yywarn(const char msg[])
	{
	print_msg(msg);
	return 0;
	}

int yyerror(const char msg[])
	{
	print_msg(msg);

	err_exit();
	return 0;
	}

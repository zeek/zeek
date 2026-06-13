%{
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <vector>
#include <set>
#include <string>

#include "module_util.h"

using namespace std;

extern int line_number;
extern char* input_filename;
extern char* input_filename_with_path;
extern char* plugin;
extern bool alternative_mode;

#define print_line_directive(fp) fprintf(fp, "\n#line %d \"%s\"\n", line_number, input_filename_with_path)

extern FILE* fp_zeek_init;
extern FILE* fp_func_def;
extern FILE* fp_func_h;
extern FILE* fp_func_init;
extern FILE* fp_netvar_h;
extern FILE* fp_netvar_def;
extern FILE* fp_netvar_init;

bool in_c_code = false;
string current_module = GLOBAL_MODULE_NAME;
int definition_type;
string type_name;

// Alternate event prototypes are only written to the .zeek file, but
// don't need any further changes to C++ source/header files, so this
// set keeps track of whether the first event prototype information has
// already been defined/written to the C++ files.
static std::set<std::string> events;

enum : uint8_t {
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
	string zeek_fullname; // fully qualified zeek name, for netvar (and lookup_ID())
	string zeek_name;  // the name as we read it from input. What we write into the .zeek file

	// special cases for events. Events have an EventHandlerPtr
	// and a enqueue_* function. This name is for the enqueue_* function
	string enqueue_c_namespace_start;
	string enqueue_c_namespace_end;
	string enqueue_c_barename;
	string enqueue_c_fullname;
} decl;

void set_definition_type(int type, const char* arg_type_name) {
    definition_type = type;
    if ( type == TYPE_DEF && arg_type_name )
        type_name = string(arg_type_name);
    else
        type_name = "";
}

void set_decl_name(const char* name) {
    decl.bare_name = extract_var_name(name);

    // make_full_var_name prepends the correct module, if any
    // then we can extract the module name again.
    string varname = make_full_var_name(current_module.c_str(), name);
    decl.module_name = extract_module_name(varname.c_str());

    decl.c_namespace_start = "";
    decl.c_namespace_end = "";
    decl.c_fullname = "";
    decl.zeek_fullname = "";
    decl.zeek_name = "";

    decl.enqueue_c_fullname = "";
    decl.enqueue_c_barename = string("enqueue_") + decl.bare_name;
    decl.enqueue_c_namespace_start = "";
    decl.enqueue_c_namespace_end = "";

    switch ( definition_type ) {
        case TYPE_DEF:
            decl.c_namespace_start = "BifType::" + type_name + "";
            decl.c_fullname = "BifType::" + type_name + "::";
            break;

        case CONST_DEF:
            decl.c_namespace_start = "BifConst";
            decl.c_fullname = "BifConst::";
            break;

        case FUNC_DEF:
            decl.c_namespace_start = "BifFunc";
            decl.c_fullname = "BifFunc::";
            break;

        case EVENT_DEF:
            decl.c_namespace_start = "";
            decl.c_namespace_end = "";
            decl.c_fullname = "::"; // need this for namespace qualified events due to event_c_body
            decl.enqueue_c_namespace_start = "BifEvent";
            decl.enqueue_c_fullname = "zeek::BifEvent::";
            break;

        default: break;
    }

    if ( decl.module_name != GLOBAL_MODULE_NAME ) {
        if ( decl.c_namespace_start.empty() ) {
            decl.c_namespace_start += "namespace " + decl.module_name + " { ";
            decl.c_namespace_end += " }";
        }
        else {
            decl.c_namespace_start += "::" + decl.module_name;
            decl.c_namespace_end = "";
        }
        decl.c_fullname += decl.module_name + "::";
        decl.zeek_fullname += decl.module_name + "::";

        if ( decl.enqueue_c_namespace_start.empty() ) {
            decl.enqueue_c_namespace_start += "namespace " + decl.module_name + " { ";
            decl.enqueue_c_namespace_end += " } ";
        }
        else {
            decl.enqueue_c_namespace_start += "::" + decl.module_name;
            decl.enqueue_c_namespace_end = "";
        }
        decl.enqueue_c_fullname += decl.module_name + "::";
    }

    decl.zeek_fullname += decl.bare_name;
    decl.c_fullname += decl.bare_name;
    decl.zeek_name += name;
    decl.enqueue_c_fullname += decl.enqueue_c_barename;
}

const char* arg_list_name = "BiF_ARGS";

#include "bif_arg.h"

int var_arg; // whether the number of arguments is variable
bool uses_frame; // whether the body references @FRAME@
bool uses_args_token; // whether the body references @ARG@/@ARGS@/@ARGC@
std::vector<BuiltinFuncArg*> args;

// Set when the input file contains a top-level "%gen-native" directive.
// When false (the default), every BiF gets the legacy single-function
// emission, preserving backward compatibility for .bif files that haven't
// been adapted to return native types.
bool gen_native = false;

// The current BiF's return type (its BuiltinFuncArg representation) or
// nullptr for void. Captured at return_type, consumed at body_end so
// the _native can use a native primitive return type when applicable.
std::unique_ptr<BuiltinFuncArg> return_type_arg;

// While parsing a func body we accumulate captured C++ into body_buf:
// the body_end action picks among natively-callable native+shim,
// not-natively-callable native+shim, and the legacy single-function form
// based on gen_native plus var_arg / uses_frame / uses_args_token.
bool in_func_body = false;
std::string body_buf;

void emit_body(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vappendf(body_buf, fmt, ap);
    va_end(ap);
}

void emit_body_line_directive() {
    appendf(body_buf, "\n#line %d \"%s\"\n", line_number, input_filename_with_path);
}

// Route output to body_buf when we're parsing a func body, otherwise straight
// to fp_func_def.
void emit_def(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    if ( in_func_body )
        vappendf(body_buf, fmt, ap);
    else
        vfprintf(fp_func_def, fmt, ap);
    va_end(ap);
}

void emit_def_line_directive() {
    if ( in_func_body )
        emit_body_line_directive();
    else
        print_line_directive(fp_func_def);
}

// Snapshot of decl state captured at head_1, for use when we materialize
// the function definition at body_end.
struct func_emit_state {
    std::string c_namespace_start;
    std::string c_namespace_end;
    std::string c_fullname;
    std::string zeek_fullname;
    std::string bare_name;
} func_emit;

// Build a comma-separated list by invoking print_one() for each arg in the
// `args` global. Used for native-function parameter lists ("type name")
// and call-argument lists ("name"), both of which only differ in which
// per-arg printer they use. Only meaningful for natively-callable BiFs;
// not-natively-callable ones get (Frame*, Args*) instead.
template<typename F> static std::string build_arg_list(F print_one) {
    std::string s;
    for ( auto* arg : args ) {
        if ( ! s.empty() )
            s += ", ";
        print_one(arg, s);
    }
    return s;
}

static std::string build_native_param_list() {
    return build_arg_list([](BuiltinFuncArg* a, std::string& s) { a->PrintCImplParam(s); });
}

static std::string build_native_call_arg_list() {
    return build_arg_list([](BuiltinFuncArg* a, std::string& s) { a->PrintCImplCallArg(s); });
}

// Emit the argc check for the shim: "exactly N" for fixed-arity, or
// "at least N" for var_arg. Returns nullptr (a ValPtr) on mismatch, which
// is fine because this only runs in the shim, which always returns ValPtr.
static void emit_argc_check(FILE* fp, int argc, bool at_least) {
    const char* op = at_least ? "<" : "!=";
    const char* word = at_least ? "at least" : "exactly";
    fprintf(fp, "\t{\n");
    fprintf(fp, "\t// NOLINTNEXTLINE(readability-container-size-empty)\n");
    fprintf(fp, "\tif ( %s->size() %s %d )\n", arg_list_name, op, argc);
    fprintf(fp, "\t\t{\n");
    fprintf(fp,
            "\t\tzeek::emit_builtin_error(zeek::util::fmt(\"%s() takes %s %d argument(s), got %%lu\", %s->size()));\n",
            func_emit.zeek_fullname.c_str(), word, argc, arg_list_name);
    fprintf(fp, "\t\treturn nullptr;\n");
    fprintf(fp, "\t\t}\n");
}

// Emit per-arg local extraction. The runtime check is true for BiFs requiring
// dynamic type-checking (due to being variadic).
static void emit_arg_extraction(FILE* fp, int argc, bool runtime_type_check) {
    std::string defs;
    for ( int i = 0; i < argc; ++i )
        args[i]->PrintCDef(defs, i, runtime_type_check);
    fputs(defs.c_str(), fp);
}

// Emit the legacy single-function form: body inline in <name>_bif.
static void emit_legacy_func(std::string captured, int argc) {
    fprintf(fp_func_def,
            "zeek::ValPtr zeek::%s_bif(zeek::detail::Frame* frame, const zeek::Args* %s)\n",
            func_emit.c_fullname.c_str(), arg_list_name);

    if ( ! var_arg ) {
        emit_argc_check(fp_func_def, argc, /*at_least=*/false);
        emit_arg_extraction(fp_func_def, argc, /*runtime_type_check=*/false);

        // Strip the captured body's leading "{" so we don't double-open the
        // brace block we just opened with emit_argc_check.
        auto pos = captured.find('{');
        if ( pos != std::string::npos )
            captured.erase(pos, 1);
    }

    fputs(captured.c_str(), fp_func_def);
}

// Pick the native return type for the current BiF.
struct native_ret_info {
    bool has_native_ret;
    const char* native_to_val; // fmt (one %s) wrapping native -> ValPtr
    const char* native_ret_type; // C++ return type of the _native function
};

static native_ret_info compute_native_ret_info() {
    const char* native_ret = (return_type_arg ? return_type_arg->NativeReturnType() : "");
    const char* native_to_val = (return_type_arg ? return_type_arg->NativeToVal() : "");
    bool has = *native_ret;
    return {has, native_to_val, has ? native_ret : "zeek::ValPtr"};
}

// Emit the shim's body: argc-check + per-arg type-check + extraction;
// then a call to _native via the supplied call_args list; and a
// possibly-wrapped return.
static void emit_shim(int argc, const std::string& call_args, const native_ret_info& nri) {
    fprintf(fp_func_def,
            "\nzeek::ValPtr zeek::%s_bif(zeek::detail::Frame* frame, const zeek::Args* %s)\n",
            func_emit.c_fullname.c_str(), arg_list_name);

    if ( argc > 0 || ! var_arg )
        emit_argc_check(fp_func_def, argc, /*at_least=*/var_arg);
    else
        fprintf(fp_func_def, "\t{\n");

    if ( argc > 0 )
        emit_arg_extraction(fp_func_def, argc, /*runtime_type_check=*/var_arg);

    std::string call;
    appendf(call, "zeek::%s_native(%s)", func_emit.c_fullname.c_str(), call_args.c_str());

    if ( nri.has_native_ret ) {
        std::string wrapped;
        appendf(wrapped, nri.native_to_val, call.c_str());
        fprintf(fp_func_def, "\treturn %s;\n", wrapped.c_str());
    }
    else
        fprintf(fp_func_def, "\treturn %s;\n", call.c_str());

    fprintf(fp_func_def, "\t} // end of shim for %s\n", func_emit.c_fullname.c_str());
}

// Emit a natively-callable function along with its shim.
static void emit_natively_callable(const std::string& captured, int argc) {
    auto nri = compute_native_ret_info();
    std::string params = build_native_param_list();

    fprintf(fp_func_h, "namespace zeek::%s { extern %s %s_native(%s);%s }\n",
            func_emit.c_namespace_start.c_str(), nri.native_ret_type, func_emit.bare_name.c_str(),
            params.c_str(), func_emit.c_namespace_end.c_str());

    fprintf(fp_func_def, "%s zeek::%s_native(%s)", nri.native_ret_type, func_emit.c_fullname.c_str(),
            params.c_str());
    fputs(captured.c_str(), fp_func_def);

    emit_shim(argc, build_native_call_arg_list(), nri);
}

// Emit a not-natively-callable function along with its shim. The shim does
// the argc + per-arg type check and the native's body opens with bare per-arg
// extraction.
static void emit_not_natively_callable(std::string captured, int argc) {
    auto nri = compute_native_ret_info();

    fprintf(fp_func_h,
            "namespace zeek::%s { extern %s %s_native(zeek::detail::Frame* frame, const zeek::Args*);%s }\n",
            func_emit.c_namespace_start.c_str(), nri.native_ret_type, func_emit.bare_name.c_str(),
            func_emit.c_namespace_end.c_str());

    fprintf(fp_func_def,
            "%s zeek::%s_native(zeek::detail::Frame* frame, const zeek::Args* %s)\n",
            nri.native_ret_type, func_emit.c_fullname.c_str(), arg_list_name);

    if ( argc > 0 ) {
        fprintf(fp_func_def, "\t{\n");
        emit_arg_extraction(fp_func_def, argc, /*runtime_type_check=*/false);

        // Strip the captured body's leading "{" so we don't double-open the
        // brace block we just opened.
        auto pos = captured.find('{');
        if ( pos != std::string::npos )
            captured.erase(pos, 1);
    }

    fputs(captured.c_str(), fp_func_def);

    std::string call_args = "frame, ";
    call_args += arg_list_name;
    emit_shim(argc, call_args, nri);
}

extern int yyerror(const char[]);
extern int yywarn(const char msg[]);
extern int yylex();

char* concat(const char* str1, const char* str2) {
    int len1 = strlen(str1);
    int len2 = strlen(str2);

    char* s = new char[len1 + len2 + 1];

    memcpy(s, str1, len1);
    memcpy(s + len1, str2, len2);

    s[len1 + len2] = '\0';

    return s;
}

static void print_event_c_prototype_args(FILE * fp) {
    for ( auto i = 0u; i < args.size(); ++i ) {
        if ( i > 0 )
            fprintf(fp, ", ");

        args[i]->PrintCArg(fp, i);
    }
}

static void print_event_c_prototype_header(FILE * fp) {
    fprintf(fp, "namespace zeek::%s { void %s(zeek::analyzer::Analyzer* analyzer%s",
            decl.enqueue_c_namespace_start.c_str(), decl.enqueue_c_barename.c_str(), args.size() ? ", " : "");

    print_event_c_prototype_args(fp);
    fprintf(fp, ")");
    fprintf(fp, "; %s }\n", decl.enqueue_c_namespace_end.c_str());
}

static void print_event_c_prototype_native(FILE * fp) {
    fprintf(fp, "void %s(zeek::analyzer::Analyzer* analyzer%s", decl.enqueue_c_fullname.c_str(),
            args.size() ? ", " : "");

    print_event_c_prototype_args(fp);
    fprintf(fp, ")");
    fprintf(fp, "\n");
}

static void print_event_c_body(FILE * fp) {
    fprintf(fp, "\t{\n");
    fprintf(fp, "\t// Note that it is intentional that here we do not\n");
    fprintf(fp, "\t// check if %s is NULL, which should happen *before*\n", decl.c_fullname.c_str());
    fprintf(fp, "\t// %s is called to avoid unnecessary Val\n", decl.enqueue_c_fullname.c_str());
    fprintf(fp, "\t// allocation.\n");
    fprintf(fp, "\n");

    BuiltinFuncArg* connection_arg = nullptr;

    fprintf(fp, "\tzeek::event_mgr.Enqueue(%s, zeek::Args{\n", decl.c_fullname.c_str());

    for ( const auto& arg : args ) {
        fprintf(fp, "\t        ");
        arg->PrintValConstructor(fp);
        fprintf(fp, ",\n");

        if ( arg->Type() == TYPE_CONNECTION ) {
            if ( connection_arg == nullptr )
                connection_arg = arg;
            else {
                // We are seeing two connection type arguments.
                yywarn(
                    "Warning: with more than connection-type "
                    "event arguments, bifcl only passes "
                    "the first one to EventMgr as cookie.");
            }
        }
    }

    fprintf(fp, "\t        },\n\t    zeek::util::detail::SOURCE_LOCAL, analyzer ? analyzer->GetID() : 0");

    if ( connection_arg )
        // Pass the connection to the EventMgr as the "cookie"
        fprintf(fp, ", %s", connection_arg->Name());

    fprintf(fp, ");\n");
    fprintf(fp, "\t}\n\n");
}

void record_bif_item(const char* id, const char* type) {
    if ( ! plugin )
        return;

    fprintf(fp_func_init, "\tplugin->AddBifItem(\"%s\", zeek::plugin::BifItem::%s);\n", id, type);
}

// Begin a FUNC_DEF: emit the canonical _bif extern, register the BiF item,
// snapshot the namespace info that the body action needs, and switch
// fp_func_def writes over to body_buf.
static void begin_func_def() {
    fprintf(fp_func_h,
            "namespace zeek::%s { extern zeek::ValPtr %s_bif(zeek::detail::Frame* frame, const zeek::Args*);%s }\n",
            decl.c_namespace_start.c_str(), decl.bare_name.c_str(), decl.c_namespace_end.c_str());

    record_bif_item(decl.zeek_fullname.c_str(), "FUNCTION");

    func_emit.c_namespace_start = decl.c_namespace_start;
    func_emit.c_namespace_end = decl.c_namespace_end;
    func_emit.c_fullname = decl.c_fullname;
    func_emit.zeek_fullname = decl.zeek_fullname;
    func_emit.bare_name = decl.bare_name;

    in_func_body = true;
    body_buf.clear();
    emit_body_line_directive();
}

// Begin an EVENT_DEF: register the event handler the first time we see
// this event name. (Repeat declarations from alternate event prototypes
// only need to update the .zeek file, which happens elsewhere.)
static void begin_event_def() {
    if ( events.find(decl.zeek_fullname) != events.end() )
        return;

    fprintf(fp_netvar_h, "%sextern zeek::EventHandlerPtr %s; %s\n", decl.c_namespace_start.c_str(),
            decl.bare_name.c_str(), decl.c_namespace_end.c_str());

    fprintf(fp_netvar_def, "%szeek::EventHandlerPtr %s; %s\n", decl.c_namespace_start.c_str(),
            decl.bare_name.c_str(), decl.c_namespace_end.c_str());

    fprintf(fp_netvar_init, "\t%s = zeek::event_registry->Register(\"%s\");\n", decl.c_fullname.c_str(),
            decl.zeek_fullname.c_str());

    record_bif_item(decl.zeek_fullname.c_str(), "EVENT");
}

%}

%token TOK_LPP TOK_RPP TOK_LPB TOK_RPB TOK_LPPB TOK_RPPB TOK_VAR_ARG
%token TOK_BOOL
%token TOK_FUNCTION TOK_EVENT TOK_CONST TOK_ENUM TOK_OF
%token TOK_TYPE TOK_RECORD TOK_SET TOK_VECTOR TOK_OPAQUE TOK_TABLE TOK_MODULE
%token TOK_ARGS TOK_ARG TOK_ARGC TOK_FRAME
%token TOK_GEN_NATIVE
%token TOK_ID TOK_ATTR TOK_CSTR TOK_LF TOK_WS TOK_COMMENT
%token TOK_ATOM TOK_INT TOK_C_TOKEN

%left ',' ':'

%type <str> TOK_C_TOKEN TOK_ID TOK_CSTR TOK_WS TOK_COMMENT TOK_ATTR TOK_INT opt_ws type attr_list opt_attr_list opt_func_attrs
%type <val> TOK_ATOM TOK_BOOL

%union	{
	const char* str;
	int val;
}

%%

builtin_lang:	definitions
			{
			fprintf(fp_zeek_init, "} # end of export section\n");
			fprintf(fp_zeek_init, "module %s;\n", GLOBAL_MODULE_NAME);
			}



definitions:	definitions definition opt_ws
			{
			if ( in_c_code )
				fprintf(fp_func_def, "%s", $3);
			else
				fprintf(fp_zeek_init, "%s", $3);
			}
	|	opt_ws
			{
			fprintf(fp_zeek_init, "export {\n");
			fprintf(fp_zeek_init, "%s", $1);
			}
	;

definition:	event_def
	|	func_def
	|	c_code_segment
	|	enum_def
	|	const_def
	|	type_def
	|	module_def
	|	gen_native_attr
	;

gen_native_attr: TOK_GEN_NATIVE
			{ gen_native = true; }
	;


module_def:	TOK_MODULE opt_ws TOK_ID opt_ws ';'
			{
			current_module = string($3);
			fprintf(fp_zeek_init, "module %s;\n", $3);
			}

	 // XXX: Add the netvar glue so that the event engine knows about
	 // the type. One still has to define the type in zeek.init.
	 // Would be nice, if we could just define the record type here
	 // and then copy to the .bif.zeek file, but type declarations in
	 // Zeek can be quite powerful. Don't know whether it's worth it
	 // extend the bif-language to be able to handle that all....
	 // Or we just support a simple form of record type definitions
	 // TODO: add other types (tables, sets)
type_def:	TOK_TYPE opt_ws TOK_ID opt_ws ':' opt_ws type_def_types opt_ws ';'
			{
			set_decl_name($3);

			fprintf(fp_netvar_h, "namespace zeek::%s { extern zeek::IntrusivePtr<zeek::%sType> %s; }\n",
				decl.c_namespace_start.c_str(), type_name.c_str(), decl.bare_name.c_str());

			fprintf(fp_netvar_def, "namespace zeek::%s { zeek::IntrusivePtr<zeek::%sType> %s; }\n",
				decl.c_namespace_start.c_str(), type_name.c_str(), decl.bare_name.c_str());
			fprintf(fp_netvar_def, "namespace %s { zeek::%sType * %s; }\n",
				decl.c_namespace_start.c_str(), type_name.c_str(), decl.bare_name.c_str());

			fprintf(fp_netvar_init,
				"\tzeek::%s = zeek::id::find_type<zeek::%sType>(\"%s\");\n",
				decl.c_fullname.c_str(), type_name.c_str(),
				decl.zeek_fullname.c_str());

			record_bif_item(decl.zeek_fullname.c_str(), "TYPE");
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

opt_func_attrs:	attr_list opt_ws
		{ $$ = $1; }
	| /* nothing */
		{ $$ = ""; }
	;

event_def:	event_prefix opt_ws plain_head opt_ws opt_func_attrs
			{ fprintf(fp_zeek_init, "%s", $5); } end_of_head ';'
			{
			if ( events.find(decl.zeek_fullname) == events.end() )
				{
				print_event_c_prototype_header(fp_func_h);
				print_event_c_prototype_native(fp_func_def);
				print_event_c_body(fp_func_def);
				events.insert(decl.zeek_fullname);
				}
			}

func_def:	func_prefix opt_ws typed_head opt_func_attrs
			{ fprintf(fp_zeek_init, "%s", $4); } end_of_head body
	;

enum_def:	enum_def_1 enum_list TOK_RPB opt_attr_list
			{
			// First, put an end to the enum type decl.
			fprintf(fp_zeek_init, "} ");
			fprintf(fp_zeek_init, "%s", $4);
			fprintf(fp_zeek_init, ";\n");
			fprintf(fp_netvar_h, "}; }\n");

			// Now generate the netvar's.
			fprintf(fp_netvar_h, "namespace zeek::%s { extern zeek::IntrusivePtr<zeek::EnumType> %s; %s}\n",
				decl.c_namespace_start.c_str(), decl.bare_name.c_str(), decl.c_namespace_end.c_str());
			fprintf(fp_netvar_def, "namespace zeek::%s { zeek::IntrusivePtr<zeek::EnumType> %s; %s}\n",
				decl.c_namespace_start.c_str(), decl.bare_name.c_str(), decl.c_namespace_end.c_str());
			fprintf(fp_netvar_def, "namespace %s { zeek::EnumType * %s; %s }\n",
				decl.c_namespace_start.c_str(), decl.bare_name.c_str(), decl.c_namespace_end.c_str());

			fprintf(fp_netvar_init,
				"\tzeek::%s = zeek::id::find_type<zeek::EnumType>(\"%s\");\n",
				decl.c_fullname.c_str(), decl.zeek_fullname.c_str());

			record_bif_item(decl.zeek_fullname.c_str(), "TYPE");
			}
	;

enum_def_1:	TOK_ENUM opt_ws TOK_ID opt_ws TOK_LPB opt_ws
			{
			set_definition_type(TYPE_DEF, "Enum");
			set_decl_name($3);
			fprintf(fp_zeek_init, "type %s: enum %s{%s", decl.zeek_name.c_str(), $4, $6);

			// this is the namespace were the enumerators are defined, not where
			// the type is defined.
			// We don't support fully qualified names as enumerators. Use a module name
			fprintf(fp_netvar_h, "// NOLINTNEXTLINE(performance-enum-size)\n");
			if ( decl.module_name != GLOBAL_MODULE_NAME )
				fprintf(fp_netvar_h, "namespace zeek::BifEnum::%s { ", decl.module_name.c_str());
			else
				fprintf(fp_netvar_h, "namespace zeek::BifEnum { ");
			fprintf(fp_netvar_h, "enum %s {\n", $3);
			}
	;

enum_list:	enum_list TOK_ID opt_ws ',' opt_ws
			{
			fprintf(fp_zeek_init, "%s%s,%s", $2, $3, $5);
			fprintf(fp_netvar_h, "\t%s,\n", $2);
			}
	| 		enum_list TOK_ID opt_ws '=' opt_ws TOK_INT opt_ws ',' opt_ws
			{
			fprintf(fp_zeek_init, "%s = %s%s,%s", $2, $6, $7, $9);
			fprintf(fp_netvar_h, "\t%s = %s,\n", $2, $6);
			}
	|	/* nothing */
	;


const_def:	TOK_CONST opt_ws TOK_ID opt_ws ':' opt_ws TOK_ID opt_ws ';'
			{
			set_definition_type(CONST_DEF, nullptr);
			set_decl_name($3);
			int typeidx = get_type_index($7);
			char accessor[1024];
			char accessor_smart[1024];

			snprintf(accessor, sizeof(accessor), bif_types[typeidx].accessor, "");
			snprintf(accessor_smart, sizeof(accessor_smart), bif_types[typeidx].accessor_smart, "");


			fprintf(fp_netvar_h, "namespace zeek::%s { extern %s %s; }\n",
					decl.c_namespace_start.c_str(),
					bif_types[typeidx].c_type_smart, decl.bare_name.c_str());

			fprintf(fp_netvar_def, "namespace zeek::%s { %s %s; }\n",
					decl.c_namespace_start.c_str(),
					bif_types[typeidx].c_type_smart, decl.bare_name.c_str());
			fprintf(fp_netvar_def, "namespace %s { %s %s; } \n",
					decl.c_namespace_start.c_str(),
					bif_types[typeidx].c_type, decl.bare_name.c_str());

			if ( alternative_mode && ! plugin )
				fprintf(fp_netvar_init, "\tzeek::detail::bif_initializers.emplace_back([]()\n");

			fprintf(fp_netvar_init, "\t{\n");
			fprintf(fp_netvar_init, "\tconst auto& v = zeek::id::find_const%s(\"%s\");\n",
					bif_types[typeidx].cast_smart, decl.zeek_fullname.c_str());
			fprintf(fp_netvar_init, "\tzeek::%s = v%s;\n",
					decl.c_fullname.c_str(), accessor_smart);
			fprintf(fp_netvar_init, "\t}\n");

			if ( alternative_mode && ! plugin )
				fprintf(fp_netvar_init, "\t);\n");

			record_bif_item(decl.zeek_fullname.c_str(), "CONSTANT");
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
			{ set_definition_type(FUNC_DEF, nullptr); }
	;

event_prefix:	TOK_EVENT
			{ set_definition_type(EVENT_DEF, nullptr); }
	;

end_of_head:	/* nothing */
			{
			fprintf(fp_zeek_init, ";\n");
			}
	;

typed_head:	plain_head opt_ws return_type
			{
			}
	|	plain_head opt_ws
			{
			}
	;

plain_head:	head_1 args arg_end
			{
			if ( var_arg )
				fprintf(fp_zeek_init, "va_args: any");
			else
				{
				for ( int i = 0; i < (int) args.size(); ++i )
					{
					if ( i > 0 )
						fprintf(fp_zeek_init, ", ");
					args[i]->PrintZeek(fp_zeek_init);
					}
				}

			fprintf(fp_zeek_init, ")");
			}
	;

head_1:		TOK_ID opt_ws arg_begin
			{
			set_decl_name($1);

			if ( definition_type == FUNC_DEF )
				{
				fprintf(fp_zeek_init, "global %s: function(", decl.zeek_name.c_str());
				begin_func_def();
				}

			else if ( definition_type == EVENT_DEF )
				{
				fprintf(fp_zeek_init, "global %s: event(", decl.zeek_name.c_str());
				begin_event_def();
				}
			}
	;

arg_begin:	TOK_LPP
			{
			args.clear();
			var_arg = 0;
			uses_frame = uses_args_token = false;
			return_type_arg.reset();
			}
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
// can parse all regular Zeek types, we can throw out the unnecessary
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
			return_type_arg = std::make_unique<BuiltinFuncArg>("", $3);
			return_type_arg->PrintZeek(fp_zeek_init);
			emit_body("%s", $4);
			}
	;

body:		body_start c_body body_end
			{
			emit_body(" // end of %s\n", decl.c_fullname.c_str());
			emit_body_line_directive();

			std::string captured = std::move(body_buf);
			body_buf.clear();
			in_func_body = false;

			// natively_callable: gen_native files always produce
			// a _native + _bif split. Those that can be called
			// directly get a typed-parameter declaration,
			// otherwise a (Frame*, Args*) native that the shim
			// simply forwards to.
			bool natively_callable = gen_native &&
				! (var_arg || uses_args_token || uses_frame);
			int argc = (int) args.size();

			fprintf(fp_func_init,
			        "\t(void) new zeek::detail::BuiltinFunc(zeek::%s_bif, \"%s\", false);\n",
			        func_emit.c_fullname.c_str(),
				func_emit.zeek_fullname.c_str());

			if ( natively_callable )
				emit_natively_callable(captured, argc);
			else if ( gen_native )
				emit_not_natively_callable(std::move(captured), argc);
			else
				emit_legacy_func(std::move(captured), argc);
			}
	;

c_code_begin:	/* empty */
			{
			in_c_code = true;
			emit_def_line_directive();
			}
	;

c_code_end:	/* empty */
			{ in_c_code = false; }
	;

body_start:	TOK_LPB c_code_begin
			{
			int argc = args.size();

			emit_body("{");

			// For var_arg BiFs the body needs to do the argc check
			// check and per-arg local extractions. Under gen_native
			// this work moves to the shim.
			if ( ! gen_native && var_arg && argc > 0 )
				{
				emit_body("\n");
				emit_body("\t// NOLINTNEXTLINE(readability-container-size-empty)\n");
				emit_body("\tif ( %s->size() < %d )\n", arg_list_name, argc);
				emit_body("\t\t{\n");
				emit_body(
					"\t\tzeek::emit_builtin_error(zeek::util::fmt(\"%s() takes at least %d argument(s), got %%lu\", %s->size()));\n",
					decl.zeek_fullname.c_str(), argc, arg_list_name);
				emit_body("\t\treturn nullptr;\n");
				emit_body("\t\t}\n");

				std::string defs;
				for ( int i = 0; i < argc; ++i )
					args[i]->PrintCDef(defs, i, /*runtime_type_check=*/true);
				body_buf += defs;
				}
			emit_body_line_directive();
			}
	;

body_end:	TOK_RPB c_code_end
			{
			emit_body("}");
			}
	;

c_code_segment: TOK_LPPB c_code_begin c_body c_code_end TOK_RPPB
	;

c_body:		opt_ws
			{ emit_def("%s", $1); }
	|	c_body c_atom opt_ws
			{ emit_def("%s", $3); }
	;

c_atom:		TOK_ID
			{ emit_def("%s", $1); }
	|	TOK_C_TOKEN
			{ emit_def("%s", $1); }
	|	TOK_ARG
			{ emit_def("(*%s)", arg_list_name); uses_args_token = true; }
	|	TOK_ARGS
			{ emit_def("%s", arg_list_name); uses_args_token = true; }
	|	TOK_ARGC
			{ emit_def("%s->size()", arg_list_name); uses_args_token = true; }
	|	TOK_FRAME
			{ emit_def("frame"); uses_frame = true; }
	|	TOK_CSTR
			{ emit_def("%s", $1); }
	|	TOK_ATOM
			{ emit_def("%c", $1); }
	|	TOK_INT
			{ emit_def("%s", $1); }

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
					// generate zeek script documentation, so pass it through.
					$$ = concat($1, $2);
				else
					$$ = $1;
			}
	|	/* empty */
			{ $$ = ""; }
	;

%%

extern char* yytext;
void err_exit(void);

void print_msg(const char msg[]) {
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

    delete[] msgbuf;
}

int yywarn(const char msg[]) {
    print_msg(msg);
    return 0;
}

int yyerror(const char msg[]) {
    print_msg(msg);

    err_exit();
    return 0;
}

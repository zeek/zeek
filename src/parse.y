%{
// See the file "COPYING" in the main distribution directory for copyright.
%}

// Switching parser table type fixes ambiguity problems.
%define lr.type ielr

%expect 217

%token TOK_ADD TOK_ADD_TO TOK_ADDR TOK_ANY TOK_ASSERT
%token TOK_ATENDIF TOK_ATELSE TOK_ATIF TOK_ATIFDEF TOK_ATIFNDEF
%token TOK_BOOL TOK_BREAK TOK_CASE TOK_OPTION TOK_CONST
%token TOK_CONSTANT TOK_COPY TOK_COUNT TOK_DEFAULT TOK_DELETE
%token TOK_DOUBLE TOK_ELSE TOK_ENUM TOK_EVENT TOK_EXPORT TOK_FALLTHROUGH
%token TOK_FILE TOK_FOR TOK_FUNCTION TOK_GLOBAL TOK_HOOK TOK_ID TOK_IF TOK_INT
%token TOK_INTERVAL TOK_LIST TOK_MODULE
%token TOK_LOCAL TOK_WHEN_LOCAL
%token TOK_NEXT TOK_OF TOK_OPAQUE TOK_PATTERN TOK_PATTERN_END TOK_PATTERN_TEXT
%token TOK_PORT TOK_PRINT TOK_RECORD TOK_REDEF
%token TOK_REMOVE_FROM TOK_RETURN TOK_SCHEDULE TOK_SET
%token TOK_STRING TOK_SUBNET TOK_SWITCH TOK_TABLE
%token TOK_TIME TOK_TIMEOUT TOK_TYPE TOK_VECTOR TOK_WHEN
%token TOK_WHILE TOK_AS TOK_IS
%token TOK_GLOBAL_ID

%token TOK_ATTR_ADD_FUNC TOK_ATTR_DEFAULT TOK_ATTR_DEFAULT_INSERT TOK_ATTR_OPTIONAL TOK_ATTR_REDEF
%token TOK_ATTR_DEL_FUNC TOK_ATTR_EXPIRE_FUNC
%token TOK_ATTR_EXPIRE_CREATE TOK_ATTR_EXPIRE_READ TOK_ATTR_EXPIRE_WRITE
%token TOK_ATTR_RAW_OUTPUT TOK_ATTR_ON_CHANGE TOK_ATTR_BROKER_STORE
%token TOK_ATTR_BROKER_STORE_ALLOW_COMPLEX TOK_ATTR_BACKEND
%token TOK_ATTR_PRIORITY TOK_ATTR_LOG TOK_ATTR_ERROR_HANDLER TOK_ATTR_GROUP
%token TOK_ATTR_TYPE_COLUMN TOK_ATTR_DEPRECATED
%token TOK_ATTR_IS_ASSIGNED TOK_ATTR_IS_USED TOK_ATTR_ORDERED

%token TOK_DEBUG

%token TOK_NO_TEST

%left ','
%right '=' TOK_ADD_TO TOK_REMOVE_FROM TOK_ADD TOK_DELETE
%right '?' ':'
%left TOK_OR_OR
%left TOK_AND_AND
%nonassoc TOK_HOOK
%nonassoc '<' '>' TOK_LE TOK_GE TOK_EQ TOK_NE
%left TOK_IN TOK_NOT_IN
%left '|'
%left '^'
%left '&'
%left TOK_LSHIFT TOK_RSHIFT
%left '+' '-'
%left '*' '/' '%'
%left TOK_INCR TOK_DECR
%right '!' '~'
%left '$' '[' ']' '(' ')' TOK_HAS_FIELD TOK_HAS_ATTR
%nonassoc TOK_AS TOK_IS

%type <b> opt_no_test opt_no_test_block opt_deep when_flavor
%type <str> TOK_ID TOK_PATTERN_TEXT TOK_GLOBAL_ID lookup_identifier
%type <id> local_id global_id def_global_id event_id global_or_event_id resolve_id begin_lambda case_type
%type <id_l> local_id_list case_type_list
%type <ic> init_class
%type <val> TOK_CONSTANT
%type <expr> expr opt_expr rhs opt_init anonymous_function lambda_body index_slice opt_deprecated when_condition
%type <event_expr> event
%type <stmt> stmt stmt_list func_body for_head
%type <type> simple_type type opt_type enum_body
%type <func_type> func_hdr func_params
%type <type_l> type_list
%type <type_decl> type_decl formal_args_decl
%type <type_decl_l> type_decl_list formal_args_decl_list
%type <record> formal_args
%type <list> expr_list opt_expr_list rhs_expr_list
%type <c_case> case
%type <case_l> case_list
%type <attr> attr
%type <attr_l> attr_list opt_attr
%type <capture> capture
%type <captures> capture_list opt_captures when_captures
%type <when_clause> when_head when_start when_clause
%type <re_modes> TOK_PATTERN_END
%type <expr> opt_assert_msg

%{
#include <cassert>
#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <set>
#include <string>

#include "zeek/Desc.h"
#include "zeek/Expr.h"
#include "zeek/Func.h"
#include "zeek/IntrusivePtr.h"
#include "zeek/RE.h"
#include "zeek/Reporter.h"
#include "zeek/Scope.h"
#include "zeek/ScriptCoverageManager.h"
#include "zeek/ScriptValidation.h"
#include "zeek/Stmt.h"
#include "zeek/Val.h"
#include "zeek/Var.h"
#include "zeek/ZeekList.h"
#include "zeek/input.h"
#include "zeek/module_util.h"
#include "zeek/zeekygen/Manager.h"
#include "zeek/DebugLogger.h"

extern const char* filename;      // Absolute path of file currently being parsed.
extern const char* last_filename; // Absolute path of last file parsed.
extern const char* last_tok_filename;
extern const char* last_last_tok_filename;

extern int conditional_epoch; // let's us track embedded conditionals

// Whether the file we're currently parsing includes @if conditionals.
extern bool current_file_has_conditionals;

extern YYLTYPE GetCurrentLocation();
extern int yyerror(const char[]);
extern int zeeklex();

#define YYLLOC_DEFAULT(Current, Rhs, N) (Current) = (Rhs)[(N)];

using namespace zeek;
using namespace zeek::detail;

// Part of the module facility: while parsing, keep track of which
// module to put things in.
std::string zeek::detail::current_module = GLOBAL_MODULE_NAME;

bool is_export = false; // true if in an export {} block

// Used to temporarily turn off "is_export". A stack because the need
// to do so can nest.
std::vector<bool> hold_is_export;

// When parsing an expression for the debugger, where to put the result
// (obviously not reentrant).
extern Expr* g_curr_debug_expr;
extern bool in_debug;
extern const char* g_curr_debug_error;

extern int in_when_cond;

static int in_hook = 0;
int in_init = 0;
int in_record = 0;
static int in_record_redef = 0;
static int in_enum_redef = 0;
bool resolving_global_ID = false;
bool defining_global_ID = false;
std::vector<int> saved_in_init;
static int expr_list_has_opt_comma = 0;

std::vector<std::set<const ID*>> locals_at_this_scope;
static std::unordered_set<const ID*> out_of_scope_locals;

static Location func_hdr_location;
static int func_hdr_cond_epoch = 0;
EnumType* cur_enum_type = nullptr;
static ID* cur_decl_type_id = nullptr;

static void parse_new_enum(void) {
    // Starting a new enum definition.
    assert(cur_enum_type == nullptr);

    if ( cur_decl_type_id ) {
        auto name = make_full_var_name(current_module.c_str(), cur_decl_type_id->Name());
        cur_enum_type = new EnumType(name);
    }
    else
        reporter->FatalError("incorrect syntax for enum type declaration");
}

static void parse_redef_enum(ID* id) {
    // Redef an enum. id points to the enum to be redefined.
    // Let cur_enum_type point to it.
    assert(cur_enum_type == nullptr);

    // abort on errors; enums need to be accessible to continue parsing
    if ( ! id->GetType() )
        reporter->FatalError("unknown enum identifier \"%s\"", id->Name());
    else {
        if ( ! id->GetType() || id->GetType()->Tag() != TYPE_ENUM )
            reporter->FatalError("identifier \"%s\" is not an enum", id->Name());
        cur_enum_type = id->GetType()->AsEnumType();
    }
}

static void parse_redef_record_field(ID* id, const char* field, InitClass ic,
                                     std::unique_ptr<std::vector<AttrPtr>> attrs) {
    if ( ! id->GetType() ) {
        reporter->FatalError("unknown record identifier \"%s\"", id->Name());
        return;
    }

    auto t = id->GetType();
    if ( ! t || t->Tag() != TYPE_RECORD ) {
        reporter->FatalError("identifier \"%s\" has type \"%s\", expected \"record\"", id->Name(), type_name(t->Tag()));
        return;
    }

    auto rt = t->AsRecordType();
    auto idx = rt->FieldOffset(field);
    if ( idx < 0 ) {
        reporter->FatalError("field \"%s\" not in record \"%s\"", field, id->Name());
        return;
    }

    auto decl = rt->FieldDecl(idx);
    if ( ! decl->attrs )
        if ( ic == INIT_EXTRA )
            decl->attrs = make_intrusive<detail::Attributes>(decl->type, true /* in_record */, false /* is_global */);

    for ( const auto& attr : *attrs ) {
        // At this point, only support &log redef'ing.
        if ( attr->Tag() != ATTR_LOG ) {
            reporter->FatalError("Can only redef \"&log\" attributes of record fields");
            return;
        }

        if ( ic == INIT_EXTRA )
            decl->attrs->AddAttr(attr, true /* is_redef */);
        else
            // Removing attributes is a noop if they don't exist.
            if ( decl->attrs )
                decl->attrs->RemoveAttr(attr->Tag());
    }
}

static void extend_record(ID* id, std::unique_ptr<type_decl_list> fields, std::unique_ptr<std::vector<AttrPtr>> attrs) {
    const auto& types = Type::Aliases(id->Name());

    if ( types.empty() ) {
        id->Error("failed to redef record: no types found in alias map");
        return;
    }

    bool add_log_attr = false;

    if ( attrs )
        for ( const auto& at : *attrs )
            if ( at->Tag() == ATTR_LOG ) {
                add_log_attr = true;
                break;
            }

    for ( const auto& t : types ) {
        auto error = t->AsRecordType()->AddFields(*fields, add_log_attr);

        if ( error ) {
            id->Error(error);
            break;
        }
    }
}

static AttributesPtr make_attributes(std::vector<AttrPtr>* attrs, TypePtr t, bool in_record, bool is_global) {
    if ( ! attrs )
        return nullptr;

    auto rval = make_intrusive<Attributes>(std::move(*attrs), std::move(t), in_record, is_global);
    delete attrs;
    return rval;
}

static bool expr_is_table_type_name(const Expr* expr) {
    if ( expr->Tag() != EXPR_NAME )
        return false;

    const auto& type = expr->GetType();

    if ( type->IsTable() )
        return true;

    if ( type->Tag() == TYPE_TYPE )
        return type->AsTypeType()->GetType()->IsTable();

    return false;
}

static void check_loop_var(const IDPtr& var) {
    if ( var->IsGlobal() )
        var->Error("global variable used in 'for' loop");

    if ( var->IsConst() )
        var->Error("constant used in 'for' loop");
}

static void build_global(ID* id, Type* t, InitClass ic, Expr* e, std::vector<AttrPtr>* attrs, DeclType dt) {
    IDPtr id_ptr{AdoptRef{}, id};
    TypePtr t_ptr{AdoptRef{}, t};
    ExprPtr e_ptr{AdoptRef{}, e};

    auto attrs_ptr = attrs ? std::make_unique<std::vector<AttrPtr>>(*attrs) : nullptr;

    add_global(id_ptr, std::move(t_ptr), ic, e_ptr, std::move(attrs_ptr), dt);

    if ( dt == VAR_REDEF )
        zeekygen_mgr->Redef(id, ::filename, ic, std::move(e_ptr));
    else
        zeekygen_mgr->Identifier(std::move(id_ptr));
}

static StmtPtr build_local(ID* id, Type* t, InitClass ic, Expr* e, std::vector<AttrPtr>* attrs, DeclType dt,
                           bool do_coverage) {
    IDPtr id_ptr{AdoptRef{}, id};
    TypePtr t_ptr{AdoptRef{}, t};
    ExprPtr e_ptr{AdoptRef{}, e};

    auto attrs_ptr = attrs ? std::make_unique<std::vector<AttrPtr>>(*attrs) : nullptr;

    auto init = add_local(std::move(id_ptr), std::move(t_ptr), ic, e_ptr, std::move(attrs_ptr), dt);

    if ( do_coverage )
        script_coverage_mgr.AddStmt(init.get());

    return init;
}

static void refine_location(zeek::detail::ID* id) {
    if ( *id->GetLocationInfo() == zeek::detail::no_location )
        id->SetLocationInfo(&detail::start_location, &detail::end_location);
}

%}

%union {
	bool b;
	char* str;
	zeek::detail::ID* id;
	zeek::IDPList* id_l;
	zeek::detail::InitClass ic;
	zeek::Val* val;
	zeek::RE_Matcher* re;
	zeek::detail::Expr* expr;
	zeek::detail::EventExpr* event_expr;
	zeek::detail::Stmt* stmt;
	zeek::detail::ListExpr* list;
	zeek::Type* type;
	zeek::RecordType* record;
	zeek::FuncType* func_type;
	zeek::TypeList* type_l;
	zeek::TypeDecl* type_decl;
	zeek::type_decl_list* type_decl_l;
	zeek::detail::Case* c_case;
	zeek::detail::case_list* case_l;
	zeek::detail::Attr* attr;
	std::vector<zeek::detail::AttrPtr>* attr_l;
	zeek::detail::AttrTag attrtag;
	zeek::FuncType::Capture* capture;
	zeek::FuncType::CaptureList* captures;
	zeek::detail::WhenInfo* when_clause;
	struct {
		bool ignore_case;
		bool single_line;
	} re_modes;
}

%%

zeek:
		decl_list
			{
			// Without the following, in some scenarios the
			// location associated with global statements gets
			// associated with the last @load'd file rather than
			// the script that includes the global statements.
			auto loc = zeek::detail::GetCurrentLocation();
			if ( loc.filename )
				set_location(loc);
			}
		stmt_list
			{
			if ( stmts )
				stmts->AsStmtList()->Stmts().push_back({AdoptRef{}, $3});
			else
				stmts = $3;

			// Do some further validation on the parsed AST unless
			// we already know there were errors.
			if ( zeek::reporter->Errors() == 0 )
				zeek::detail::script_validation();

			// Any objects creates from here on out should not
			// have file positions associated with them.
			set_location(no_location);
			}
	|
		/* Silly way of allowing the debugger to call yyparse()
		 * on an expr rather than a file.
		 */
		TOK_DEBUG { in_debug = true; } expr
			{
			g_curr_debug_expr = $3;
			}
	;

decl_list:
		decl_list decl
	|
	;

opt_expr:
		expr
			{ $$ = $1; }
	|
			{ $$ = 0; }
	;

when_clause:
		when_head TOK_TIMEOUT expr '{' opt_no_test_block stmt_list '}'
			{
			set_location(@1, @7);
			$1->AddTimeout({AdoptRef{}, $3}, {AdoptRef{}, $6});
			if ( $5 )
			    script_coverage_mgr.DecIgnoreDepth();
			}
	|
		when_head
	;

when_head:
		when_start stmt
			{
			set_location(@1, @2);
			$1->AddBody({AdoptRef{}, $2});
			}
	;

when_start:
		when_flavor '[' when_captures ']' '(' when_condition ')'
			{
			set_location(@1, @7);
			$$ = new WhenInfo({AdoptRef{}, $6}, $3, $1);
			}

	|	when_flavor '(' when_condition ')'
			{
			set_location(@1, @4);
			$$ = new WhenInfo({AdoptRef{}, $3}, nullptr, $1);
			}
	;

when_flavor:
		TOK_RETURN TOK_WHEN
			{ $$ = true; }
	|
		TOK_WHEN
			{ $$ = false; }
	;

when_captures:
		capture_list
	|
		{ $$ = new zeek::FuncType::CaptureList; }
	;

when_condition:
		{ ++in_when_cond; } expr { --in_when_cond; }
			{ $$ = $2; }
		;

expr:
		'(' expr ')'
			{
			set_location(@1, @3);
			$$ = $2; $$->MarkParen();
			}

	|	TOK_COPY '(' expr ')'
			{
			set_location(@1, @4);
			$$ = new CloneExpr({AdoptRef{}, $3});
			}

	|	TOK_ADD expr
			{
			set_location(@1, @2);
			$$ = new AggrAddExpr({AdoptRef{}, $2});
			}

	|	TOK_DELETE expr
			{
			set_location(@1, @2);
			$$ = new AggrDelExpr({AdoptRef{}, $2});
			}

	|	TOK_INCR expr
			{
			set_location(@1, @2);
			$$ = new IncrExpr(EXPR_INCR, {AdoptRef{}, $2});
			}

	|	TOK_DECR expr
			{
			set_location(@1, @2);
			$$ = new IncrExpr(EXPR_DECR, {AdoptRef{}, $2});
			}

	|	'!' expr
			{
			set_location(@1, @2);
			$$ = new NotExpr({AdoptRef{}, $2});
			}

	|	'~' expr
			{
			set_location(@1, @2);
			$$ = new ComplementExpr({AdoptRef{}, $2});
			}

	|	'-' expr	%prec '!'
			{
			set_location(@1, @2);
			$$ = new NegExpr({AdoptRef{}, $2});

			if ( ! $$->IsError() && $2->IsConst() ) {
				auto v = $2->ExprVal();
				auto tag = v->GetType()->Tag();

				if ( tag == TYPE_COUNT ) {
					auto c = v->AsCount();
					uint64_t int_max = static_cast<uint64_t>(INT64_MAX) + 1;

					if ( c <= int_max ) {
						auto ce = new ConstExpr(val_mgr->Int(-c));
						Unref($$);
						$$ = ce;
					}
					else {
						$$->Error("literal is outside range of 'int' values");
						$$->SetError();
					}
				}
				else {
					auto ce = new ConstExpr($$->Eval(nullptr));
					Unref($$);
					$$ = ce;
				}
			}
			}

	|	'+' expr	%prec '!'
			{
			set_location(@1, @2);
			$$ = new PosExpr({AdoptRef{}, $2});
			}

	|	expr '+' expr
			{
			set_location(@1, @3);
			$$ = new AddExpr({AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_ADD_TO rhs
			{
			set_location(@1, @3);

			ExprPtr lhs = {AdoptRef{}, $1};
			ExprPtr rhs = {AdoptRef{}, $3};
			auto tag1 = $1->GetType()->Tag();

			if ( IsArithmetic($1->GetType()->Tag()) ) {
				// Script optimization assumes that each AST
				// node is distinct, hence the call to
				// Duplicate() here.
				ExprPtr sum = make_intrusive<AddExpr>(lhs->Duplicate(), rhs);

				if ( sum->GetType()->Tag() != tag1 )
					sum = make_intrusive<ArithCoerceExpr>(sum, tag1);

				$$ = new AssignExpr(lhs, sum, false);
			}
			else
				$$ = new AddToExpr(lhs, rhs);
			}

	|	expr '-' expr
			{
			set_location(@1, @3);
			$$ = new SubExpr({AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_REMOVE_FROM rhs
			{
			set_location(@1, @3);

			ExprPtr lhs = {AdoptRef{}, $1};
			ExprPtr rhs = {AdoptRef{}, $3};
			auto tag1 = $1->GetType()->Tag();

			if ( IsArithmetic(tag1) ) {
				ExprPtr sum = make_intrusive<SubExpr>(lhs, rhs);

				if ( sum->GetType()->Tag() != tag1 )
					sum = make_intrusive<ArithCoerceExpr>(sum, tag1);

				$$ = new AssignExpr(lhs, sum, false);
			}
			else
				$$ = new RemoveFromExpr(lhs, rhs);
			}

	|	expr '*' expr
			{
			set_location(@1, @3);
			$$ = new TimesExpr({AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr '/' expr
			{
			set_location(@1, @3);
			if ( $1->GetType()->Tag() == TYPE_ADDR )
				$$ = new MaskExpr({AdoptRef{}, $1}, {AdoptRef{}, $3});
			else
				$$ = new DivideExpr({AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr '%' expr
			{
			set_location(@1, @3);
			$$ = new ModExpr({AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr '&' expr
			{
			set_location(@1, @3);
			$$ = new BitExpr(EXPR_AND, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr '|' expr
			{
			set_location(@1, @3);
			$$ = new BitExpr(EXPR_OR, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr '^' expr
			{
			set_location(@1, @3);
			$$ = new BitExpr(EXPR_XOR, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_LSHIFT expr
			{
			set_location(@1, @3);
			$$ = new BitExpr(EXPR_LSHIFT, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_RSHIFT expr
			{
			set_location(@1, @3);
			$$ = new BitExpr(EXPR_RSHIFT, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_AND_AND expr
			{
			set_location(@1, @3);
			$$ = new BoolExpr(EXPR_AND_AND, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_OR_OR expr
			{
			set_location(@1, @3);
			$$ = new BoolExpr(EXPR_OR_OR, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_EQ expr
			{
			set_location(@1, @3);
			$$ = new EqExpr(EXPR_EQ, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_NE expr
			{
			set_location(@1, @3);
			$$ = new EqExpr(EXPR_NE, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr '<' expr
			{
			set_location(@1, @3);
			$$ = new RelExpr(EXPR_LT, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_LE expr
			{
			set_location(@1, @3);
			$$ = new RelExpr(EXPR_LE, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr '>' expr
			{
			set_location(@1, @3);
			$$ = new RelExpr(EXPR_GT, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_GE expr
			{
			set_location(@1, @3);
			$$ = new RelExpr(EXPR_GE, {AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr '?' expr ':' expr
			{
			set_location(@1, @5);
			$$ = new CondExpr({AdoptRef{}, $1}, {AdoptRef{}, $3}, {AdoptRef{}, $5});
			}

	|	expr '='
			{
			// Prevent usage of trailing commas on the left-hand
			// side of list expressions (e.g. in table inits).
			if ( $1->Tag() == EXPR_LIST && expr_list_has_opt_comma )
				$1->Error("incorrect syntax for list expression "
				          "on left-hand side of assignment: "
				          "trailing comma not allowed");
			}
		rhs
			{
			set_location(@1, @3);

			if ( $1->Tag() == EXPR_INDEX && $1->AsIndexExpr()->IsSlice() )
				reporter->Error("index slice assignment may not be used"
				                      " in arbitrary expression contexts, only"
				                      " as a statement");

			$$ = get_assign_expr({AdoptRef{}, $1}, {AdoptRef{}, $4}, in_init).release();
			}

	|	TOK_WHEN_LOCAL local_id '=' rhs
			{
			set_location(@2, @4);
			if ( ! locals_at_this_scope.empty() )
				locals_at_this_scope.back().insert($2);
			$$ = add_and_assign_local({AdoptRef{}, $2}, {AdoptRef{}, $4},
			                                        val_mgr->True()).release();
			}

	|	expr '[' expr_list ']'
			{
			set_location(@1, @4);
			if ( in_when_cond > 0 )
				$$ = new IndexExprWhen({AdoptRef{}, $1}, {AdoptRef{}, $3});
			else
				$$ = new IndexExpr({AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	index_slice

	|	expr '$' TOK_ID
			{
			set_location(@1, @3);
			$$ = new FieldExpr({AdoptRef{}, $1}, $3);
			}

	|	'$' TOK_ID '=' expr
			{
			set_location(@1, @4);
			$$ = new FieldAssignExpr($2, {AdoptRef{}, $4});
			}

	|	'$' TOK_ID begin_lambda '='
			{
			func_hdr_location = @1;
			$3->SetInferReturnType(true);
			}
		lambda_body
			{
			$$ = new FieldAssignExpr($2, IntrusivePtr{AdoptRef{}, $6});
			}

	|	expr TOK_IN expr
			{
			set_location(@1, @3);
			$$ = new InExpr({AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_NOT_IN expr
			{
			set_location(@1, @3);
			$$ = new NotExpr(make_intrusive<InExpr>(
			        ExprPtr{AdoptRef{}, $1},
			        ExprPtr{AdoptRef{}, $3}));
			}

	|	'[' opt_expr_list ']'
			{
			set_location(@1, @3);

			bool is_record_ctor = true;

			// If every expression in the list is a field assignment,
			// then treat it as a record constructor, else as a list
			// used for an initializer. Interpret no expressions
			// as an empty record constructor.

			for ( int i = 0; i < $2->Exprs().length(); ++i ) {
				if ( $2->Exprs()[i]->Tag() != EXPR_FIELD_ASSIGN ) {
					is_record_ctor = false;
					break;
				}
			}

			if ( is_record_ctor )
				$$ = new RecordConstructorExpr({AdoptRef{}, $2});
			else
				$$ = $2;
			}

	|	TOK_RECORD '(' expr_list ')'
			{
			set_location(@1, @4);
			$$ = new RecordConstructorExpr({AdoptRef{}, $3});
			}

	|	TOK_TABLE '(' { ++in_init; } opt_expr_list ')' { --in_init; }
		opt_attr
			{ // the ++in_init fixes up the parsing of "[x] = y"
			set_location(@1, @5);
			std::unique_ptr<std::vector<AttrPtr>> attrs{$7};
			$$ = new TableConstructorExpr({AdoptRef{}, $4}, std::move(attrs));
			}

	|	TOK_SET '(' opt_expr_list ')' opt_attr
			{
			set_location(@1, @4);
			std::unique_ptr<std::vector<AttrPtr>> attrs{$5};
			$$ = new SetConstructorExpr({AdoptRef{}, $3}, std::move(attrs));
			}

	|	TOK_VECTOR '(' opt_expr_list ')'
			{
			set_location(@1, @4);
			$$ = new VectorConstructorExpr({AdoptRef{}, $3});
			}

	|	expr '('
			{
			if ( expr_is_table_type_name($1) )
				++in_init;
			}

		opt_expr_list
			{
			if ( expr_is_table_type_name($1) )
				--in_init;
			}

		')'
			{
			set_location(@1, @6);

			if ( $1->Tag() == EXPR_NAME && $1->AsNameExpr()->Id()->IsType() )
				{
				const auto& ctor_type = $1->AsNameExpr()->Id()->GetType();

				switch ( ctor_type->Tag() ) {
				case TYPE_RECORD: {
					auto rt = cast_intrusive<RecordType>(ctor_type);
					$$ = new RecordConstructorExpr(rt, ListExprPtr{AdoptRef{}, $4});
					break;
				}

				case TYPE_TABLE:
					if ( ctor_type->IsTable() )
						$$ = new TableConstructorExpr({AdoptRef{}, $4}, 0, ctor_type);
					else
						$$ = new SetConstructorExpr({AdoptRef{}, $4}, 0, ctor_type);

					break;

				case TYPE_VECTOR:
					$$ = new VectorConstructorExpr({AdoptRef{}, $4}, ctor_type);
					break;

				default:
					$1->Error("constructor type not implemented");
					YYERROR;
				}
			}

			else
				$$ = new CallExpr({AdoptRef{}, $1}, {AdoptRef{}, $4}, in_hook > 0, in_when_cond);
			}

	|	TOK_HOOK { ++in_hook; } expr
			{
			--in_hook;
			set_location(@1, @3);

			if ( $3->Tag() != EXPR_CALL )
				$3->Error("not a valid hook call expression");
			else if ( $3->AsCallExpr()->Func()->GetType()->AsFuncType()->Flavor() != FUNC_FLAVOR_HOOK )
				$3->Error("hook keyword should only be used to call hooks");

			$$ = $3;
			}

	|	expr TOK_HAS_FIELD TOK_ID
			{
			set_location(@1, @3);
			$$ = new HasFieldExpr({AdoptRef{}, $1}, $3);
			}

	|	anonymous_function

	|	TOK_SCHEDULE expr '{' event '}'
			{
			set_location(@1, @5);
			$$ = new ScheduleExpr({AdoptRef{}, $2}, {AdoptRef{}, $4});
			}

	|	lookup_identifier
			{
			set_location(@1);
			auto id = lookup_ID($1, current_module.c_str());

			if ( ! id ) {
				if ( ! in_debug ) {
/*	// CHECK THAT THIS IS NOT GLOBAL.
					id = install_ID($1, current_module.c_str(),
							        false, is_export);
*/

					yyerror(util::fmt("unknown identifier %s", $1));
					YYERROR;
				}
				else {
					yyerror(util::fmt("unknown identifier %s", $1));
					YYERROR;
				}
			}
			else {
				if ( id->IsDeprecated() )
					reporter->Deprecation(id->GetDeprecationWarning());

				if ( id->IsBlank() ) {
					$$ = new NameExpr(std::move(id));
					$$->SetError("blank identifier used in expression");
				}
				else if ( ! id->GetType() ) {
					id->Error("undeclared variable");
					id->SetType(error_type());
					$$ = new NameExpr(std::move(id));
				}
				else if ( id->IsEnumConst() ) {
					if ( IsErrorType(id->GetType()->Tag()) ) {
						// The most-relevant error message should already be reported, so
						// just bail out.
						YYERROR;
					}

					EnumType* t = id->GetType()->AsEnumType();
					auto intval = t->Lookup(id->ModuleName(), id->Name());
					if ( intval < 0 )
						reporter->InternalError("enum value not found for %s", id->Name());
					$$ = new ConstExpr(t->GetEnumVal(intval));
				}
				else {
					if ( out_of_scope_locals.count(id.get()) > 0 )
						id->Error("use of out-of-scope local; move declaration to outer scope");

					$$ = new NameExpr(std::move(id));
				}
			}
			}

	|	TOK_CONSTANT
			{
			set_location(@1);
			$$ = new ConstExpr({AdoptRef{}, $1});
			}

	|	simple_type
			{
			set_location(@1);
			TypePtr ty{AdoptRef(), $1};
			$$ = new ConstExpr(make_intrusive<TypeVal>(ty, true));
			}

	|	'/' { begin_RE(); } TOK_PATTERN_TEXT TOK_PATTERN_END
			{
			set_location(@3);

			auto* re = new RE_Matcher($3);
			delete [] $3;

			if ( $4.ignore_case )
				re->MakeCaseInsensitive();

			if ( $4.single_line )
				re->MakeSingleLine();

			re->Compile();
			$$ = new ConstExpr(make_intrusive<PatternVal>(re));
			}

	|	'|' expr '|'	%prec '('
			{
			set_location(@1, @3);
			ExprPtr e{AdoptRef{}, $2};
			$$ = new SizeExpr(std::move(e));
			}

	|	expr TOK_AS type
			{
			set_location(@1, @3);
			$$ = new CastExpr({AdoptRef{}, $1}, {AdoptRef{}, $3});
			}

	|	expr TOK_IS type
			{
			set_location(@1, @3);
			$$ = new IsExpr({AdoptRef{}, $1}, {AdoptRef{}, $3});
			}
	;

rhs:		'{' { ++in_init; } rhs_expr_list '}'
			{
			--in_init;
			$$ = $3;
			}
	|	expr
	;

rhs_expr_list: expr_list expr_list_opt_comma
	|
		{ $$ = new ListExpr(); }
	;

expr_list:
		expr_list ',' expr
			{
			set_location(@1, @3);
			$1->Append({AdoptRef{}, $3});
			}

	|	expr
			{
			set_location(@1);
			expr_list_has_opt_comma = 0;
			$$ = new ListExpr({AdoptRef{}, $1});
			}
	;

opt_expr_list:
		expr_list expr_list_opt_comma
	|
		{ $$ = new ListExpr(); }
	;

enum_body:
		enum_body_list
			{
			$$ = cur_enum_type;
			cur_enum_type = nullptr;
			}

	|	enum_body_list ','
			{
			$$ = cur_enum_type;
			cur_enum_type = nullptr;
			}
	;

enum_body_list:
		enum_body_elem

	|	enum_body_list ',' enum_body_elem
	;

enum_body_elem:
		/* TODO: We could also define this as TOK_ID '=' expr, (or
		   TOK_ID '=' = TOK_ID) so that we can return more descriptive
		   error messages if somebody tries to use constant variables as
		   enumerator.
		*/
		TOK_ID '=' TOK_CONSTANT opt_deprecated
			{
			set_location(@1, @3);
			assert(cur_enum_type);

			if ( $3->GetType()->Tag() != TYPE_COUNT )
				reporter->Error("enumerator is not a count constant");
			else
				cur_enum_type->AddName(current_module, $1,
				                       $3->InternalUnsigned(), is_export, $4,
				                       in_enum_redef != 0);
			}

	|	TOK_ID '=' '-' TOK_CONSTANT
			{
			// We only accept counts as enumerator, but we want to return a nice
			// error message if users try to use a negative integer (will also
			// catch other cases, but that's fine.)
			reporter->Error("enumerator is not a count constant");
			}

	|	TOK_ID opt_deprecated
			{
			set_location(@1);
			assert(cur_enum_type);
			cur_enum_type->AddName(current_module, $1, is_export, $2,
			                       in_enum_redef != 0);
			}
	;

simple_type:
		TOK_BOOL
			{
			set_location(@1);
			$$ = base_type(TYPE_BOOL)->Ref();
			}

	|	TOK_INT
			{
			set_location(@1);
			$$ = base_type(TYPE_INT)->Ref();
			}

	|	TOK_COUNT
			{
			set_location(@1);
			$$ = base_type(TYPE_COUNT)->Ref();
			}

	|	TOK_DOUBLE
			{
			set_location(@1);
			$$ = base_type(TYPE_DOUBLE)->Ref();
			}

	|	TOK_TIME
			{
			set_location(@1);
			$$ = base_type(TYPE_TIME)->Ref();
			}

	|	TOK_INTERVAL
			{
			set_location(@1);
			$$ = base_type(TYPE_INTERVAL)->Ref();
			}

	|	TOK_STRING
			{
			set_location(@1);
			$$ = base_type(TYPE_STRING)->Ref();
			}

	|	TOK_PATTERN
			{
			set_location(@1);
			$$ = base_type(TYPE_PATTERN)->Ref();
			}

	|	TOK_PORT
			{
			set_location(@1);
			$$ = base_type(TYPE_PORT)->Ref();
			}

	|	TOK_ADDR
			{
			set_location(@1);
			$$ = base_type(TYPE_ADDR)->Ref();
			}

	|	TOK_SUBNET
			{
			set_location(@1);
			$$ = base_type(TYPE_SUBNET)->Ref();
			}

	|	TOK_ANY
			{
			set_location(@1);
			$$ = base_type(TYPE_ANY)->Ref();
			}

	|	TOK_TABLE '[' type_list ']' TOK_OF type
			{
			set_location(@1, @6);
			$$ = new TableType({AdoptRef{}, $3}, {AdoptRef{}, $6});
			}

	|	TOK_SET '[' type_list ']'
			{
			set_location(@1, @4);
			$$ = new SetType({AdoptRef{}, $3}, nullptr);
			}

	|	TOK_RECORD '{'
			{ ++in_record; }
		type_decl_list
			{ --in_record; }
		'}'
			{
			set_location(@1, @5);
			$$ = new RecordType($4);
			}

	|	TOK_ENUM '{' { set_location(@1); parse_new_enum(); } enum_body '}'
			{
			set_location(@1, @5);
			$4->UpdateLocationEndInfo(@5);
			$$ = $4;
			}

	|	TOK_LIST
			{
			set_location(@1);
			// $$ = new TypeList();
			reporter->Error("list type not implemented");
			$$ = 0;
			}

	|	TOK_LIST TOK_OF type
			{
			set_location(@1);
			// $$ = new TypeList($3);
			reporter->Error("list type not implemented");
			$$ = 0;
			}

	|	TOK_VECTOR TOK_OF type
			{
			set_location(@1, @3);
			$$ = new VectorType({AdoptRef{}, $3});
			}

	|	TOK_FILE TOK_OF type
			{
			set_location(@1, @3);
			$$ = new FileType({AdoptRef{}, $3});
			}

	|	TOK_FILE
			{
			set_location(@1);
			$$ = new FileType(base_type(TYPE_STRING));
			}

	|	TOK_OPAQUE TOK_OF TOK_ID
			{
			set_location(@1, @3);
			$$ = new OpaqueType($3);
			}

type:
		simple_type
	|	TOK_FUNCTION func_params
			{
			set_location(@1, @2);
			$$ = $2;
			}

	|	TOK_HOOK '(' formal_args ')'
			{
			set_location(@1, @3);
			$$ = new FuncType({AdoptRef{}, $3}, base_type(TYPE_BOOL), FUNC_FLAVOR_HOOK);
			}

	|	TOK_EVENT '(' formal_args ')'
			{
			set_location(@1, @3);
			$$ = new FuncType({AdoptRef{}, $3}, nullptr, FUNC_FLAVOR_EVENT);
			}

	|	resolve_id
			{
			if ( ! $1 || ! ($$ = $1->IsType() ? $1->GetType().get() : nullptr) ) {
				NullStmt here;
				if ( $1 )
					$1->Error("not a Zeek type", &here);
				$$ = error_type()->Ref();
			}
			else {
				Ref($$);

				if ( $1->IsDeprecated() )
					reporter->Deprecation($1->GetDeprecationWarning());
			}
			}
	;

type_list:
		type_list ',' type
			{ $1->AppendEvenIfNotPure({AdoptRef{}, $3}); }
	|	type
			{
			$$ = new TypeList({NewRef{}, $1});
			$$->Append({AdoptRef{}, $1});
			}
	;

type_decl_list:
		type_decl_list conditional_list type_decl
			{
			$1->push_back($3);
			}
	|
			{
			$$ = new type_decl_list();
			}
	;

type_decl:
		TOK_ID ':' type opt_attr ';'
			{
			set_location(@1, @4);
			auto attrs = make_attributes($4, {NewRef{}, $3}, in_record > 0, false);
			$$ = new TypeDecl($1, {AdoptRef{}, $3}, std::move(attrs));

			if ( in_record > 0 && cur_decl_type_id )
				zeekygen_mgr->RecordField(cur_decl_type_id, $$, ::filename,
				                          in_record_redef != 0);
			}
	;

formal_args:
		formal_args_decl_list
			{ $$ = new RecordType($1); }
	|	formal_args_decl_list ';'
			{ $$ = new RecordType($1); }
	|
			{ $$ = new RecordType(new type_decl_list()); }
	;

formal_args_decl_list:
		formal_args_decl_list ';' formal_args_decl
			{ $1->push_back($3); }
	|	formal_args_decl_list ',' formal_args_decl
			{ $1->push_back($3); }
	|	formal_args_decl
			{ $$ = new type_decl_list(); $$->push_back($1); }
	;

formal_args_decl:
		TOK_ID ':' type opt_attr
			{
			set_location(@1, @4);
			auto attrs = make_attributes($4, {NewRef{}, $3}, true, false);
			$$ = new TypeDecl($1, {AdoptRef{}, $3}, std::move(attrs));
			}
	;

decl:
		TOK_MODULE TOK_ID ';'
			{
			current_module = $2;
			zeek::detail::add_module($2);
			zeekygen_mgr->ModuleUsage(::filename, current_module);
			}

	|	TOK_EXPORT '{' { is_export = true; } decl_list '}'
			{ is_export = false; }

	|	TOK_GLOBAL def_global_id opt_type init_class opt_init opt_attr ';'
			{
			build_global($2, $3, $4, $5, $6, VAR_REGULAR);
			}

	|	TOK_OPTION def_global_id opt_type init_class opt_init opt_attr ';'
			{
			if ( $2->IsBlank() )
				$2->Error("blank identifier used as option");
			else
				build_global($2, $3, $4, $5, $6, VAR_OPTION);
			}

	|	TOK_CONST def_global_id opt_type init_class opt_init opt_attr ';'
			{
			build_global($2, $3, $4, $5, $6, VAR_CONST);
			}

	|	TOK_REDEF global_id {
			if ( $2->IsType() ) {
				auto tag = $2->GetType()->Tag();
				auto tstr = type_name(tag);
				if ( tag == TYPE_RECORD || tag == TYPE_ENUM )
					yyerror(zeek::util::fmt("redef of %s type %s is missing %s keyword",
								tstr, $2->Name(), tstr));
				else
					yyerror(zeek::util::fmt("can not redef %s type %s", tstr, $2->Name()));

				YYERROR;  // bail
				}
		} opt_type init_class opt_init opt_attr ';'
			{
			build_global($2, $4, $5, $6, $7, VAR_REDEF);
			}

	|	TOK_REDEF TOK_ENUM global_id TOK_ADD_TO '{'
			{ ++in_enum_redef; parse_redef_enum($3); zeekygen_mgr->Redef($3, ::filename); }
		enum_body '}' ';'
			{
			--in_enum_redef;
			// Zeekygen already grabbed new enum IDs as the type created them.
			}

	|	TOK_REDEF TOK_RECORD  global_id '$' TOK_ID
			{ cur_decl_type_id = $3; zeekygen_mgr->Redef($3, ::filename, INIT_EXTRA); }
		TOK_ADD_TO '{' attr_list '}' ';'
			{
			cur_decl_type_id = 0;
			parse_redef_record_field($3, $5, INIT_EXTRA, std::unique_ptr<std::vector<AttrPtr>>($9));
			}
	|	TOK_REDEF TOK_RECORD  global_id '$' TOK_ID
			{ cur_decl_type_id = $3; zeekygen_mgr->Redef($3, ::filename, INIT_REMOVE); }
		TOK_REMOVE_FROM '{' attr_list '}' ';'
			{
			cur_decl_type_id = 0;
			parse_redef_record_field($3, $5, INIT_REMOVE, std::unique_ptr<std::vector<AttrPtr>>($9));
			}
	|	TOK_REDEF TOK_RECORD global_id
			{ cur_decl_type_id = $3; zeekygen_mgr->Redef($3, ::filename); }
		TOK_ADD_TO '{'
			{ ++in_record; ++in_record_redef; }
		type_decl_list
			{ --in_record; --in_record_redef; }
		'}' opt_attr ';'
			{
			cur_decl_type_id = 0;

			if ( ! $3->GetType() )
				$3->Error("unknown identifier");
			else
				extend_record($3, std::unique_ptr<type_decl_list>($8),
				              std::unique_ptr<std::vector<AttrPtr>>($11));
			}

	|	TOK_TYPE def_global_id ':'
			{ cur_decl_type_id = $2; zeekygen_mgr->StartType({NewRef{}, $2});  }
		type opt_attr ';'
			{
			cur_decl_type_id = 0;
			IntrusivePtr id{AdoptRef{}, $2};
			add_type(id.get(), {AdoptRef{}, $5},
			         std::unique_ptr<std::vector<AttrPtr>>{$6});
			zeekygen_mgr->Identifier(std::move(id));
			}

	|	func_hdr
			{
			func_hdr_location = @1;
			func_hdr_cond_epoch = conditional_epoch;
			}
		conditional_list func_body

	|	conditional
	;

conditional_list:
	|	conditional_list conditional
	;

conditional:
		TOK_ATIF '(' expr ')'
			{ do_atif($3); }
	|	TOK_ATIFDEF '(' TOK_ID ')'
			{ do_atifdef($3); }
	|	TOK_ATIFNDEF '(' TOK_ID ')'
			{ do_atifndef($3); }
	|	TOK_ATENDIF
			{ do_atendif(); }
	|	TOK_ATELSE
			{ do_atelse(); }
	;

func_hdr:
		TOK_FUNCTION def_global_id func_params opt_attr
			{
			IntrusivePtr id{AdoptRef{}, $2};
			begin_func(id, current_module.c_str(),
				       FUNC_FLAVOR_FUNCTION, false, {NewRef{}, $3},
			           std::unique_ptr<std::vector<AttrPtr>>{$4});
			$$ = $3;
			zeekygen_mgr->Identifier(std::move(id));
			}
	|	TOK_EVENT event_id func_params opt_attr
			{
			begin_func({NewRef{}, $2}, current_module.c_str(),
				       FUNC_FLAVOR_EVENT, false, {NewRef{}, $3},
			           std::unique_ptr<std::vector<AttrPtr>>{$4});
			$$ = $3;
			}
	|	TOK_HOOK def_global_id func_params opt_attr
			{
			$3->ClearYieldType(FUNC_FLAVOR_HOOK);
			$3->SetYieldType(base_type(TYPE_BOOL));
			begin_func({NewRef{}, $2}, current_module.c_str(),
				       FUNC_FLAVOR_HOOK, false, {NewRef{}, $3},
			           std::unique_ptr<std::vector<AttrPtr>>{$4});
			$$ = $3;
			}
	|	TOK_REDEF TOK_EVENT event_id func_params opt_attr
			{
			begin_func({NewRef{}, $3}, current_module.c_str(),
				       FUNC_FLAVOR_EVENT, true, {NewRef{}, $4},
			           std::unique_ptr<std::vector<AttrPtr>>{$5});
			$$ = $4;
			}
	;

func_body:
		'{'
			{
			saved_in_init.push_back(in_init);
			in_init = 0;

			locals_at_this_scope.clear();
			out_of_scope_locals.clear();
			}

		stmt_list
			{
			in_init = saved_in_init.back();
			saved_in_init.pop_back();
			}

		'}'
			{
			set_location(func_hdr_location, @5);

			bool free_of_conditionals = true;
			if ( current_file_has_conditionals || conditional_epoch > func_hdr_cond_epoch )
				free_of_conditionals = false;

			end_func({AdoptRef{}, $3}, current_module.c_str(), free_of_conditionals);
			}
	;

lambda_body:
		'{'
			{
			saved_in_init.push_back(in_init);
			in_init = 0;
			}

		stmt_list
			{
			in_init = saved_in_init.back();
			saved_in_init.pop_back();
			}

		'}'
			{
			set_location(@1, @5);

			// Code duplication here is sad but needed.
			// end_func actually instantiates the function
			// and associates it with an ID. We perform that
			// association later and need to return a lambda
			// expression.

			// Gather the ingredients for a Func from the
			// current scope.
			auto ingredients = std::make_shared<FunctionIngredients>(
				current_scope(), IntrusivePtr{AdoptRef{}, $3}, current_module.c_str());
			auto outer_ids = gather_outer_ids(pop_scope(), ingredients->Body());

			$$ = new LambdaExpr(std::move(ingredients), std::move(outer_ids));
			}
	;

anonymous_function:
		TOK_FUNCTION
			{
			// "is_export" is used in some contexts to determine
			// whether a given newly seen identifier is a global.
			// We're about parse a lambda body, for which all of
			// the new identifiers should be locals, not globals,
			// so we need to turn off "is_export" here.  We use
			// a stack because lambdas can have additional lambdas
			// inside their bodies.
			hold_is_export.push_back(is_export);
			is_export = false;
			}
		begin_lambda conditional_list lambda_body
			{
			is_export = hold_is_export.back();
			hold_is_export.pop_back();
			$$ = $5;
			}
	;

begin_lambda:
		opt_captures func_params
			{
			auto id = current_scope()->GenerateTemporary("anonymous-function");
			begin_func(id, current_module.c_str(), FUNC_FLAVOR_FUNCTION, false, {AdoptRef{}, $2});

			std::optional<FuncType::CaptureList> captures;

			if ( $1 ) {
				captures = *$1;
				delete $1;
			}

			$2->SetCaptures(std::move(captures));
			$$ = id.release();
			}
	;

opt_captures:
		'[' capture_list ']'
			{ $$ = $2; }
	|
			{ $$ = nullptr; }
	;

capture_list:
		capture_list ',' capture
			{
			$1->push_back(*$3);
			delete $3;
			}
	|	capture
			{
			$$ = new zeek::FuncType::CaptureList;
			$$->push_back(*$1);
			delete $1;
			}
	;

capture:
		opt_deep TOK_ID
			{
			set_location(@2);
			auto id = lookup_ID($2, current_module.c_str());

			if ( ! id )
				reporter->Error("no such local identifier: %s", $2);
			else if ( id->IsType() ) {
				reporter->Error("cannot specify type in capture: %s", $2);
				id = nullptr;
			}
			else if ( id->IsGlobal() ) {
				reporter->Error("cannot specify global in capture: %s", $2);
				id = nullptr;
			}

			delete [] $2;

			$$ = new FuncType::Capture(id, $1);
			}
	;

opt_deep:	TOK_COPY
			{ $$ = true; }
	|
			{ $$ = false; }
	;

func_params:
		'(' formal_args ')' ':' type
			{ $$ = new FuncType({AdoptRef{}, $2}, {AdoptRef{}, $5}, FUNC_FLAVOR_FUNCTION); }
	|	'(' formal_args ')'
			{ $$ = new FuncType({AdoptRef{}, $2}, base_type(TYPE_VOID), FUNC_FLAVOR_FUNCTION); }
	;

opt_type:
		':' type
			{ $$ = $2; }
	|
			{ $$ = 0; }
	;

init_class:
				{ $$ = INIT_NONE; }
	|	'='		{ $$ = INIT_FULL; }
	|	TOK_ADD_TO	{ $$ = INIT_EXTRA; }
	|	TOK_REMOVE_FROM	{ $$ = INIT_REMOVE; }
	;

opt_init:
		{ ++in_init; } rhs { --in_init; }
			{ $$ = $2; }
	|
			{ $$ = 0; }
	;

index_slice:
		expr '[' opt_expr ':' opt_expr ']'
			{
			set_location(@1, @6);

			auto low = $3 ? ExprPtr{AdoptRef{}, $3} :
			                make_intrusive<ConstExpr>(val_mgr->Count(0));

			auto high = $5 ? ExprPtr{AdoptRef{}, $5} :
			                 make_intrusive<SizeExpr>(
			                     ExprPtr{NewRef{}, $1});

			if ( ! IsIntegral(low->GetType()->Tag()) || ! IsIntegral(high->GetType()->Tag()) )
				reporter->Error("slice notation must have integral values as indexes");

			auto le = make_intrusive<ListExpr>(std::move(low));
			le->Append(std::move(high));

			if ( in_when_cond > 0  )
				$$ = new IndexExprWhen({AdoptRef{}, $1}, std::move(le), true);
			else
				$$ = new IndexExpr({AdoptRef{}, $1}, std::move(le), true);
			}

opt_attr:
		attr_list
	|
			{ $$ = nullptr; }
	;

attr_list:
		attr_list attr
			{ $1->emplace_back(AdoptRef{}, $2); }
	|	attr
			{
			$$ = new std::vector<AttrPtr>;
			$$->emplace_back(AdoptRef{}, $1);
			}
	;

attr:
		TOK_ATTR_DEFAULT '=' expr
			{ $$ = new Attr(ATTR_DEFAULT, {AdoptRef{}, $3}); }
	|	TOK_ATTR_DEFAULT_INSERT '=' expr
			{ $$ = new Attr(ATTR_DEFAULT_INSERT, {AdoptRef{}, $3}); }
	|	TOK_ATTR_OPTIONAL
			{ $$ = new Attr(ATTR_OPTIONAL); }
	|	TOK_ATTR_REDEF
			{ $$ = new Attr(ATTR_REDEF); }
	|	TOK_ATTR_IS_ASSIGNED
			{ $$ = new Attr(ATTR_IS_ASSIGNED); }
	|	TOK_ATTR_IS_USED
			{ $$ = new Attr(ATTR_IS_USED); }
	|	TOK_ATTR_ADD_FUNC '=' expr
			{ $$ = new Attr(ATTR_ADD_FUNC, {AdoptRef{}, $3}); }
	|	TOK_ATTR_DEL_FUNC '=' expr
			{ $$ = new Attr(ATTR_DEL_FUNC, {AdoptRef{}, $3}); }
	|	TOK_ATTR_ON_CHANGE '=' expr
			{ $$ = new Attr(ATTR_ON_CHANGE, {AdoptRef{}, $3}); }
	|	TOK_ATTR_BROKER_STORE '=' expr
			{ $$ = new Attr(ATTR_BROKER_STORE, {AdoptRef{}, $3}); }
	|	TOK_ATTR_BROKER_STORE_ALLOW_COMPLEX
			{ $$ = new Attr(ATTR_BROKER_STORE_ALLOW_COMPLEX); }
	|	TOK_ATTR_BACKEND '=' expr
			{ $$ = new Attr(ATTR_BACKEND, {AdoptRef{}, $3}); }
	|	TOK_ATTR_EXPIRE_FUNC '=' expr
			{ $$ = new Attr(ATTR_EXPIRE_FUNC, {AdoptRef{}, $3}); }
	|	TOK_ATTR_EXPIRE_CREATE '=' expr
			{ $$ = new Attr(ATTR_EXPIRE_CREATE, {AdoptRef{}, $3}); }
	|	TOK_ATTR_EXPIRE_READ '=' expr
			{ $$ = new Attr(ATTR_EXPIRE_READ, {AdoptRef{}, $3}); }
	|	TOK_ATTR_EXPIRE_WRITE '=' expr
			{ $$ = new Attr(ATTR_EXPIRE_WRITE, {AdoptRef{}, $3}); }
	|	TOK_ATTR_RAW_OUTPUT
			{ $$ = new Attr(ATTR_RAW_OUTPUT); }
	|	TOK_ATTR_PRIORITY '=' expr
			{ $$ = new Attr(ATTR_PRIORITY, {AdoptRef{}, $3}); }
	|	TOK_ATTR_GROUP '=' expr
			{ $$ = new Attr(ATTR_GROUP, {AdoptRef{}, $3}); }
	|	TOK_ATTR_TYPE_COLUMN '=' expr
			{ $$ = new Attr(ATTR_TYPE_COLUMN, {AdoptRef{}, $3}); }
	|	TOK_ATTR_LOG
			{ $$ = new Attr(ATTR_LOG); }
	|	TOK_ATTR_ERROR_HANDLER
			{ $$ = new Attr(ATTR_ERROR_HANDLER); }
	|	TOK_ATTR_DEPRECATED
			{ $$ = new Attr(ATTR_DEPRECATED); }
	|	TOK_ATTR_DEPRECATED '=' TOK_CONSTANT
			{
			if ( IsString($3->GetType()->Tag()) )
				$$ = new Attr(
					ATTR_DEPRECATED,
					make_intrusive<ConstExpr>(IntrusivePtr{AdoptRef{}, $3}));
			else {
				ODesc d;
				$3->Describe(&d);
				Unref($3);
				reporter->Error("'&deprecated=%s' must use a string literal",
				                d.Description());
				$$ = new Attr(ATTR_DEPRECATED);
				}
			}
	|	TOK_ATTR_ORDERED
			{ $$ = new Attr(ATTR_ORDERED); }
	;

stmt:
		'{'
			{
			std::set<const ID*> id_set;
			locals_at_this_scope.emplace_back(id_set);
			}
		opt_no_test_block stmt_list '}'
			{
			auto& scope_locals = locals_at_this_scope.back();
			out_of_scope_locals.insert(scope_locals.begin(), scope_locals.end());
			locals_at_this_scope.pop_back();

			set_location(@1, @5);
			$$ = $4;
			if ( $3 )
				script_coverage_mgr.DecIgnoreDepth();
			}

	|	TOK_ASSERT expr opt_assert_msg ';'
			{
			$$ = new AssertStmt(IntrusivePtr{AdoptRef{}, $2}, {AdoptRef{}, $3});
			}

	|	TOK_PRINT expr_list ';' opt_no_test
			{
			set_location(@1, @3);
			$$ = new PrintStmt(IntrusivePtr{AdoptRef{}, $2});
			if ( ! $4 )
				script_coverage_mgr.AddStmt($$);
			}

	|	TOK_EVENT event ';' opt_no_test
			{
			set_location(@1, @3);
			$$ = new EventStmt({AdoptRef{}, $2});
			if ( ! $4 )
				script_coverage_mgr.AddStmt($$);
			}

	|	TOK_IF '(' expr ')' stmt
			{
			reject_directive($5);
			set_location(@1, @4);
			$$ = new IfStmt({AdoptRef{}, $3}, {AdoptRef{}, $5}, make_intrusive<NullStmt>());
			script_coverage_mgr.AddStmt($$);
			}

	|	TOK_IF '(' expr ')' stmt TOK_ELSE stmt
			{
			reject_directive($5);
			reject_directive($7);
			set_location(@1, @4);
			$$ = new IfStmt({AdoptRef{}, $3}, {AdoptRef{}, $5}, {AdoptRef{}, $7});
			script_coverage_mgr.AddStmt($$);
			}

	|	TOK_SWITCH expr '{' case_list '}'
			{
			set_location(@1, @2);
			$$ = new SwitchStmt({AdoptRef{}, $2}, $4);
			script_coverage_mgr.AddStmt($$);
			}

	|	for_head stmt
			{
			reject_directive($2);
			$1->AsForStmt()->AddBody({AdoptRef{}, $2});
			script_coverage_mgr.AddStmt($1);
			}

	|	TOK_WHILE '(' expr ')' stmt
			{
			reject_directive($5);
			$$ = new WhileStmt({AdoptRef{}, $3}, {AdoptRef{}, $5});
			script_coverage_mgr.AddStmt($$);
			}

	|	TOK_NEXT ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new NextStmt;
			if ( ! $3 )
				script_coverage_mgr.AddStmt($$);
			}

	|	TOK_BREAK ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new BreakStmt;
			if ( ! $3 )
				script_coverage_mgr.AddStmt($$);
			}

	|	TOK_FALLTHROUGH ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new FallthroughStmt;
			if ( ! $3 )
				script_coverage_mgr.AddStmt($$);
			}

	|	TOK_RETURN ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new ReturnStmt(0);
			if ( ! $3 )
				script_coverage_mgr.AddStmt($$);
			}

	|	TOK_RETURN expr ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new ReturnStmt({AdoptRef{}, $2});
			if ( ! $4 )
				script_coverage_mgr.AddStmt($$);
			}

	|	TOK_LOCAL local_id opt_type init_class opt_init opt_attr ';' opt_no_test
			{
			set_location(@1, @7);
			if ( ! locals_at_this_scope.empty() )
				   locals_at_this_scope.back().insert($2);
			$$ = build_local($2, $3, $4, $5, $6, VAR_REGULAR, ! $8).release();
			}

	|	TOK_CONST local_id opt_type init_class opt_init opt_attr ';' opt_no_test
			{
			set_location(@1, @6);

			$$ = build_local($2, $3, $4, $5, $6, VAR_CONST, ! $8).release();
			}

	|	when_clause
			{
			std::shared_ptr<WhenInfo> wi($1);
			$$ = new WhenStmt(std::move(wi));
			script_coverage_mgr.AddStmt($$);
			}

	|	index_slice '=' expr ';' opt_no_test
			{
			set_location(@1, @4);
			$$ = new ExprStmt(get_assign_expr({AdoptRef{}, $1},
			                                  {AdoptRef{}, $3}, in_init));

			if ( ! $5 )
				script_coverage_mgr.AddStmt($$);
			}

	|	expr ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new ExprStmt({AdoptRef{}, $1});
			if ( ! $3 )
				script_coverage_mgr.AddStmt($$);
			}

	|	';'
			{
			set_location(@1, @1);
			$$ = new NullStmt;
			script_coverage_mgr.AddStmt($$);
			}

	|	conditional
			{ $$ = new NullStmt(true /* is_directive */); }
	;

stmt_list:
		stmt_list stmt
			{
			set_location(@1, @2);
			$1->AsStmtList()->Stmts().push_back({AdoptRef{}, $2});
			$1->UpdateLocationEndInfo(@2);
			}
	|
			{ $$ = new StmtList(); }
	;

event:
		lookup_identifier '(' opt_expr_list ')'
			{
			set_location(@1, @4);
			const auto& id = lookup_ID($1, current_module.c_str());

			if ( id ) {
				if ( ! id->IsGlobal() ) {
					yyerror(util::fmt("local identifier \"%s\" cannot be used to reference an event", $1));
					YYERROR;
				}

				if ( id->IsDeprecated() )
					reporter->Deprecation(id->GetDeprecationWarning());

				$$ = new EventExpr(id->Name(), {AdoptRef{}, $3});
			}
			else {
				$$ = new EventExpr($1, {AdoptRef{}, $3});
				}
			}
	;

case_list:
		case_list case
			{ $1->push_back($2); }
	|
			{ $$ = new case_list; }
	;

case:
		TOK_CASE expr_list ':' stmt_list
			{ $$ = new Case({AdoptRef{}, $2}, nullptr, {AdoptRef{}, $4}); }
	|
		TOK_CASE case_type_list ':' stmt_list
			{ $$ = new Case(nullptr, $2, {AdoptRef{}, $4}); }
	|
		TOK_DEFAULT ':' stmt_list
			{ $$ = new Case(nullptr, nullptr, {AdoptRef{}, $3}); }
	;

case_type_list:
		case_type_list ',' case_type
			{ $1->push_back($3); }
	|
		case_type
			{
			$$ = new IDPList;
			$$->push_back($1);
			}
	;

case_type:
		TOK_TYPE type
			{
			$$ = new ID(0, SCOPE_FUNCTION, false);
			$$->SetType({AdoptRef{}, $2});
			}

	|	TOK_TYPE type TOK_AS TOK_ID
			{
			const char* name = $4;
			TypePtr type{AdoptRef{}, $2};
			auto case_var = lookup_ID(name, current_module.c_str());

			if ( case_var && case_var->IsGlobal() )
				case_var->Error("already a global identifier");
			else
				case_var = install_ID(name, current_module.c_str(), false, false);

			add_local(case_var, std::move(type), INIT_NONE, nullptr, nullptr, VAR_REGULAR);
			$$ = case_var.release();
			}

for_head:
		TOK_FOR '(' TOK_ID TOK_IN expr ')'
			{
			set_location(@1, @6);

			// This rule needs to be separate from the loop
			// body so that we execute these actions - defining
			// the local variable - prior to parsing the body,
			// which might refer to the variable.
			auto loop_var = lookup_ID($3, current_module.c_str());

			if ( loop_var )
				check_loop_var(loop_var);
			else {
				loop_var = install_ID($3, current_module.c_str(), false, false);
			}

			auto* loop_vars = new IDPList;
			loop_vars->push_back(loop_var.release());

			$$ = new ForStmt(loop_vars, {AdoptRef{}, $5});
			}
	|
		TOK_FOR '(' '[' local_id_list ']' TOK_IN expr ')'
			{
			$$ = new ForStmt($4, {AdoptRef{}, $7});
			}
	|
		TOK_FOR '(' TOK_ID ',' TOK_ID TOK_IN expr ')'
			{
			set_location(@1, @8);
			const char* module = current_module.c_str();

			// Check for previous definitions of key and
			// value variables.
			auto key_var = lookup_ID($3, module);
			auto val_var = lookup_ID($5, module);

			// Validate previous definitions as needed.
			if ( key_var )
				check_loop_var(key_var);
			else
				key_var = install_ID($3, module, false, false);

			if ( val_var )
				check_loop_var(val_var);
			else
				val_var = install_ID($5, module, false, false);

			auto* loop_vars = new IDPList;
			loop_vars->push_back(key_var.release());

			$$ = new ForStmt(loop_vars, {AdoptRef{}, $7}, std::move(val_var));
			}
	|
		TOK_FOR '(' '[' local_id_list ']' ',' TOK_ID TOK_IN expr ')'
			{
			set_location(@1, @10);
			const char* module = current_module.c_str();

			// Validate value variable
			auto val_var = lookup_ID($7, module);

			if ( val_var )
				check_loop_var(val_var);
			else
				val_var = install_ID($7, module, false, false);

			$$ = new ForStmt($4, {AdoptRef{}, $9}, std::move(val_var));
			}
	;

local_id_list:
		local_id_list ',' local_id
			{ $1->push_back($3); }
	|	local_id
			{
			$$ = new IDPList;
			$$->push_back($1);
			}
	;

local_id:
		TOK_ID
			{
			set_location(@1);
			auto id = lookup_ID($1, current_module.c_str());
			$$ = id.release();

			if ( $$ ) {
				if ( $$->IsGlobal() && ! $$->IsBlank() )
					$$->Error("already a global identifier");

				if ( $$->IsConst() && ! $$->IsBlank() )
 					$$->Error("already a const identifier");

				delete [] $1;
			}
			else {
				$$ = install_ID($1, current_module.c_str(), false, false).release();
				}
			}
	;

global_id:
	{ resolving_global_ID = true; } global_or_event_id
		{ $$ = $2; }
	;

def_global_id:
	{ defining_global_ID = true; } global_id { defining_global_ID = false; }
		{ $$ = $2; }
	;

event_id:
	{ resolving_global_ID = false; } global_or_event_id
		{ $$ = $2; }
	;

global_or_event_id:
		lookup_identifier
			{
			set_location(@1);
			auto id = lookup_ID($1, current_module.c_str(), false,
			                    defining_global_ID);
			$$ = id.release();

			if ( $$ ) {
				if ( ! $$->IsGlobal() )
					$$->Error("already a local identifier");

				if ( $$->IsDeprecated() ) {
					const auto& t = $$->GetType();

					if ( t->Tag() != TYPE_FUNC ||
					     t->AsFuncType()->Flavor() != FUNC_FLAVOR_FUNCTION )
						reporter->Deprecation($$->GetDeprecationWarning());
				}

				refine_location($$);
				delete [] $1;
			}
			else {
				const char* module_name =
					resolving_global_ID ?
						current_module.c_str() : nullptr;

				$$ = install_ID($1, module_name, true, is_export).release();
				}
			}
	;


resolve_id:
		lookup_identifier
			{
			set_location(@1);
			auto id = lookup_ID($1, current_module.c_str());
			$$ = id.release();

			if ( ! $$ )
				reporter->Error("identifier not defined: %s", $1);

			delete [] $1;
			}
	;

lookup_identifier:
		TOK_ID
	|
		TOK_GLOBAL_ID
			{
			if ( is_export ) {
				reporter->Error("cannot use :: prefix in export section: %s", $1);
				YYERROR;
			}
			}

	;

opt_assert_msg:
		',' expr
			{ $$ = $2; }
	|
			{ $$ = nullptr; }
	;

opt_no_test:
		TOK_NO_TEST
			{ $$ = true; }
	|
			{ $$ = false; }
	;

opt_no_test_block:
		TOK_NO_TEST
			{ $$ = true; script_coverage_mgr.IncIgnoreDepth(); }
	|
			{ $$ = false; }
	;

opt_deprecated:
		TOK_ATTR_DEPRECATED
			{ $$ = new ConstExpr(make_intrusive<StringVal>("")); }
	|
		TOK_ATTR_DEPRECATED '=' TOK_CONSTANT
			{
			if ( IsString($3->GetType()->Tag()) )
				$$ = new ConstExpr({AdoptRef{}, $3});
			else {
				ODesc d;
				$3->Describe(&d);
				reporter->Error("'&deprecated=%s' must use a string literal",
				                d.Description());
				$$ = new ConstExpr(make_intrusive<StringVal>(""));
				}
			}
	|
			{ $$ = nullptr; }
	;

expr_list_opt_comma: ',' { expr_list_has_opt_comma = 1; }
	|
	;

%%

int yyerror(const char msg[]) {
    if ( in_debug )
        g_curr_debug_error = util::copy_string(msg);

    if ( last_tok[0] == '\n' )
        reporter->Error("%s, on previous line", msg);
    else if ( last_tok[0] == '\0' ) {
        if ( last_filename )
            reporter->Error("%s, at end of file %s", msg, last_filename);
        else
            reporter->Error("%s, at end of file", msg);
    }
    else {
        if ( last_last_tok_filename && last_tok_filename && ! util::streq(last_last_tok_filename, last_tok_filename) )
            reporter->Error("%s, at or near \"%s\" or end of file %s", msg, last_tok, last_last_tok_filename);
        else
            reporter->Error("%s, at or near \"%s\"", msg, last_tok);
    }

    return 0;
}

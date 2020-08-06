%{
// See the file "COPYING" in the main distribution directory for copyright.
%}

// Switching parser table type fixes ambiguity problems.
%define lr.type ielr

%expect 129

%token TOK_ADD TOK_ADD_TO TOK_ADDR TOK_ANY
%token TOK_ATENDIF TOK_ATELSE TOK_ATIF TOK_ATIFDEF TOK_ATIFNDEF
%token TOK_BOOL TOK_BREAK TOK_CASE TOK_OPTION TOK_CONST
%token TOK_CONSTANT TOK_COPY TOK_COUNT TOK_DEFAULT TOK_DELETE
%token TOK_DOUBLE TOK_ELSE TOK_ENUM TOK_EVENT TOK_EXPORT TOK_FALLTHROUGH
%token TOK_FILE TOK_FOR TOK_FUNCTION TOK_GLOBAL TOK_HOOK TOK_ID TOK_IF TOK_INT
%token TOK_INTERVAL TOK_LIST TOK_LOCAL TOK_MODULE
%token TOK_NEXT TOK_OF TOK_OPAQUE TOK_PATTERN TOK_PATTERN_END TOK_PATTERN_TEXT
%token TOK_PORT TOK_PRINT TOK_RECORD TOK_REDEF
%token TOK_REMOVE_FROM TOK_RETURN TOK_SCHEDULE TOK_SET
%token TOK_STRING TOK_SUBNET TOK_SWITCH TOK_TABLE
%token TOK_TIME TOK_TIMEOUT TOK_TIMER TOK_TYPE TOK_UNION TOK_VECTOR TOK_WHEN
%token TOK_WHILE TOK_AS TOK_IS

%token TOK_ATTR_ADD_FUNC TOK_ATTR_DEFAULT TOK_ATTR_OPTIONAL TOK_ATTR_REDEF
%token TOK_ATTR_DEL_FUNC TOK_ATTR_EXPIRE_FUNC
%token TOK_ATTR_EXPIRE_CREATE TOK_ATTR_EXPIRE_READ TOK_ATTR_EXPIRE_WRITE
%token TOK_ATTR_RAW_OUTPUT TOK_ATTR_ON_CHANGE TOK_ATTR_BROKER_STORE
%token TOK_ATTR_BROKER_STORE_ALLOW_COMPLEX TOK_ATTR_BACKEND
%token TOK_ATTR_PRIORITY TOK_ATTR_LOG TOK_ATTR_ERROR_HANDLER
%token TOK_ATTR_TYPE_COLUMN TOK_ATTR_DEPRECATED

%token TOK_DEBUG

%token TOK_NO_TEST

%left ','
%right '=' TOK_ADD_TO TOK_REMOVE_FROM
%right '?' ':'
%left TOK_OR_OR
%left TOK_AND_AND
%nonassoc TOK_HOOK
%nonassoc '<' '>' TOK_LE TOK_GE TOK_EQ TOK_NE
%left TOK_IN TOK_NOT_IN
%left '|'
%left '^'
%left '&'
%left '+' '-'
%left '*' '/' '%'
%left TOK_INCR TOK_DECR
%right '!' '~'
%left '$' '[' ']' '(' ')' TOK_HAS_FIELD TOK_HAS_ATTR
%nonassoc TOK_AS TOK_IS

%type <b> opt_no_test opt_no_test_block TOK_PATTERN_END
%type <str> TOK_ID TOK_PATTERN_TEXT
%type <id> local_id global_id def_global_id event_id global_or_event_id resolve_id begin_func case_type
%type <id_l> local_id_list case_type_list
%type <ic> init_class
%type <expr> opt_init
%type <val> TOK_CONSTANT
%type <expr> expr opt_expr init anonymous_function lambda_body index_slice opt_deprecated
%type <event_expr> event
%type <stmt> stmt stmt_list func_body for_head
%type <type> type opt_type enum_body
%type <func_type> func_hdr func_params
%type <type_l> type_list
%type <type_decl> type_decl formal_args_decl
%type <type_decl_l> type_decl_list formal_args_decl_list
%type <record> formal_args
%type <list> expr_list opt_expr_list
%type <c_case> case
%type <case_l> case_list
%type <attr> attr
%type <attr_l> attr_list opt_attr

%{
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "input.h"
#include "BroList.h"
#include "Desc.h"
#include "Expr.h"
#include "Func.h"
#include "Stmt.h"
#include "Val.h"
#include "Var.h"
/* #include "analyzer/protocol/dns/DNS.h" */
#include "RE.h"
#include "Scope.h"
#include "Reporter.h"
#include "ScriptCoverageManager.h"
#include "zeekygen/Manager.h"
#include "module_util.h"
#include "IntrusivePtr.h"

#include <set>
#include <string>

extern const char* filename;  // Absolute path of file currently being parsed.
extern const char* last_filename; // Absolute path of last file parsed.
extern const char* last_tok_filename;
extern const char* last_last_tok_filename;

YYLTYPE GetCurrentLocation();
extern int yyerror(const char[]);
extern int brolex();

#define YYLLOC_DEFAULT(Current, Rhs, N) \
	(Current) = (Rhs)[(N)];

/*
 * Part of the module facility: while parsing, keep track of which
 * module to put things in.
 */
std::string zeek::detail::current_module = GLOBAL_MODULE_NAME;
std::string& current_module = zeek::detail::current_module;

bool is_export = false; // true if in an export {} block

/*
 * When parsing an expression for the debugger, where to put the result
 * (obviously not reentrant).
 */
extern zeek::detail::Expr* g_curr_debug_expr;
extern bool in_debug;
extern const char* g_curr_debug_error;

static int in_hook = 0;
int in_init = 0;
int in_record = 0;
bool resolving_global_ID = false;
bool defining_global_ID = false;
std::vector<int> saved_in_init;

static zeek::detail::Location func_hdr_location;
zeek::EnumType* cur_enum_type = nullptr;
static zeek::detail::ID* cur_decl_type_id = nullptr;

static void parser_new_enum (void)
	{
	/* Starting a new enum definition. */
	assert(cur_enum_type == nullptr);

	if ( cur_decl_type_id )
		cur_enum_type = new zeek::EnumType(cur_decl_type_id->Name());
	else
		zeek::reporter->FatalError("incorrect syntax for enum type declaration");
	}

static void parser_redef_enum (zeek::detail::ID *id)
	{
	/* Redef an enum. id points to the enum to be redefined.
	   Let cur_enum_type point to it. */
	assert(cur_enum_type == nullptr);

	// abort on errors; enums need to be accessible to continue parsing
	if ( ! id->GetType() )
		zeek::reporter->FatalError("unknown enum identifier \"%s\"", id->Name());
	else
		{
		if ( ! id->GetType() || id->GetType()->Tag() != zeek::TYPE_ENUM )
			zeek::reporter->FatalError("identifier \"%s\" is not an enum", id->Name());
		cur_enum_type = id->GetType()->AsEnumType();
		}
	}

static void extend_record(zeek::detail::ID* id, std::unique_ptr<zeek::type_decl_list> fields,
                          std::unique_ptr<std::vector<zeek::detail::AttrPtr>> attrs)
	{
	std::set<zeek::Type*> types = zeek::Type::GetAliases(id->Name());

	if ( types.empty() )
		{
		id->Error("failed to redef record: no types found in alias map");
		return;
		}

	bool add_log_attr = false;

	if ( attrs )
		for ( const auto& at : *attrs )
			if ( at->Tag() == zeek::detail::ATTR_LOG )
				{
				add_log_attr = true;
				break;
				}

	for ( auto t : types )
		{
		auto error = t->AsRecordType()->AddFields(*fields, add_log_attr);

		if ( error )
			{
			id->Error(error);
			break;
			}
		}
	}

static zeek::detail::AttributesPtr
make_attributes(std::vector<zeek::detail::AttrPtr>* attrs,
                zeek::TypePtr t, bool in_record, bool is_global)
	{
	if ( ! attrs )
		return nullptr;

	auto rval = zeek::make_intrusive<zeek::detail::Attributes>(std::move(*attrs), std::move(t),
	                                       in_record, is_global);
	delete attrs;
	return rval;
	}

static bool expr_is_table_type_name(const zeek::detail::Expr* expr)
	{
	if ( expr->Tag() != zeek::detail::EXPR_NAME )
		return false;

	const auto& type = expr->GetType();

	if ( type->IsTable() )
		return true;

	if ( type->Tag() == zeek::TYPE_TYPE )
		return type->AsTypeType()->GetType()->IsTable();

	return false;
	}
%}

%union {
	bool b;
	char* str;
	zeek::detail::ID* id;
	id_list* id_l;
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
}

%%

bro:
		decl_list stmt_list
			{
			if ( stmts )
				stmts->AsStmtList()->Stmts().push_back($2);
			else
				stmts = $2;

			// Any objects creates from here on out should not
			// have file positions associated with them.
			zeek::detail::set_location(zeek::detail::no_location);
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

expr:
		'(' expr ')'
			{
			zeek::detail::set_location(@1, @3);
			$$ = $2; $$->MarkParen();
			}

	|	TOK_COPY '(' expr ')'
			{
			zeek::detail::set_location(@1, @4);
			$$ = new zeek::detail::CloneExpr({zeek::AdoptRef{}, $3});
			}

	|	TOK_INCR expr
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::IncrExpr(zeek::detail::EXPR_INCR, {zeek::AdoptRef{}, $2});
			}

	|	TOK_DECR expr
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::IncrExpr(zeek::detail::EXPR_DECR, {zeek::AdoptRef{}, $2});
			}

	|	'!' expr
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::NotExpr({zeek::AdoptRef{}, $2});
			}

	|	'~' expr
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::ComplementExpr({zeek::AdoptRef{}, $2});
			}

	|	'-' expr	%prec '!'
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::NegExpr({zeek::AdoptRef{}, $2});
			}

	|	'+' expr	%prec '!'
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::PosExpr({zeek::AdoptRef{}, $2});
			}

	|	expr '+' expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::AddExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr TOK_ADD_TO expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::AddToExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr '-' expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::SubExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr TOK_REMOVE_FROM expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::RemoveFromExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr '*' expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::TimesExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr '/' expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::DivideExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr '%' expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::ModExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr '&' expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::BitExpr(zeek::detail::EXPR_AND, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr '|' expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::BitExpr(zeek::detail::EXPR_OR, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr '^' expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::BitExpr(zeek::detail::EXPR_XOR, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr TOK_AND_AND expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::BoolExpr(zeek::detail::EXPR_AND_AND, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr TOK_OR_OR expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::BoolExpr(zeek::detail::EXPR_OR_OR, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr TOK_EQ expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::EqExpr(zeek::detail::EXPR_EQ, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr TOK_NE expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::EqExpr(zeek::detail::EXPR_NE, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr '<' expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::RelExpr(zeek::detail::EXPR_LT, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr TOK_LE expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::RelExpr(zeek::detail::EXPR_LE, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr '>' expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::RelExpr(zeek::detail::EXPR_GT, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr TOK_GE expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::RelExpr(zeek::detail::EXPR_GE, {zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr '?' expr ':' expr
			{
			zeek::detail::set_location(@1, @5);
			$$ = new zeek::detail::CondExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3}, {zeek::AdoptRef{}, $5});
			}

	|	expr '=' expr
			{
			zeek::detail::set_location(@1, @3);

			if ( $1->Tag() == zeek::detail::EXPR_INDEX && $1->AsIndexExpr()->IsSlice() )
				zeek::reporter->Error("index slice assignment may not be used"
				                      " in arbitrary expression contexts, only"
				                      " as a statement");

			$$ = zeek::detail::get_assign_expr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3}, in_init).release();
			}

	|	TOK_LOCAL local_id '=' expr
			{
			zeek::detail::set_location(@2, @4);
			$$ = add_and_assign_local({zeek::AdoptRef{}, $2}, {zeek::AdoptRef{}, $4},
			                          zeek::val_mgr->True()).release();
			}

	|	expr '[' expr_list ']'
			{
			zeek::detail::set_location(@1, @4);
			$$ = new zeek::detail::IndexExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	index_slice

	|	expr '$' TOK_ID
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::FieldExpr({zeek::AdoptRef{}, $1}, $3);
			}

	|	'$' TOK_ID '=' expr
			{
			zeek::detail::set_location(@1, @4);
			$$ = new zeek::detail::FieldAssignExpr($2, {zeek::AdoptRef{}, $4});
			}

	|	'$' TOK_ID func_params '='
			{
			func_hdr_location = @1;
			auto func_id = zeek::detail::current_scope()->GenerateTemporary("anonymous-function");
			func_id->SetInferReturnType(true);
			begin_func(std::move(func_id), zeek::detail::current_module.c_str(),
		   	           zeek::FUNC_FLAVOR_FUNCTION, false,
			           {zeek::AdoptRef{}, $3});
			}
		 lambda_body
			{
			$$ = new zeek::detail::FieldAssignExpr($2, zeek::IntrusivePtr{zeek::AdoptRef{}, $6});
			}

	|	expr TOK_IN expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::InExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|	expr TOK_NOT_IN expr
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::NotExpr(zeek::make_intrusive<zeek::detail::InExpr>(
			        zeek::detail::ExprPtr{zeek::AdoptRef{}, $1},
			        zeek::detail::ExprPtr{zeek::AdoptRef{}, $3}));
			}

	|	'[' expr_list ']'
			{
			zeek::detail::set_location(@1, @3);

			bool is_record_ctor = true;

			// If every expression in the list is a field assignment,
			// then treat it as a record constructor, else as a list
			// used for an initializer.

			for ( int i = 0; i < $2->Exprs().length(); ++i )
				{
				if ( $2->Exprs()[i]->Tag() != zeek::detail::EXPR_FIELD_ASSIGN )
					{
					is_record_ctor = false;
					break;
					}
				}

			if ( is_record_ctor )
				$$ = new zeek::detail::RecordConstructorExpr({zeek::AdoptRef{}, $2});
			else
				$$ = $2;
			}

	|	'[' ']'
			{
			// We interpret this as an empty record constructor.
			$$ = new zeek::detail::RecordConstructorExpr(zeek::make_intrusive<zeek::detail::ListExpr>());
			}


	|	TOK_RECORD '(' expr_list ')'
			{
			zeek::detail::set_location(@1, @4);
			$$ = new zeek::detail::RecordConstructorExpr({zeek::AdoptRef{}, $3});
			}

	|	TOK_TABLE '(' { ++in_init; } opt_expr_list ')' { --in_init; }
		opt_attr
			{ // the ++in_init fixes up the parsing of "[x] = y"
			zeek::detail::set_location(@1, @5);
			std::unique_ptr<std::vector<zeek::detail::AttrPtr>> attrs{$7};
			$$ = new zeek::detail::TableConstructorExpr({zeek::AdoptRef{}, $4}, std::move(attrs));
			}

	|	TOK_SET '(' opt_expr_list ')' opt_attr
			{
			zeek::detail::set_location(@1, @4);
			std::unique_ptr<std::vector<zeek::detail::AttrPtr>> attrs{$5};
			$$ = new zeek::detail::SetConstructorExpr({zeek::AdoptRef{}, $3}, std::move(attrs));
			}

	|	TOK_VECTOR '(' opt_expr_list ')'
			{
			zeek::detail::set_location(@1, @4);
			$$ = new zeek::detail::VectorConstructorExpr({zeek::AdoptRef{}, $3});
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
			zeek::detail::set_location(@1, @6);

			if ( $1->Tag() == zeek::detail::EXPR_NAME && $1->AsNameExpr()->Id()->IsType() )
				{
				const auto& ctor_type = $1->AsNameExpr()->Id()->GetType();

				switch ( ctor_type->Tag() ) {
				case zeek::TYPE_RECORD:
					{
					auto rce = zeek::make_intrusive<zeek::detail::RecordConstructorExpr>(
						zeek::detail::ListExprPtr{zeek::AdoptRef{}, $4});
					auto rt = zeek::cast_intrusive<zeek::RecordType>(ctor_type);
					$$ = new zeek::detail::RecordCoerceExpr(std::move(rce), std::move(rt));
					}
					break;

				case zeek::TYPE_TABLE:
					if ( ctor_type->IsTable() )
						$$ = new zeek::detail::TableConstructorExpr({zeek::AdoptRef{}, $4}, 0, ctor_type);
					else
						$$ = new zeek::detail::SetConstructorExpr({zeek::AdoptRef{}, $4}, 0, ctor_type);

					break;

				case zeek::TYPE_VECTOR:
					$$ = new zeek::detail::VectorConstructorExpr({zeek::AdoptRef{}, $4}, ctor_type);
					break;

				default:
					$1->Error("constructor type not implemented");
					YYERROR;
				}
				}

			else
				$$ = new zeek::detail::CallExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $4}, in_hook > 0);
			}

	|	TOK_HOOK { ++in_hook; } expr
			{
			--in_hook;
			zeek::detail::set_location(@1, @3);
			if ( $3->Tag() != zeek::detail::EXPR_CALL )
				$3->Error("not a valid hook call expression");
			$$ = $3;
			}

	|	expr TOK_HAS_FIELD TOK_ID
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::HasFieldExpr({zeek::AdoptRef{}, $1}, $3);
			}

	|	anonymous_function


	|	TOK_SCHEDULE expr '{' event '}'
			{
			zeek::detail::set_location(@1, @5);
			$$ = new zeek::detail::ScheduleExpr({zeek::AdoptRef{}, $2}, {zeek::AdoptRef{}, $4});
			}

	|	TOK_ID
			{
			zeek::detail::set_location(@1);
			auto id = zeek::detail::lookup_ID($1, zeek::detail::current_module.c_str());

			if ( ! id )
				{
				if ( ! in_debug )
					{
/*	// CHECK THAT THIS IS NOT GLOBAL.
					id = install_ID($1, zeek::detail::current_module.c_str(),
							        false, is_export);
*/

					yyerror(zeek::util::fmt("unknown identifier %s", $1));
					YYERROR;
					}
				else
					{
					yyerror(zeek::util::fmt("unknown identifier %s", $1));
					YYERROR;
					}
				}
			else
				{
				if ( id->IsDeprecated() )
					zeek::reporter->Warning("%s", id->GetDeprecationWarning().c_str());

				if ( ! id->GetType() )
					{
					id->Error("undeclared variable");
					id->SetType(zeek::error_type());
					$$ = new zeek::detail::NameExpr(std::move(id));
					}

				else if ( id->IsEnumConst() )
					{
					zeek::EnumType* t = id->GetType()->AsEnumType();
					auto intval = t->Lookup(id->ModuleName(), id->Name());
					if ( intval < 0 )
						zeek::reporter->InternalError("enum value not found for %s", id->Name());
					$$ = new zeek::detail::ConstExpr(t->GetEnumVal(intval));
					}
				else
					{
					$$ = new zeek::detail::NameExpr(std::move(id));
					}
				}
			}

	|	TOK_CONSTANT
			{
			zeek::detail::set_location(@1);
			$$ = new zeek::detail::ConstExpr({zeek::AdoptRef{}, $1});
			}

	|	'/' { begin_RE(); } TOK_PATTERN_TEXT TOK_PATTERN_END
			{
			zeek::detail::set_location(@3);

			auto* re = new zeek::RE_Matcher($3);
			delete [] $3;

			if ( $4 )
				re->MakeCaseInsensitive();

			re->Compile();
			$$ = new zeek::detail::ConstExpr(zeek::make_intrusive<zeek::PatternVal>(re));
			}

	|       '|' expr '|'	%prec '('
			{
			zeek::detail::set_location(@1, @3);
			zeek::detail::ExprPtr e{zeek::AdoptRef{}, $2};

			if ( zeek::IsIntegral(e->GetType()->Tag()) )
				e = zeek::make_intrusive<zeek::detail::ArithCoerceExpr>(std::move(e), zeek::TYPE_INT);

			$$ = new zeek::detail::SizeExpr(std::move(e));
			}

	|       expr TOK_AS type
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::CastExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}

	|       expr TOK_IS type
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::IsExpr({zeek::AdoptRef{}, $1}, {zeek::AdoptRef{}, $3});
			}
	;

expr_list:
		expr_list ',' expr
			{
			zeek::detail::set_location(@1, @3);
			$1->Append({zeek::AdoptRef{}, $3});
			}

	|	expr
			{
			zeek::detail::set_location(@1);
			$$ = new zeek::detail::ListExpr({zeek::AdoptRef{}, $1});
			}
	;

opt_expr_list:
		expr_list
	|
		{ $$ = new zeek::detail::ListExpr(); }
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
		   error messages if someboy tries to use constant variables as
		   enumerator.
		*/
		TOK_ID '=' TOK_CONSTANT opt_deprecated
			{
			zeek::detail::set_location(@1, @3);
			assert(cur_enum_type);

			if ( $3->GetType()->Tag() != zeek::TYPE_COUNT )
				zeek::reporter->Error("enumerator is not a count constant");
			else
				cur_enum_type->AddName(zeek::detail::current_module, $1,
				                       $3->InternalUnsigned(), is_export, $4);
			}

	|	TOK_ID '=' '-' TOK_CONSTANT
			{
			/* We only accept counts as enumerator, but we want to return a nice
			   error message if users triy to use a negative integer (will also
			   catch other cases, but that's fine.)
			*/
			zeek::reporter->Error("enumerator is not a count constant");
			}

	|	TOK_ID opt_deprecated
			{
			zeek::detail::set_location(@1);
			assert(cur_enum_type);
			cur_enum_type->AddName(zeek::detail::current_module, $1, is_export, $2);
			}
	;

type:
		TOK_BOOL	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_BOOL)->Ref();
				}

	|	TOK_INT		{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_INT)->Ref();
				}

	|	TOK_COUNT	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_COUNT)->Ref();
				}

	|	TOK_DOUBLE	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_DOUBLE)->Ref();
				}

	|	TOK_TIME	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_TIME)->Ref();
				}

	|	TOK_INTERVAL	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_INTERVAL)->Ref();
				}

	|	TOK_STRING	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_STRING)->Ref();
				}

	|	TOK_PATTERN	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_PATTERN)->Ref();
				}

	|	TOK_TIMER	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_TIMER)->Ref();
				}

	|	TOK_PORT	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_PORT)->Ref();
				}

	|	TOK_ADDR	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_ADDR)->Ref();
				}

	|	TOK_SUBNET	{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_SUBNET)->Ref();
				}

	|	TOK_ANY		{
				zeek::detail::set_location(@1);
				$$ = zeek::base_type(zeek::TYPE_ANY)->Ref();
				}

	|	TOK_TABLE '[' type_list ']' TOK_OF type
				{
				zeek::detail::set_location(@1, @6);
				$$ = new zeek::TableType({zeek::AdoptRef{}, $3}, {zeek::AdoptRef{}, $6});
				}

	|	TOK_SET '[' type_list ']'
				{
				zeek::detail::set_location(@1, @4);
				$$ = new zeek::SetType({zeek::AdoptRef{}, $3}, nullptr);
				}

	|	TOK_RECORD '{'
			{ ++in_record; }
		type_decl_list
			{ --in_record; }
		'}'
				{
				zeek::detail::set_location(@1, @5);
				$$ = new zeek::RecordType($4);
				}

	|	TOK_UNION '{' type_list '}'
				{
				zeek::detail::set_location(@1, @4);
				zeek::reporter->Error("union type not implemented");
				$$ = 0;
				}

	|	TOK_ENUM '{' { zeek::detail::set_location(@1); parser_new_enum(); } enum_body '}'
				{
				zeek::detail::set_location(@1, @5);
				$4->UpdateLocationEndInfo(@5);
				$$ = $4;
				}

	|	TOK_LIST
				{
				zeek::detail::set_location(@1);
				// $$ = new TypeList();
				zeek::reporter->Error("list type not implemented");
				$$ = 0;
				}

	|	TOK_LIST TOK_OF type
				{
				zeek::detail::set_location(@1);
				// $$ = new TypeList($3);
				zeek::reporter->Error("list type not implemented");
				$$ = 0;
				}

	|	TOK_VECTOR TOK_OF type
				{
				zeek::detail::set_location(@1, @3);
				$$ = new zeek::VectorType({zeek::AdoptRef{}, $3});
				}

	|	TOK_FUNCTION func_params
				{
				zeek::detail::set_location(@1, @2);
				$$ = $2;
				}

	|	TOK_EVENT '(' formal_args ')'
				{
				zeek::detail::set_location(@1, @3);
				$$ = new zeek::FuncType({zeek::AdoptRef{}, $3}, nullptr, zeek::FUNC_FLAVOR_EVENT);
				}

	|	TOK_HOOK '(' formal_args ')'
				{
				zeek::detail::set_location(@1, @3);
				$$ = new zeek::FuncType({zeek::AdoptRef{}, $3}, zeek::base_type(zeek::TYPE_BOOL), zeek::FUNC_FLAVOR_HOOK);
				}

	|	TOK_FILE TOK_OF type
				{
				zeek::detail::set_location(@1, @3);
				$$ = new zeek::FileType({zeek::AdoptRef{}, $3});
				}

	|	TOK_FILE
				{
				zeek::detail::set_location(@1);
				$$ = new zeek::FileType(zeek::base_type(zeek::TYPE_STRING));
				}

	|	TOK_OPAQUE TOK_OF TOK_ID
				{
				zeek::detail::set_location(@1, @3);
				$$ = new zeek::OpaqueType($3);
				}

	|	resolve_id
			{
			if ( ! $1 || ! ($$ = $1->IsType() ? $1->GetType().get() : nullptr) )
				{
				zeek::detail::NullStmt here;
				if ( $1 )
					$1->Error("not a Zeek type", &here);
				$$ = zeek::error_type()->Ref();
				}
			else
				{
				Ref($$);

				if ( $1->IsDeprecated() )
					zeek::reporter->Warning("%s", $1->GetDeprecationWarning().c_str());
				}
			}
	;

type_list:
		type_list ',' type
			{ $1->AppendEvenIfNotPure({zeek::AdoptRef{}, $3}); }
	|	type
			{
			$$ = new zeek::TypeList({zeek::NewRef{}, $1});
			$$->Append({zeek::AdoptRef{}, $1});
			}
	;

type_decl_list:
		type_decl_list type_decl
			{
			$1->push_back($2);
			}
	|
			{
			$$ = new zeek::type_decl_list();
			}
	;

type_decl:
		TOK_ID ':' type opt_attr ';'
			{
			zeek::detail::set_location(@1, @4);
			auto attrs = make_attributes($4, {zeek::NewRef{}, $3}, in_record > 0, false);
			$$ = new zeek::TypeDecl($1, {zeek::AdoptRef{}, $3}, std::move(attrs));

			if ( in_record > 0 && cur_decl_type_id )
				zeekygen_mgr->RecordField(cur_decl_type_id, $$, ::filename);
			}
	;

formal_args:
		formal_args_decl_list
			{ $$ = new zeek::RecordType($1); }
	|	formal_args_decl_list ';'
			{ $$ = new zeek::RecordType($1); }
	|
			{ $$ = new zeek::RecordType(new zeek::type_decl_list()); }
	;

formal_args_decl_list:
		formal_args_decl_list ';' formal_args_decl
			{ $1->push_back($3); }
	|	formal_args_decl_list ',' formal_args_decl
			{ $1->push_back($3); }
	|	formal_args_decl
			{ $$ = new zeek::type_decl_list(); $$->push_back($1); }
	;

formal_args_decl:
		TOK_ID ':' type opt_attr
			{
			zeek::detail::set_location(@1, @4);
			auto attrs = make_attributes($4, {zeek::NewRef{}, $3}, true, false);
			$$ = new zeek::TypeDecl($1, {zeek::AdoptRef{}, $3}, std::move(attrs));
			}
	;

decl:
		TOK_MODULE TOK_ID ';'
			{
			zeek::detail::current_module = $2;
			zeekygen_mgr->ModuleUsage(::filename, zeek::detail::current_module);
			}

	|	TOK_EXPORT '{' { is_export = true; } decl_list '}'
			{ is_export = false; }

	|	TOK_GLOBAL def_global_id opt_type init_class opt_init opt_attr ';'
			{
			zeek::IntrusivePtr id{zeek::AdoptRef{}, $2};
			add_global(id, {zeek::AdoptRef{}, $3}, $4, {zeek::AdoptRef{}, $5},
			           std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$6},
			           VAR_REGULAR);
			zeekygen_mgr->Identifier(std::move(id));
			}

	|	TOK_OPTION def_global_id opt_type init_class opt_init opt_attr ';'
			{
			zeek::IntrusivePtr id{zeek::AdoptRef{}, $2};
			add_global(id, {zeek::AdoptRef{}, $3}, $4, {zeek::AdoptRef{}, $5},
			           std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$6},
			           VAR_OPTION);
			zeekygen_mgr->Identifier(std::move(id));
			}

	|	TOK_CONST def_global_id opt_type init_class opt_init opt_attr ';'
			{
			zeek::IntrusivePtr id{zeek::AdoptRef{}, $2};
			add_global(id, {zeek::AdoptRef{}, $3}, $4, {zeek::AdoptRef{}, $5},
			           std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$6},
			           VAR_CONST);
			zeekygen_mgr->Identifier(std::move(id));
			}

	|	TOK_REDEF global_id opt_type init_class opt_init opt_attr ';'
			{
			zeek::IntrusivePtr id{zeek::AdoptRef{}, $2};
			zeek::detail::ExprPtr init{zeek::AdoptRef{}, $5};
			add_global(id, {zeek::AdoptRef{}, $3}, $4, init,
			           std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$6},
			           VAR_REDEF);
			zeekygen_mgr->Redef(id.get(), ::filename, $4, std::move(init));
			}

	|	TOK_REDEF TOK_ENUM global_id TOK_ADD_TO '{'
			{ parser_redef_enum($3); zeekygen_mgr->Redef($3, ::filename); }
		enum_body '}' ';'
			{
			// Zeekygen already grabbed new enum IDs as the type created them.
			}

	|	TOK_REDEF TOK_RECORD global_id
			{ cur_decl_type_id = $3; zeekygen_mgr->Redef($3, ::filename); }
		TOK_ADD_TO '{'
			{ ++in_record; }
		type_decl_list
			{ --in_record; }
		'}' opt_attr ';'
			{
			cur_decl_type_id = 0;

			if ( ! $3->GetType() )
				$3->Error("unknown identifier");
			else
				extend_record($3, std::unique_ptr<zeek::type_decl_list>($8),
				              std::unique_ptr<std::vector<zeek::detail::AttrPtr>>($11));
			}

	|	TOK_TYPE global_id ':'
			{ cur_decl_type_id = $2; zeekygen_mgr->StartType({zeek::NewRef{}, $2});  }
		type opt_attr ';'
			{
			cur_decl_type_id = 0;
			zeek::IntrusivePtr id{zeek::AdoptRef{}, $2};
			add_type(id.get(), {zeek::AdoptRef{}, $5},
			         std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$6});
			zeekygen_mgr->Identifier(std::move(id));
			}

	|	func_hdr { func_hdr_location = @1; } func_body

	|	func_hdr { func_hdr_location = @1; } conditional_list func_body

	|	conditional
	;

conditional_list:
		conditional
	|	conditional conditional_list

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
			zeek::IntrusivePtr id{zeek::AdoptRef{}, $2};
			begin_func(id, zeek::detail::current_module.c_str(),
				zeek::FUNC_FLAVOR_FUNCTION, 0, {zeek::NewRef{}, $3},
				std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$4});
			$$ = $3;
			zeekygen_mgr->Identifier(std::move(id));
			}
	|	TOK_EVENT event_id func_params opt_attr
			{
			const char* name = $2->Name();
			if ( zeek::util::streq("bro_init", name) || zeek::util::streq("bro_done", name) || zeek::util::streq("bro_script_loaded", name) )
				{
				auto base = std::string(name).substr(4);
				zeek::reporter->Error("event %s() is no longer available, use zeek_%s() instead", name, base.c_str());
				}

			begin_func({zeek::NewRef{}, $2}, zeek::detail::current_module.c_str(),
				   zeek::FUNC_FLAVOR_EVENT, 0, {zeek::NewRef{}, $3},
				   std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$4});
			$$ = $3;
			}
	|	TOK_HOOK def_global_id func_params opt_attr
			{
			$3->ClearYieldType(zeek::FUNC_FLAVOR_HOOK);
			$3->SetYieldType(zeek::base_type(zeek::TYPE_BOOL));
			begin_func({zeek::NewRef{}, $2}, zeek::detail::current_module.c_str(),
				   zeek::FUNC_FLAVOR_HOOK, 0, {zeek::NewRef{}, $3},
				   std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$4});
			$$ = $3;
			}
	|	TOK_REDEF TOK_EVENT event_id func_params opt_attr
			{
			begin_func({zeek::NewRef{}, $3}, zeek::detail::current_module.c_str(),
				   zeek::FUNC_FLAVOR_EVENT, 1, {zeek::NewRef{}, $4},
				   std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$5});
			$$ = $4;
			}
	;

func_body:
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
			zeek::detail::set_location(func_hdr_location, @5);
			end_func({zeek::AdoptRef{}, $3});
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
			zeek::detail::set_location(@1, @5);

			// Code duplication here is sad but needed. end_func actually instantiates the function
			// and associates it with an ID. We perform that association later and need to return
			// a lambda expression.

			// Gather the ingredients for a BroFunc from the current scope
			auto ingredients = std::make_unique<zeek::detail::function_ingredients>(
				zeek::IntrusivePtr{zeek::NewRef{}, zeek::detail::current_scope()},
				zeek::IntrusivePtr{zeek::AdoptRef{}, $3});
			id_list outer_ids = gather_outer_ids(zeek::detail::pop_scope().get(), ingredients->body.get());

			$$ = new zeek::detail::LambdaExpr(std::move(ingredients), std::move(outer_ids));
			}
	;

anonymous_function:
		TOK_FUNCTION begin_func lambda_body
			{ $$ = $3; }
	;

begin_func:
		func_params
			{
			auto id = zeek::detail::current_scope()->GenerateTemporary("anonymous-function");
			begin_func(id, zeek::detail::current_module.c_str(), zeek::FUNC_FLAVOR_FUNCTION, 0, {zeek::AdoptRef{}, $1});
			$$ = id.release();
			}
	;

func_params:
		'(' formal_args ')' ':' type
			{ $$ = new zeek::FuncType({zeek::AdoptRef{}, $2}, {zeek::AdoptRef{}, $5}, zeek::FUNC_FLAVOR_FUNCTION); }
	|	'(' formal_args ')'
			{ $$ = new zeek::FuncType({zeek::AdoptRef{}, $2}, zeek::base_type(zeek::TYPE_VOID), zeek::FUNC_FLAVOR_FUNCTION); }
	;

opt_type:
		':' type
			{ $$ = $2; }
	|
			{ $$ = 0; }
	;

init_class:
				{ $$ = zeek::detail::INIT_NONE; }
	|	'='		{ $$ = zeek::detail::INIT_FULL; }
	|	TOK_ADD_TO	{ $$ = zeek::detail::INIT_EXTRA; }
	|	TOK_REMOVE_FROM	{ $$ = zeek::detail::INIT_REMOVE; }
	;

opt_init:
		{ ++in_init; } init { --in_init; }
			{ $$ = $2; }
	|
			{ $$ = 0; }
	;

init:
		'{' opt_expr_list '}'
			{ $$ = $2; }
	|	'{' expr_list ',' '}'
			{ $$ = $2; }
	|	expr
	;

index_slice:
		expr '[' opt_expr ':' opt_expr ']'
			{
			zeek::detail::set_location(@1, @6);

			auto low = $3 ? zeek::detail::ExprPtr{zeek::AdoptRef{}, $3} :
			                zeek::make_intrusive<zeek::detail::ConstExpr>(zeek::val_mgr->Count(0));

			auto high = $5 ? zeek::detail::ExprPtr{zeek::AdoptRef{}, $5} :
			                 zeek::make_intrusive<zeek::detail::SizeExpr>(
			                     zeek::detail::ExprPtr{zeek::NewRef{}, $1});

			if ( ! zeek::IsIntegral(low->GetType()->Tag()) || ! zeek::IsIntegral(high->GetType()->Tag()) )
				zeek::reporter->Error("slice notation must have integral values as indexes");

			auto le = zeek::make_intrusive<zeek::detail::ListExpr>(std::move(low));
			le->Append(std::move(high));
			$$ = new zeek::detail::IndexExpr({zeek::AdoptRef{}, $1}, std::move(le), true);
			}

opt_attr:
		attr_list
	|
			{ $$ = nullptr; }
	;

attr_list:
		attr_list attr
			{ $1->emplace_back(zeek::AdoptRef{}, $2); }
	|	attr
			{
			$$ = new std::vector<zeek::detail::AttrPtr>;
			$$->emplace_back(zeek::AdoptRef{}, $1);
			}
	;

attr:
		TOK_ATTR_DEFAULT '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_DEFAULT, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_OPTIONAL
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_OPTIONAL); }
	|	TOK_ATTR_REDEF
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_REDEF); }
	|	TOK_ATTR_ADD_FUNC '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_ADD_FUNC, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_DEL_FUNC '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_DEL_FUNC, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_ON_CHANGE '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_ON_CHANGE, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_BROKER_STORE '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_BROKER_STORE, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_BROKER_STORE_ALLOW_COMPLEX
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_BROKER_STORE_ALLOW_COMPLEX); }
	|	TOK_ATTR_BACKEND '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_BACKEND, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_EXPIRE_FUNC '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_EXPIRE_FUNC, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_EXPIRE_CREATE '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_EXPIRE_CREATE, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_EXPIRE_READ '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_EXPIRE_READ, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_EXPIRE_WRITE '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_EXPIRE_WRITE, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_RAW_OUTPUT
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_RAW_OUTPUT); }
	|	TOK_ATTR_PRIORITY '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_PRIORITY, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_TYPE_COLUMN '=' expr
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_TYPE_COLUMN, {zeek::AdoptRef{}, $3}); }
	|	TOK_ATTR_LOG
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_LOG); }
	|	TOK_ATTR_ERROR_HANDLER
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_ERROR_HANDLER); }
	|	TOK_ATTR_DEPRECATED
			{ $$ = new zeek::detail::Attr(zeek::detail::ATTR_DEPRECATED); }
	|	TOK_ATTR_DEPRECATED '=' TOK_CONSTANT
			{
			if ( zeek::IsString($3->GetType()->Tag()) )
				$$ = new zeek::detail::Attr(
					zeek::detail::ATTR_DEPRECATED,
					zeek::make_intrusive<zeek::detail::ConstExpr>(zeek::IntrusivePtr{zeek::AdoptRef{}, $3}));
			else
				{
				zeek::ODesc d;
				$3->Describe(&d);
				Unref($3);
				zeek::reporter->Error("'&deprecated=%s' must use a string literal",
				                      d.Description());
				$$ = new zeek::detail::Attr(zeek::detail::ATTR_DEPRECATED);
				}
			}
	;

stmt:
		'{' opt_no_test_block stmt_list '}'
			{
			zeek::detail::set_location(@1, @4);
			$$ = $3;
			if ( $2 )
			    zeek::detail::script_coverage_mgr.DecIgnoreDepth();
			}

	|	TOK_PRINT expr_list ';' opt_no_test
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::PrintStmt(zeek::IntrusivePtr{zeek::AdoptRef{}, $2});
			if ( ! $4 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_EVENT event ';' opt_no_test
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::EventStmt({zeek::AdoptRef{}, $2});
			if ( ! $4 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_IF '(' expr ')' stmt
			{
			zeek::detail::set_location(@1, @4);
			$$ = new zeek::detail::IfStmt({zeek::AdoptRef{}, $3}, {zeek::AdoptRef{}, $5}, zeek::make_intrusive<zeek::detail::NullStmt>());
			}

	|	TOK_IF '(' expr ')' stmt TOK_ELSE stmt
			{
			zeek::detail::set_location(@1, @4);
			$$ = new zeek::detail::IfStmt({zeek::AdoptRef{}, $3}, {zeek::AdoptRef{}, $5}, {zeek::AdoptRef{}, $7});
			}

	|	TOK_SWITCH expr '{' case_list '}'
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::SwitchStmt({zeek::AdoptRef{}, $2}, $4);
			}

	|	for_head stmt
			{
			$1->AsForStmt()->AddBody({zeek::AdoptRef{}, $2});
			}

	|	TOK_WHILE '(' expr ')' stmt
			{
			$$ = new zeek::detail::WhileStmt({zeek::AdoptRef{}, $3}, {zeek::AdoptRef{}, $5});
			}

	|	TOK_NEXT ';' opt_no_test
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::NextStmt;
			if ( ! $3 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_BREAK ';' opt_no_test
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::BreakStmt;
			if ( ! $3 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_FALLTHROUGH ';' opt_no_test
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::FallthroughStmt;
			if ( ! $3 )
				zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_RETURN ';' opt_no_test
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::ReturnStmt(0);
			if ( ! $3 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_RETURN expr ';' opt_no_test
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::ReturnStmt({zeek::AdoptRef{}, $2});
			if ( ! $4 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_ADD expr ';' opt_no_test
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::AddStmt({zeek::AdoptRef{}, $2});
			if ( ! $4 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_DELETE expr ';' opt_no_test
			{
			zeek::detail::set_location(@1, @3);
			$$ = new zeek::detail::DelStmt({zeek::AdoptRef{}, $2});
			if ( ! $4 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_LOCAL local_id opt_type init_class opt_init opt_attr ';' opt_no_test
			{
			zeek::detail::set_location(@1, @7);
			$$ = add_local({zeek::AdoptRef{}, $2}, {zeek::AdoptRef{}, $3}, $4,
			               {zeek::AdoptRef{}, $5},
			               std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$6},
			               VAR_REGULAR).release();
			if ( ! $8 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_CONST local_id opt_type init_class opt_init opt_attr ';' opt_no_test
			{
			zeek::detail::set_location(@1, @6);
			$$ = add_local({zeek::AdoptRef{}, $2}, {zeek::AdoptRef{}, $3}, $4,
			               {zeek::AdoptRef{}, $5},
			               std::unique_ptr<std::vector<zeek::detail::AttrPtr>>{$6},
			               VAR_CONST).release();
			if ( ! $8 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	TOK_WHEN '(' expr ')' stmt
			{
			zeek::detail::set_location(@3, @5);
			$$ = new zeek::detail::WhenStmt({zeek::AdoptRef{}, $3}, {zeek::AdoptRef{}, $5},
			                                  nullptr, nullptr, false);
			}

	|	TOK_WHEN '(' expr ')' stmt TOK_TIMEOUT expr '{' opt_no_test_block stmt_list '}'
			{
			zeek::detail::set_location(@3, @9);
			$$ = new zeek::detail::WhenStmt({zeek::AdoptRef{}, $3}, {zeek::AdoptRef{}, $5},
			                                  {zeek::AdoptRef{}, $10}, {zeek::AdoptRef{}, $7}, false);
			if ( $9 )
			    zeek::detail::script_coverage_mgr.DecIgnoreDepth();
			}


	|	TOK_RETURN TOK_WHEN '(' expr ')' stmt
			{
			zeek::detail::set_location(@4, @6);
			$$ = new zeek::detail::WhenStmt({zeek::AdoptRef{}, $4}, {zeek::AdoptRef{}, $6}, nullptr,
			                  nullptr, true);
			}

	|	TOK_RETURN TOK_WHEN '(' expr ')' stmt TOK_TIMEOUT expr '{' opt_no_test_block stmt_list '}'
			{
			zeek::detail::set_location(@4, @10);
			$$ = new zeek::detail::WhenStmt({zeek::AdoptRef{}, $4}, {zeek::AdoptRef{}, $6},
			                                  {zeek::AdoptRef{}, $11}, {zeek::AdoptRef{}, $8}, true);
			if ( $10 )
			    zeek::detail::script_coverage_mgr.DecIgnoreDepth();
			}

	|	index_slice '=' expr ';' opt_no_test
			{
			zeek::detail::set_location(@1, @4);
			$$ = new zeek::detail::ExprStmt(zeek::detail::get_assign_expr({zeek::AdoptRef{}, $1},
			                                  {zeek::AdoptRef{}, $3}, in_init));

			if ( ! $5 )
				zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	expr ';' opt_no_test
			{
			zeek::detail::set_location(@1, @2);
			$$ = new zeek::detail::ExprStmt({zeek::AdoptRef{}, $1});
			if ( ! $3 )
			    zeek::detail::script_coverage_mgr.AddStmt($$);
			}

	|	';'
			{
			zeek::detail::set_location(@1, @1);
			$$ = new zeek::detail::NullStmt;
			}

	|	conditional
			{ $$ = new zeek::detail::NullStmt; }
	;

stmt_list:
		stmt_list stmt
			{
			zeek::detail::set_location(@1, @2);
			$1->AsStmtList()->Stmts().push_back($2);
			$1->UpdateLocationEndInfo(@2);
			}
	|
			{ $$ = new zeek::detail::StmtList(); }
	;

event:
		TOK_ID '(' opt_expr_list ')'
			{
			zeek::detail::set_location(@1, @4);
			const auto& id = zeek::detail::lookup_ID($1, zeek::detail::current_module.c_str());

			if ( id )
				{
				if ( ! id->IsGlobal() )
					{
					yyerror(zeek::util::fmt("local identifier \"%s\" cannot be used to reference an event", $1));
					YYERROR;
					}

				if ( id->IsDeprecated() )
					zeek::reporter->Warning("%s", id->GetDeprecationWarning().c_str());
				}

			$$ = new zeek::detail::EventExpr($1, {zeek::AdoptRef{}, $3});
			}
	;

case_list:
		case_list case
			{ $1->push_back($2); }
	|
			{ $$ = new zeek::detail::case_list; }
	;

case:
		TOK_CASE expr_list ':' stmt_list
			{ $$ = new zeek::detail::Case({zeek::AdoptRef{}, $2}, 0, {zeek::AdoptRef{}, $4}); }
	|
		TOK_CASE case_type_list ':' stmt_list
			{ $$ = new zeek::detail::Case(nullptr, $2, {zeek::AdoptRef{}, $4}); }
	|
		TOK_DEFAULT ':' stmt_list
			{ $$ = new zeek::detail::Case(nullptr, 0, {zeek::AdoptRef{}, $3}); }
	;

case_type_list:
		case_type_list ',' case_type
			{ $1->push_back($3); }
	|
		case_type
			{
			$$ = new id_list;
			$$->push_back($1);
			}
	;

case_type:
		TOK_TYPE type
			{
			$$ = new zeek::detail::ID(0, zeek::detail::SCOPE_FUNCTION, 0);
			$$->SetType({zeek::AdoptRef{}, $2});
			}

	|	TOK_TYPE type TOK_AS TOK_ID
			{
			const char* name = $4;
			zeek::TypePtr type{zeek::AdoptRef{}, $2};
			auto case_var = zeek::detail::lookup_ID(name, zeek::detail::current_module.c_str());

			if ( case_var && case_var->IsGlobal() )
				case_var->Error("already a global identifier");
			else
				case_var = zeek::detail::install_ID(name, zeek::detail::current_module.c_str(), false, false);

			add_local(case_var, std::move(type), zeek::detail::INIT_NONE, nullptr, nullptr,
			          VAR_REGULAR);
			$$ = case_var.release();
			}

for_head:
		TOK_FOR '(' TOK_ID TOK_IN expr ')'
			{
			zeek::detail::set_location(@1, @6);

			// This rule needs to be separate from the loop
			// body so that we execute these actions - defining
			// the local variable - prior to parsing the body,
			// which might refer to the variable.
			auto loop_var = zeek::detail::lookup_ID($3, zeek::detail::current_module.c_str());

			if ( loop_var )
				{
				if ( loop_var->IsGlobal() )
					loop_var->Error("global variable used in for loop");
				}

			else
				{
				loop_var = zeek::detail::install_ID($3, zeek::detail::current_module.c_str(),
				                                    false, false);
				}

			id_list* loop_vars = new id_list;
			loop_vars->push_back(loop_var.release());

			$$ = new zeek::detail::ForStmt(loop_vars, {zeek::AdoptRef{}, $5});
			}
	|
		TOK_FOR '(' '[' local_id_list ']' TOK_IN expr ')'
			{
			$$ = new zeek::detail::ForStmt($4, {zeek::AdoptRef{}, $7});
			}
	|
		TOK_FOR '(' TOK_ID ',' TOK_ID TOK_IN expr ')'
			{
			zeek::detail::set_location(@1, @8);
			const char* module = zeek::detail::current_module.c_str();

			// Check for previous definitions of key and
			// value variables.
			auto key_var = zeek::detail::lookup_ID($3, module);
			auto val_var = zeek::detail::lookup_ID($5, module);

			// Validate previous definitions as needed.
			if ( key_var )
				{
				if ( key_var->IsGlobal() )
					key_var->Error("global variable used in for loop");
				}
			else
				key_var = zeek::detail::install_ID($3, module, false, false);

			if ( val_var )
				{
				if ( val_var->IsGlobal() )
					val_var->Error("global variable used in for loop");
				}
			else
				val_var = zeek::detail::install_ID($5, module, false, false);

			id_list* loop_vars = new id_list;
			loop_vars->push_back(key_var.release());

			$$ = new zeek::detail::ForStmt(loop_vars, {zeek::AdoptRef{}, $7}, std::move(val_var));
			}
	|
		TOK_FOR '(' '[' local_id_list ']' ',' TOK_ID TOK_IN expr ')'
			{
			zeek::detail::set_location(@1, @10);
			const char* module = zeek::detail::current_module.c_str();

			// Validate value variable
			auto val_var = zeek::detail::lookup_ID($7, module);

			if ( val_var )
				{
				if ( val_var->IsGlobal() )
					val_var->Error("global variable used in for loop");
				}
			else
				val_var = zeek::detail::install_ID($7, module, false, false);

			$$ = new zeek::detail::ForStmt($4, {zeek::AdoptRef{}, $9}, std::move(val_var));
			}
	;

local_id_list:
		local_id_list ',' local_id
			{ $1->push_back($3); }
	|	local_id
			{
			$$ = new id_list;
			$$->push_back($1);
			}
	;

local_id:
		TOK_ID
			{
			zeek::detail::set_location(@1);
			auto id = zeek::detail::lookup_ID($1, zeek::detail::current_module.c_str());
			$$ = id.release();

			if ( $$ )
				{
				if ( $$->IsGlobal() )
					$$->Error("already a global identifier");
				delete [] $1;
				}

			else
				{
				$$ = zeek::detail::install_ID($1, zeek::detail::current_module.c_str(),
				                              false, is_export).release();
				}
			}
	;

global_id:
	{ resolving_global_ID = 1; } global_or_event_id
		{ $$ = $2; }
	;

def_global_id:
	{ defining_global_ID = 1; } global_id { defining_global_ID = 0; }
		{ $$ = $2; }
	;

event_id:
	{ resolving_global_ID = 0; } global_or_event_id
		{ $$ = $2; }
	;

global_or_event_id:
		TOK_ID
			{
			zeek::detail::set_location(@1);
			auto id = zeek::detail::lookup_ID($1, zeek::detail::current_module.c_str(), false,
			                    defining_global_ID);
			$$ = id.release();

			if ( $$ )
				{
				if ( ! $$->IsGlobal() )
					$$->Error("already a local identifier");

				if ( $$->IsDeprecated() )
					{
					const auto& t = $$->GetType();

					if ( t->Tag() != zeek::TYPE_FUNC ||
					     t->AsFuncType()->Flavor() != zeek::FUNC_FLAVOR_FUNCTION )
						zeek::reporter->Warning("%s", $$->GetDeprecationWarning().c_str());
					}

				delete [] $1;
				}

			else
				{
				const char* module_name =
					resolving_global_ID ?
						zeek::detail::current_module.c_str() : 0;

				$$ = zeek::detail::install_ID($1, module_name,
				                              true, is_export).release();
				}
			}
	;


resolve_id:
		TOK_ID
			{
			zeek::detail::set_location(@1);
			auto id = zeek::detail::lookup_ID($1, zeek::detail::current_module.c_str());
			$$ = id.release();

			if ( ! $$ )
				zeek::reporter->Error("identifier not defined: %s", $1);

			delete [] $1;
			}
	;

opt_no_test:
		TOK_NO_TEST
			{ $$ = true; }
	|
			{ $$ = false; }

opt_no_test_block:
		TOK_NO_TEST
			{ $$ = true; zeek::detail::script_coverage_mgr.IncIgnoreDepth(); }
	|
			{ $$ = false; }

opt_deprecated:
		TOK_ATTR_DEPRECATED
			{ $$ = new zeek::detail::ConstExpr(zeek::make_intrusive<zeek::StringVal>("")); }
	|
		TOK_ATTR_DEPRECATED '=' TOK_CONSTANT
			{
			if ( zeek::IsString($3->GetType()->Tag()) )
				$$ = new zeek::detail::ConstExpr({zeek::AdoptRef{}, $3});
			else
				{
				zeek::ODesc d;
				$3->Describe(&d);
				zeek::reporter->Error("'&deprecated=%s' must use a string literal",
				                      d.Description());
				$$ = new zeek::detail::ConstExpr(zeek::make_intrusive<zeek::StringVal>(""));
				}
			}
	|
			{ $$ = nullptr; }

%%

int yyerror(const char msg[])
	{
	if ( in_debug )
		g_curr_debug_error = zeek::util::copy_string(msg);

	if ( last_tok[0] == '\n' )
		zeek::reporter->Error("%s, on previous line", msg);
	else if ( last_tok[0] == '\0' )
		{
		if ( last_filename )
			zeek::reporter->Error("%s, at end of file %s", msg, last_filename);
		else
			zeek::reporter->Error("%s, at end of file", msg);
		}
	else
		{
		if ( last_last_tok_filename && last_tok_filename &&
		     ! zeek::util::streq(last_last_tok_filename, last_tok_filename) )
			zeek::reporter->Error("%s, at or near \"%s\" or end of file %s",
			                      msg, last_tok, last_last_tok_filename);
		else
			zeek::reporter->Error("%s, at or near \"%s\"", msg, last_tok);
		}

	return 0;
	}

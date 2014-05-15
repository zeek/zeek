%{
// See the file "COPYING" in the main distribution directory for copyright.
%}

%expect 75

%token TOK_ADD TOK_ADD_TO TOK_ADDR TOK_ANY
%token TOK_ATENDIF TOK_ATELSE TOK_ATIF TOK_ATIFDEF TOK_ATIFNDEF
%token TOK_BOOL TOK_BREAK TOK_CASE TOK_CONST
%token TOK_CONSTANT TOK_COPY TOK_COUNT TOK_COUNTER TOK_DEFAULT TOK_DELETE
%token TOK_DOUBLE TOK_ELSE TOK_ENUM TOK_EVENT TOK_EXPORT TOK_FALLTHROUGH
%token TOK_FILE TOK_FOR TOK_FUNCTION TOK_GLOBAL TOK_HOOK TOK_ID TOK_IF TOK_INT
%token TOK_INTERVAL TOK_LIST TOK_LOCAL TOK_MODULE
%token TOK_NEXT TOK_OF TOK_OPAQUE TOK_PATTERN TOK_PATTERN_TEXT
%token TOK_PORT TOK_PRINT TOK_RECORD TOK_REDEF
%token TOK_REMOVE_FROM TOK_RETURN TOK_SCHEDULE TOK_SET
%token TOK_STRING TOK_SUBNET TOK_SWITCH TOK_TABLE
%token TOK_TIME TOK_TIMEOUT TOK_TIMER TOK_TYPE TOK_UNION TOK_VECTOR TOK_WHEN

%token TOK_ATTR_ADD_FUNC TOK_ATTR_ENCRYPT TOK_ATTR_DEFAULT
%token TOK_ATTR_OPTIONAL TOK_ATTR_REDEF TOK_ATTR_ROTATE_INTERVAL
%token TOK_ATTR_ROTATE_SIZE TOK_ATTR_DEL_FUNC TOK_ATTR_EXPIRE_FUNC
%token TOK_ATTR_EXPIRE_CREATE TOK_ATTR_EXPIRE_READ TOK_ATTR_EXPIRE_WRITE
%token TOK_ATTR_PERSISTENT TOK_ATTR_SYNCHRONIZED
%token TOK_ATTR_RAW_OUTPUT TOK_ATTR_MERGEABLE
%token TOK_ATTR_PRIORITY TOK_ATTR_LOG TOK_ATTR_ERROR_HANDLER
%token TOK_ATTR_TYPE_COLUMN

%token TOK_DEBUG

%token TOK_NO_TEST

%nonassoc TOK_HOOK
%left ',' '|'
%right '=' TOK_ADD_TO TOK_REMOVE_FROM
%right '?' ':'
%left TOK_OR
%left TOK_AND
%nonassoc '<' '>' TOK_LE TOK_GE TOK_EQ TOK_NE
%left TOK_IN TOK_NOT_IN
%left '+' '-'
%left '*' '/' '%'
%left TOK_INCR TOK_DECR
%right '!'
%left '$' '[' ']' '(' ')' TOK_HAS_FIELD TOK_HAS_ATTR

%type <b> opt_no_test opt_no_test_block
%type <str> TOK_ID TOK_PATTERN_TEXT single_pattern
%type <id> local_id global_id def_global_id event_id global_or_event_id resolve_id begin_func
%type <id_l> local_id_list
%type <ic> init_class
%type <expr> opt_init
%type <val> TOK_CONSTANT
%type <re> pattern
%type <expr> expr opt_expr init anonymous_function
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
#include "Expr.h"
#include "Stmt.h"
#include "Var.h"
/* #include "analyzer/protocol/dns/DNS.h" */
#include "RE.h"
#include "Scope.h"
#include "Reporter.h"
#include "Brofiler.h"
#include "broxygen/Manager.h"

#include <set>
#include <string>

extern const char* filename;  // Absolute path of file currently being parsed.

YYLTYPE GetCurrentLocation();
extern int yyerror(const char[]);
extern int brolex();

#define YYLLOC_DEFAULT(Current, Rhs, N) \
	(Current) = (Rhs)[(N)];

/*
 * Part of the module facility: while parsing, keep track of which
 * module to put things in.
 */
string current_module = GLOBAL_MODULE_NAME;
bool is_export = false; // true if in an export {} block

/*
 * When parsing an expression for the debugger, where to put the result
 * (obviously not reentrant).
 */
extern Expr* g_curr_debug_expr;
extern bool in_debug;
extern const char* g_curr_debug_error;

#define YYLTYPE yyltype

static int in_hook = 0;
int in_init = 0;
int in_record = 0;
bool resolving_global_ID = false;
bool defining_global_ID = false;
std::vector<int> saved_in_init;

ID* func_id = 0;
EnumType *cur_enum_type = 0;
static ID* cur_decl_type_id = 0;

static void parser_new_enum (void)
	{
	/* Starting a new enum definition. */
	assert(cur_enum_type == NULL);
	cur_enum_type = new EnumType();
	}

static void parser_redef_enum (ID *id)
	{
	/* Redef an enum. id points to the enum to be redefined.
	   Let cur_enum_type point to it. */
	assert(cur_enum_type == NULL);
	if ( ! id->Type() )
		id->Error("unknown identifier");
	else
		{
		cur_enum_type = id->Type()->AsEnumType();
		if ( ! cur_enum_type )
			id->Error("not an enum");
		}
	}

static type_decl_list* copy_type_decl_list(type_decl_list* tdl)
	{
	if ( ! tdl )
		return 0;

	type_decl_list* rval = new type_decl_list();

	loop_over_list(*tdl, i)
		{
		TypeDecl* td = (*tdl)[i];
		rval->append(new TypeDecl(*td));
		}

	return rval;
	}

static attr_list* copy_attr_list(attr_list* al)
	{
	if ( ! al )
		return 0;

	attr_list* rval = new attr_list();

	loop_over_list(*al, i)
		{
		Attr* a = (*al)[i];
		::Ref(a);
		rval->append(a);
		}

	return rval;
	}

static void extend_record(ID* id, type_decl_list* fields, attr_list* attrs)
	{
	set<BroType*> types = BroType::GetAliases(id->Name());

	if ( types.empty() )
		{
		id->Error("failed to redef record: no types found in alias map");
		return;
		}

	for ( set<BroType*>::const_iterator it = types.begin(); it != types.end(); )
		{
		RecordType* add_to = (*it)->AsRecordType();
		const char* error = 0;
		++it;

		if ( it == types.end() )
			error = add_to->AddFields(fields, attrs);
		else
			error = add_to->AddFields(copy_type_decl_list(fields),
			                          copy_attr_list(attrs));

		if ( error )
			{
			id->Error(error);
			break;
			}
		}
	}

static bool expr_is_table_type_name(const Expr* expr)
	{
	if ( expr->Tag() != EXPR_NAME )
		return false;

	BroType* type = expr->Type();

	if ( type->IsTable() )
		return true;

	if ( type->Tag() == TYPE_TYPE )
		return type->AsTypeType()->Type()->IsTable();

	return false;
	}
%}

%union {
	bool b;
	char* str;
	ID* id;
	id_list* id_l;
	init_class ic;
	Val* val;
	RE_Matcher* re;
	Expr* expr;
	EventExpr* event_expr;
	Stmt* stmt;
	ListExpr* list;
	BroType* type;
	RecordType* record;
	FuncType* func_type;
	TypeList* type_l;
	TypeDecl* type_decl;
	type_decl_list* type_decl_l;
	Case* c_case;
	case_list* case_l;
	Attr* attr;
	attr_list* attr_l;
	attr_tag attrtag;
}

%%

bro:
		decl_list stmt_list
			{
			if ( optimize )
				$2 = $2->Simplify();

			if ( stmts )
				stmts->AsStmtList()->Stmts().append($2);
			else
				stmts = $2;

			// Any objects creates from hereon out should not
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

expr:
		'(' expr ')'
			{
			set_location(@1, @3);
			$$ = $2; $$->MarkParen();
			}

	|	TOK_COPY '(' expr ')'
			{
			set_location(@1, @4);
			$$ = new CloneExpr($3);
			}

	|	TOK_INCR expr
			{
			set_location(@1, @2);
			$$ = new IncrExpr(EXPR_INCR, $2);
			}

	|	TOK_DECR expr
			{
			set_location(@1, @2);
			$$ = new IncrExpr(EXPR_DECR, $2);
			}

	|	'!' expr
			{
			set_location(@1, @2);
			$$ = new NotExpr($2);
			}

	|	'-' expr	%prec '!'
			{
			set_location(@1, @2);
			$$ = new NegExpr($2);
			}

	|	'+' expr	%prec '!'
			{
			set_location(@1, @2);
			$$ = new PosExpr($2);
			}

	|	expr '+' expr
			{
			set_location(@1, @3);
			$$ = new AddExpr($1, $3);
			}

	|	expr TOK_ADD_TO expr
			{
			set_location(@1, @3);
			$$ = new AddToExpr($1, $3);
			}

	|	expr '-' expr
			{
			set_location(@1, @3);
			$$ = new SubExpr($1, $3);
			}

	|	expr TOK_REMOVE_FROM expr
			{
			set_location(@1, @3);
			$$ = new RemoveFromExpr($1, $3);
			}

	|	expr '*' expr
			{
			set_location(@1, @3);
			$$ = new TimesExpr($1, $3);
			}

	|	expr '/' expr
			{
			set_location(@1, @3);
			$$ = new DivideExpr($1, $3);
			}

	|	expr '%' expr
			{
			set_location(@1, @3);
			$$ = new ModExpr($1, $3);
			}

	|	expr TOK_AND expr
			{
			set_location(@1, @3);
			$$ = new BoolExpr(EXPR_AND, $1, $3);
			}

	|	expr TOK_OR expr
			{
			set_location(@1, @3);
			$$ = new BoolExpr(EXPR_OR, $1, $3);
			}

	|	expr TOK_EQ expr
			{
			set_location(@1, @3);
			$$ = new EqExpr(EXPR_EQ, $1, $3);
			}

	|	expr TOK_NE expr
			{
			set_location(@1, @3);
			$$ = new EqExpr(EXPR_NE, $1, $3);
			}

	|	expr '<' expr
			{
			set_location(@1, @3);
			$$ = new RelExpr(EXPR_LT, $1, $3);
			}

	|	expr TOK_LE expr
			{
			set_location(@1, @3);
			$$ = new RelExpr(EXPR_LE, $1, $3);
			}

	|	expr '>' expr
			{
			set_location(@1, @3);
			$$ = new RelExpr(EXPR_GT, $1, $3);
			}

	|	expr TOK_GE expr
			{
			set_location(@1, @3);
			$$ = new RelExpr(EXPR_GE, $1, $3);
			}

	|	expr '?' expr ':' expr
			{
			set_location(@1, @5);
			$$ = new CondExpr($1, $3, $5);
			}

	|	expr '=' expr
			{
			set_location(@1, @3);
			$$ = get_assign_expr($1, $3, in_init);
			}

	|	TOK_LOCAL local_id '=' expr
			{
			set_location(@2, @4);
			$$ = add_and_assign_local($2, $4, new Val(1, TYPE_BOOL));
			}

	|	expr '[' expr_list ']'
			{
			set_location(@1, @4);
			$$ = new IndexExpr($1, $3);
			}

	|	expr '[' opt_expr ':' opt_expr ']'
			{
			set_location(@1, @6);
			Expr* low = $3 ? $3 : new ConstExpr(new Val(0, TYPE_COUNT));
			Expr* high = $5 ? $5 : new SizeExpr($1);
			ListExpr* le = new ListExpr(low);
			le->Append(high);
			$$ = new IndexExpr($1, le, true);
			}

	|	expr '$' TOK_ID
			{
			set_location(@1, @3);
			$$ = new FieldExpr($1, $3);
			}

	|	'$' TOK_ID '=' expr
			{
			set_location(@1, @4);
			$$ = new FieldAssignExpr($2, $4);
			}

	|       '$' TOK_ID func_params '='
			{
			func_id = current_scope()->GenerateTemporary("anonymous-function");
			func_id->SetInferReturnType(true);
			begin_func(func_id,
				   current_module.c_str(),
				   FUNC_FLAVOR_FUNCTION,
				   0,
				   $3);
			}
		 func_body
			{
			$$ = new FieldAssignExpr($2, new ConstExpr(func_id->ID_Val()));
			}

	|	expr TOK_IN expr
			{
			set_location(@1, @3);
			$$ = new InExpr($1, $3);
			}

	|	expr TOK_NOT_IN expr
			{
			set_location(@1, @3);
			$$ = new NotExpr(new InExpr($1, $3));
			}

	|	'[' expr_list ']'
			{
			set_location(@1, @3);

			bool is_record_ctor = true;

			// If every expression in the list is a field assignment,
			// then treat it as a record constructor, else as a list
			// used for an initializer.

			for ( int i = 0; i < $2->Exprs().length(); ++i )
				{
				if ( $2->Exprs()[i]->Tag() != EXPR_FIELD_ASSIGN )
					{
					is_record_ctor = false;
					break;
					}
				}

			if ( is_record_ctor )
				$$ = new RecordConstructorExpr($2);
			else
				$$ = $2;
			}

	|	'[' ']'
			{
			// We interpret this as an empty record constructor.
			$$ = new RecordConstructorExpr(new ListExpr);
			}


	|	TOK_RECORD '(' expr_list ')'
			{
			set_location(@1, @4);
			$$ = new RecordConstructorExpr($3);
			}

	|	TOK_TABLE '(' { ++in_init; } opt_expr_list ')' { --in_init; }
		opt_attr
			{ // the ++in_init fixes up the parsing of "[x] = y"
			set_location(@1, @5);
			$$ = new TableConstructorExpr($4, $7);
			}

	|	TOK_SET '(' opt_expr_list ')' opt_attr
			{
			set_location(@1, @4);
			$$ = new SetConstructorExpr($3, $5);
			}

	|	TOK_VECTOR '(' opt_expr_list ')'
			{
			set_location(@1, @4);
			$$ = new VectorConstructorExpr($3);
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

			BroType* ctor_type = 0;

			if ( $1->Tag() == EXPR_NAME &&
			     (ctor_type = $1->AsNameExpr()->Id()->AsType()) )
				{
				switch ( ctor_type->Tag() ) {
				case TYPE_RECORD:
					$$ = new RecordCoerceExpr(new RecordConstructorExpr($4),
					                          ctor_type->AsRecordType());
					break;

				case TYPE_TABLE:
					if ( ctor_type->IsTable() )
						$$ = new TableConstructorExpr($4, 0, ctor_type);
					else
						$$ = new SetConstructorExpr($4, 0, ctor_type);

					break;

				case TYPE_VECTOR:
					$$ = new VectorConstructorExpr($4, ctor_type);
					break;

				default:
					$1->Error("constructor type not implemented");
					YYERROR;
				}
				}

			else
				$$ = new CallExpr($1, $4, in_hook > 0);
			}

	|	TOK_HOOK { ++in_hook; } expr
			{
			--in_hook;
			set_location(@1, @3);
			if ( $3->Tag() != EXPR_CALL )
				$3->Error("not a valid hook call expression");
			$$ = $3;
			}

	|	expr TOK_HAS_FIELD TOK_ID
			{
			set_location(@1, @3);
			$$ = new HasFieldExpr($1, $3);
			}

	|	anonymous_function

	|	TOK_SCHEDULE expr '{' event '}'
			{
			set_location(@1, @5);
			$$ = new ScheduleExpr($2, $4);
			}

	|	TOK_ID
			{
			set_location(@1);

			ID* id = lookup_ID($1, current_module.c_str());
			if ( ! id )
				{
				if ( ! in_debug )
					{
/*	// CHECK THAT THIS IS NOT GLOBAL.
					id = install_ID($1, current_module.c_str(),
							false, is_export);
*/

					yyerror(fmt("unknown identifier %s", $1));
					YYERROR;
					}
				else
					{
					yyerror(fmt("unknown identifier %s", $1));
					YYERROR;
					}
				}
			else
				{
				if ( ! id->Type() )
					{
					id->Error("undeclared variable");
					id->SetType(error_type());
					$$ = new NameExpr(id);
					}

				else if ( id->IsEnumConst() )
					{
					EnumType* t = id->Type()->AsEnumType();
					int intval = t->Lookup(id->ModuleName(),
							       id->Name());
					if ( intval < 0 )
						reporter->InternalError("enum value not found for %s", id->Name());
					$$ = new ConstExpr(new EnumVal(intval, t));
					}
				else
					$$ = new NameExpr(id);
				}
			}

	|	TOK_CONSTANT
			{
			set_location(@1);
			$$ = new ConstExpr($1);
			}

	|	pattern
			{
			set_location(@1);
			$1->Compile();
			$$ = new ConstExpr(new PatternVal($1));
			}

	|       '|' expr '|'
			{
			set_location(@1, @3);
			$$ = new SizeExpr($2);
			}
	;

expr_list:
		expr_list ',' expr
			{
			set_location(@1, @3);
			$1->Append($3);
			}

	|	expr
			{
			set_location(@1);
			$$ = new ListExpr($1);
			}
	;

opt_expr_list:
		expr_list
	|
		{ $$ = new ListExpr(); }
	;

pattern:
		pattern '|' single_pattern
			{
			$1->AddPat($3);
			delete [] $3;
			}

	|	single_pattern
			{
			$$ = new RE_Matcher($1);
			delete [] $1;
			}
	;

single_pattern:
		'/' { begin_RE(); } TOK_PATTERN_TEXT { end_RE(); } '/'
			{ $$ = $3; }
	;

enum_body:
		enum_body_list
			{
			$$ = cur_enum_type;
			cur_enum_type = NULL;
			}

	|	enum_body_list ','
			{
			$$ = cur_enum_type;
			cur_enum_type = NULL;
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
		TOK_ID '=' TOK_CONSTANT
			{
			set_location(@1, @3);
			assert(cur_enum_type);

			if ( $3->Type()->Tag() != TYPE_COUNT )
				reporter->Error("enumerator is not a count constant");
			else
				cur_enum_type->AddName(current_module, $1,
				                       $3->InternalUnsigned(), is_export);
			}

	|	TOK_ID '=' '-' TOK_CONSTANT
			{
			/* We only accept counts as enumerator, but we want to return a nice
			   error message if users triy to use a negative integer (will also
			   catch other cases, but that's fine.)
			*/
			reporter->Error("enumerator is not a count constant");
			}

	|	TOK_ID
			{
			set_location(@1);
			assert(cur_enum_type);
			cur_enum_type->AddName(current_module, $1, is_export);
			}
	;

type:
		TOK_BOOL	{
				set_location(@1);
				$$ = base_type(TYPE_BOOL);
				}

	|	TOK_INT		{
				set_location(@1);
				$$ = base_type(TYPE_INT);
				}

	|	TOK_COUNT	{
				set_location(@1);
				$$ = base_type(TYPE_COUNT);
				}

	|	TOK_COUNTER	{
				set_location(@1);
				$$ = base_type(TYPE_COUNTER);
				}

	|	TOK_DOUBLE	{
				set_location(@1);
				$$ = base_type(TYPE_DOUBLE);
				}

	|	TOK_TIME	{
				set_location(@1);
				$$ = base_type(TYPE_TIME);
				}

	|	TOK_INTERVAL	{
				set_location(@1);
				$$ = base_type(TYPE_INTERVAL);
				}

	|	TOK_STRING	{
				set_location(@1);
				$$ = base_type(TYPE_STRING);
				}

	|	TOK_PATTERN	{
				set_location(@1);
				$$ = base_type(TYPE_PATTERN);
				}

	|	TOK_TIMER	{
				set_location(@1);
				$$ = base_type(TYPE_TIMER);
				}

	|	TOK_PORT	{
				set_location(@1);
				$$ = base_type(TYPE_PORT);
				}

	|	TOK_ADDR	{
				set_location(@1);
				$$ = base_type(TYPE_ADDR);
				}

	|	TOK_SUBNET	{
				set_location(@1);
				$$ = base_type(TYPE_SUBNET);
				}

	|	TOK_ANY		{
				set_location(@1);
				$$ = base_type(TYPE_ANY);
				}

	|	TOK_TABLE '[' type_list ']' TOK_OF type
				{
				set_location(@1, @6);
				$$ = new TableType($3, $6);
				}

	|	TOK_SET '[' type_list ']'
				{
				set_location(@1, @4);
				$$ = new SetType($3, 0);
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

	|	TOK_UNION '{' type_list '}'
				{
				set_location(@1, @4);
				reporter->Error("union type not implemented");
				$$ = 0;
				}

	|	TOK_ENUM '{' { set_location(@1); parser_new_enum(); } enum_body '}'
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
				$$ = new VectorType($3);
				}

	|	TOK_FUNCTION func_params
				{
				set_location(@1, @2);
				$$ = $2;
				}

	|	TOK_EVENT '(' formal_args ')'
				{
				set_location(@1, @3);
				$$ = new FuncType($3, 0, FUNC_FLAVOR_EVENT);
				}

	|	TOK_HOOK '(' formal_args ')'
				{
				set_location(@1, @3);
				$$ = new FuncType($3, base_type(TYPE_BOOL), FUNC_FLAVOR_HOOK);
				}

	|	TOK_FILE TOK_OF type
				{
				set_location(@1, @3);
				$$ = new FileType($3);
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

	|	resolve_id
			{
			if ( ! $1 || ! ($$ = $1->AsType()) )
				{
				NullStmt here;
				if ( $1 )
					$1->Error("not a BRO type", &here);
				$$ = error_type();
				}
			else
				Ref($$);
			}
	;

type_list:
		type_list ',' type
			{ $1->AppendEvenIfNotPure($3); }
	|	type
			{
			$$ = new TypeList($1);
			$$->Append($1);
			}
	;

type_decl_list:
		type_decl_list type_decl
			{
			$1->append($2);
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
			$$ = new TypeDecl($3, $1, $4, (in_record > 0));

			if ( in_record > 0 && cur_decl_type_id )
				broxygen_mgr->RecordField(cur_decl_type_id, $$, ::filename);
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
			{ $1->append($3); }
	|	formal_args_decl_list ',' formal_args_decl
			{ $1->append($3); }
	|	formal_args_decl
			{ $$ = new type_decl_list(); $$->append($1); }
	;

formal_args_decl:
		TOK_ID ':' type opt_attr
			{
			set_location(@1, @4);
			$$ = new TypeDecl($3, $1, $4);
			}
	;

decl:
		TOK_MODULE TOK_ID ';'
			{
			current_module = $2;
			broxygen_mgr->ModuleUsage(::filename, current_module);
			}

	|	TOK_EXPORT '{' { is_export = true; } decl_list '}'
			{ is_export = false; }

	|	TOK_GLOBAL def_global_id opt_type init_class opt_init opt_attr ';'
			{
			add_global($2, $3, $4, $5, $6, VAR_REGULAR);
			broxygen_mgr->Identifier($2);
			}

	|	TOK_CONST def_global_id opt_type init_class opt_init opt_attr ';'
			{
			add_global($2, $3, $4, $5, $6, VAR_CONST);
			broxygen_mgr->Identifier($2);
			}

	|	TOK_REDEF global_id opt_type init_class opt_init opt_attr ';'
			{
			add_global($2, $3, $4, $5, $6, VAR_REDEF);
			broxygen_mgr->Redef($2, ::filename);
			}

	|	TOK_REDEF TOK_ENUM global_id TOK_ADD_TO '{'
			{ parser_redef_enum($3); broxygen_mgr->Redef($3, ::filename); }
		enum_body '}' ';'
			{
			// Broxygen already grabbed new enum IDs as the type created them.
			}

	|	TOK_REDEF TOK_RECORD global_id
			{ cur_decl_type_id = $3; broxygen_mgr->Redef($3, ::filename); }
		TOK_ADD_TO '{'
			{ ++in_record; }
		type_decl_list
			{ --in_record; }
		'}' opt_attr ';'
			{
			cur_decl_type_id = 0;

			if ( ! $3->Type() )
				$3->Error("unknown identifier");
			else
				extend_record($3, $8, $11);
			}

	|	TOK_TYPE global_id ':'
			{ cur_decl_type_id = $2; broxygen_mgr->StartType($2);  }
		type opt_attr ';'
			{
			cur_decl_type_id = 0;
			add_type($2, $5, $6);
			broxygen_mgr->Identifier($2);
			}

	|	func_hdr func_body
			{ }

	|	conditional
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
		TOK_FUNCTION def_global_id func_params
			{
			begin_func($2, current_module.c_str(),
				FUNC_FLAVOR_FUNCTION, 0, $3);
			$$ = $3;
			broxygen_mgr->Identifier($2);
			}
	|	TOK_EVENT event_id func_params
			{
			begin_func($2, current_module.c_str(),
				   FUNC_FLAVOR_EVENT, 0, $3);
			$$ = $3;
			}
	|	TOK_HOOK def_global_id func_params
			{
			$3->ClearYieldType(FUNC_FLAVOR_HOOK);
			$3->SetYieldType(base_type(TYPE_BOOL));
			begin_func($2, current_module.c_str(),
				   FUNC_FLAVOR_HOOK, 0, $3);
			$$ = $3;
			}
	|	TOK_REDEF TOK_EVENT event_id func_params
			{
			begin_func($3, current_module.c_str(),
				   FUNC_FLAVOR_EVENT, 1, $4);
			$$ = $4;
			}
	;

func_body:
		opt_attr '{'
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
			if ( optimize )
				$4 = $4->Simplify();

			end_func($4, $1);
			}
	;

anonymous_function:
		TOK_FUNCTION begin_func func_body
			{ $$ = new ConstExpr($2->ID_Val()); }
	;

begin_func:
		func_params
			{
			$$ = current_scope()->GenerateTemporary("anonymous-function");
			begin_func($$, current_module.c_str(),
				   FUNC_FLAVOR_FUNCTION, 0, $1);
			}
	;

func_params:
		'(' formal_args ')' ':' type
			{ $$ = new FuncType($2, $5, FUNC_FLAVOR_FUNCTION); }
	|	'(' formal_args ')'
			{ $$ = new FuncType($2, base_type(TYPE_VOID), FUNC_FLAVOR_FUNCTION); }
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

opt_attr:
		attr_list
	|
			{ $$ = 0; }
	;

attr_list:
		attr_list attr
			{ $1->append($2); }
	|	attr
			{
			$$ = new attr_list;
			$$->append($1);
			}
	;

attr:
		TOK_ATTR_DEFAULT '=' expr
			{ $$ = new Attr(ATTR_DEFAULT, $3); }
	|	TOK_ATTR_OPTIONAL
			{ $$ = new Attr(ATTR_OPTIONAL); }
	|	TOK_ATTR_REDEF
			{ $$ = new Attr(ATTR_REDEF); }
	|	TOK_ATTR_ROTATE_INTERVAL '=' expr
			{ $$ = new Attr(ATTR_ROTATE_INTERVAL, $3); }
	|	TOK_ATTR_ROTATE_SIZE '=' expr
			{ $$ = new Attr(ATTR_ROTATE_SIZE, $3); }
	|	TOK_ATTR_ADD_FUNC '=' expr
			{ $$ = new Attr(ATTR_ADD_FUNC, $3); }
	|	TOK_ATTR_DEL_FUNC '=' expr
			{ $$ = new Attr(ATTR_DEL_FUNC, $3); }
	|	TOK_ATTR_EXPIRE_FUNC '=' expr
			{ $$ = new Attr(ATTR_EXPIRE_FUNC, $3); }
	|	TOK_ATTR_EXPIRE_CREATE '=' expr
			{ $$ = new Attr(ATTR_EXPIRE_CREATE, $3); }
	|	TOK_ATTR_EXPIRE_READ '=' expr
			{ $$ = new Attr(ATTR_EXPIRE_READ, $3); }
	|	TOK_ATTR_EXPIRE_WRITE '=' expr
			{ $$ = new Attr(ATTR_EXPIRE_WRITE, $3); }
	|	TOK_ATTR_PERSISTENT
			{ $$ = new Attr(ATTR_PERSISTENT); }
	|	TOK_ATTR_SYNCHRONIZED
			{ $$ = new Attr(ATTR_SYNCHRONIZED); }
	|	TOK_ATTR_ENCRYPT
			{ $$ = new Attr(ATTR_ENCRYPT); }
	|	TOK_ATTR_ENCRYPT '=' expr
			{ $$ = new Attr(ATTR_ENCRYPT, $3); }
	|	TOK_ATTR_RAW_OUTPUT
			{ $$ = new Attr(ATTR_RAW_OUTPUT); }
	|	TOK_ATTR_MERGEABLE
			{ $$ = new Attr(ATTR_MERGEABLE); }
	|	TOK_ATTR_PRIORITY '=' expr
			{ $$ = new Attr(ATTR_PRIORITY, $3); }
	|	TOK_ATTR_TYPE_COLUMN '=' expr
			{ $$ = new Attr(ATTR_TYPE_COLUMN, $3); }
	|	TOK_ATTR_LOG
			{ $$ = new Attr(ATTR_LOG); }
	|	TOK_ATTR_ERROR_HANDLER
			{ $$ = new Attr(ATTR_ERROR_HANDLER); }
	;

stmt:
		'{' opt_no_test_block stmt_list '}'
			{
			set_location(@1, @4);
			$$ = $3;
			if ( $2 )
			    brofiler.DecIgnoreDepth();
			}

	|	TOK_PRINT expr_list ';' opt_no_test
			{
			set_location(@1, @3);
			$$ = new PrintStmt($2);
			if ( ! $4 )
			    brofiler.AddStmt($$);
			}

	|	TOK_EVENT event ';' opt_no_test
			{
			set_location(@1, @3);
			$$ = new EventStmt($2);
			if ( ! $4 )
			    brofiler.AddStmt($$);
			}

	|	TOK_IF '(' expr ')' stmt
			{
			set_location(@1, @4);
			$$ = new IfStmt($3, $5, new NullStmt());
			}

	|	TOK_IF '(' expr ')' stmt TOK_ELSE stmt
			{
			set_location(@1, @4);
			$$ = new IfStmt($3, $5, $7);
			}

	|	TOK_SWITCH expr '{' case_list '}'
			{
			set_location(@1, @2);
			$$ = new SwitchStmt($2, $4);
			}

	|	for_head stmt
			{
			$1->AsForStmt()->AddBody($2);
			}

	|	TOK_NEXT ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new NextStmt;
			if ( ! $3 )
			    brofiler.AddStmt($$);
			}

	|	TOK_BREAK ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new BreakStmt;
			if ( ! $3 )
			    brofiler.AddStmt($$);
			}

	|	TOK_FALLTHROUGH ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new FallthroughStmt;
			if ( ! $3 )
				brofiler.AddStmt($$);
			}

	|	TOK_RETURN ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new ReturnStmt(0);
			if ( ! $3 )
			    brofiler.AddStmt($$);
			}

	|	TOK_RETURN expr ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new ReturnStmt($2);
			if ( ! $4 )
			    brofiler.AddStmt($$);
			}

	|	TOK_ADD expr ';' opt_no_test
			{
			set_location(@1, @3);
			$$ = new AddStmt($2);
			if ( ! $4 )
			    brofiler.AddStmt($$);
			}

	|	TOK_DELETE expr ';' opt_no_test
			{
			set_location(@1, @3);
			$$ = new DelStmt($2);
			if ( ! $4 )
			    brofiler.AddStmt($$);
			}

	|	TOK_LOCAL local_id opt_type init_class opt_init opt_attr ';' opt_no_test
			{
			set_location(@1, @7);
			$$ = add_local($2, $3, $4, $5, $6, VAR_REGULAR);
			if ( ! $8 )
			    brofiler.AddStmt($$);
			}

	|	TOK_CONST local_id opt_type init_class opt_init opt_attr ';' opt_no_test
			{
			set_location(@1, @6);
			$$ = add_local($2, $3, $4, $5, $6, VAR_CONST);
			if ( ! $8 )
			    brofiler.AddStmt($$);
			}

	|	TOK_WHEN '(' expr ')' stmt
			{
			set_location(@3, @5);
			$$ = new WhenStmt($3, $5, 0, 0, false);
			}

	|	TOK_WHEN '(' expr ')' stmt TOK_TIMEOUT expr '{' opt_no_test_block stmt_list '}'
			{
			set_location(@3, @9);
			$$ = new WhenStmt($3, $5, $10, $7, false);
			if ( $9 )
			    brofiler.DecIgnoreDepth();
			}


	|	TOK_RETURN TOK_WHEN '(' expr ')' stmt
			{
			set_location(@4, @6);
			$$ = new WhenStmt($4, $6, 0, 0, true);
			}

	|	TOK_RETURN TOK_WHEN '(' expr ')' stmt TOK_TIMEOUT expr '{' opt_no_test_block stmt_list '}'
			{
			set_location(@4, @10);
			$$ = new WhenStmt($4, $6, $11, $8, true);
			if ( $10 )
			    brofiler.DecIgnoreDepth();
			}

	|	expr ';' opt_no_test
			{
			set_location(@1, @2);
			$$ = new ExprStmt($1);
			if ( ! $3 )
			    brofiler.AddStmt($$);
			}

	|	';'
			{
			set_location(@1, @1);
			$$ = new NullStmt;
			}

	|	conditional
			{ $$ = new NullStmt; }
	;

stmt_list:
		stmt_list stmt
			{
			set_location(@1, @2);
			$1->AsStmtList()->Stmts().append($2);
			$1->UpdateLocationEndInfo(@2);
			}
	|
			{ $$ = new StmtList(); }
	;

event:
		TOK_ID '(' opt_expr_list ')'
			{
			set_location(@1, @4);
			$$ = new EventExpr($1, $3);
			}
	;

case_list:
		case_list case
			{ $1->append($2); }
	|
			{ $$ = new case_list; }
	;

case:
		TOK_CASE expr_list ':' stmt_list
			{ $$ = new Case($2, $4); }
	|
		TOK_DEFAULT ':' stmt_list
			{ $$ = new Case(0, $3); }
	;

for_head:
		TOK_FOR '(' TOK_ID TOK_IN expr ')'
			{
			set_location(@1, @6);

			// This rule needs to be separate from the loop
			// body so that we execute these actions - defining
			// the local variable - prior to parsing the body,
			// which might refer to the variable.
			ID* loop_var = lookup_ID($3, current_module.c_str());

			if ( loop_var )
				{
				if ( loop_var->IsGlobal() )
					loop_var->Error("global used in for loop");
				}

			else
				loop_var = install_ID($3, current_module.c_str(),
						      false, false);

			id_list* loop_vars = new id_list;
			loop_vars->append(loop_var);

			$$ = new ForStmt(loop_vars, $5);
			}
	|
		TOK_FOR '(' '[' local_id_list ']' TOK_IN expr ')'
			{ $$ = new ForStmt($4, $7); }
		;

local_id_list:
		local_id_list ',' local_id
			{ $1->append($3); }
	|	local_id
			{
			$$ = new id_list;
			$$->append($1);
			}
	;

local_id:
		TOK_ID
			{
			set_location(@1);

			$$ = lookup_ID($1, current_module.c_str());
			if ( $$ )
				{
				if ( $$->IsGlobal() )
					$$->Error("already a global identifier");
				delete [] $1;
				}

			else
				{
				$$ = install_ID($1, current_module.c_str(),
						false, is_export);
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
			set_location(@1);

			$$ = lookup_ID($1, current_module.c_str(), false, defining_global_ID);
			if ( $$ )
				{
				if ( ! $$->IsGlobal() )
					$$->Error("already a local identifier");

				delete [] $1;
				}

			else
				{
				const char* module_name =
					resolving_global_ID ?
						current_module.c_str() : 0;

				$$ = install_ID($1, module_name,
						true, is_export);
				}
			}
	;


resolve_id:
		TOK_ID
			{
			set_location(@1);
			$$ = lookup_ID($1, current_module.c_str());

			if ( ! $$ )
				reporter->Error("identifier not defined: %s", $1);

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
			{ $$ = true; brofiler.IncIgnoreDepth(); }
	|
			{ $$ = false; }

%%

int yyerror(const char msg[])
	{
	char* msgbuf = new char[strlen(msg) + strlen(last_tok) + 128];

	if ( last_tok[0] == '\n' )
		sprintf(msgbuf, "%s, on previous line", msg);
	else if ( last_tok[0] == '\0' )
		sprintf(msgbuf, "%s, at end of file", msg);
	else
		sprintf(msgbuf, "%s, at or near \"%s\"", msg, last_tok);

	if ( in_debug )
		g_curr_debug_error = copy_string(msg);

	reporter->Error("%s", msgbuf);

	return 0;
	}

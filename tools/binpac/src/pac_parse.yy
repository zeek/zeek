%token TOK_TYPE TOK_RECORD TOK_CASE TOK_ENUM TOK_LET TOK_FUNCTION
%token TOK_REFINE TOK_CASEFUNC TOK_CASETYPE TOK_TYPEATTR
%token TOK_HELPERHEADER TOK_HELPERCODE
%token TOK_RIGHTARROW TOK_DEFAULT TOK_OF
%token TOK_PADDING TOK_TO TOK_ALIGN
%token TOK_WITHINPUT
%token TOK_INT8 TOK_INT16 TOK_INT32 TOK_INT64
%token TOK_UINT8 TOK_UINT16 TOK_UINT32 TOK_UINT64
%token TOK_ID TOK_NUMBER TOK_REGEX TOK_STRING
%token TOK_BEGIN_RE TOK_END_RE
%token TOK_ATTR_ALSO
%token TOK_ATTR_BYTEORDER TOK_ATTR_CHECK TOK_ATTR_CHUNKED TOK_ATTR_ENFORCE
%token TOK_ATTR_EXPORTSOURCEDATA TOK_ATTR_IF
%token TOK_ATTR_LENGTH TOK_ATTR_LET
%token TOK_ATTR_LINEBREAKER TOK_ATTR_MULTILINE TOK_ATTR_ONELINE
%token TOK_ATTR_REFCOUNT TOK_ATTR_REQUIRES
%token TOK_ATTR_RESTOFDATA TOK_ATTR_RESTOFFLOW
%token TOK_ATTR_TRANSIENT TOK_ATTR_UNTIL
%token TOK_ANALYZER TOK_CONNECTION TOK_FLOW
%token TOK_STATE TOK_ACTION TOK_WHEN TOK_HELPER
%token TOK_DATAUNIT TOK_FLOWDIR TOK_WITHCONTEXT
%token TOK_LPB_EXTERN TOK_LPB_HEADER TOK_LPB_CODE
%token TOK_LPB_MEMBER TOK_LPB_INIT TOK_LPB_CLEANUP TOK_LPB_EOF
%token TOK_LPB TOK_RPB
%token TOK_EMBEDDED_ATOM TOK_EMBEDDED_STRING
%token TOK_PAC_VAL TOK_PAC_SET TOK_PAC_TYPE TOK_PAC_TYPEOF TOK_PAC_CONST_DEF
%token TOK_END_PAC
%token TOK_EXTERN TOK_NULLPTR

%nonassoc '=' TOK_PLUSEQ
%left ';'
%left ','
%left '?' ':'
%left TOK_OR
%left TOK_AND
%nonassoc TOK_EQUAL TOK_NEQ TOK_LE TOK_GE '<' '>'
%left '&' '|' '^'
%left TOK_LSHIFT TOK_RSHIFT
%left '+' '-'
%left '*' '/' '%'
%right '~' '!'
%right TOK_SIZEOF TOK_OFFSETOF
%right '(' ')' '[' ']'
%left '.'

%type <actionparam> actionparam
%type <actionparamtype> actionparamtype
%type <aelem> sah
%type <aelemlist> sahlist conn flow
%type <attr> attr
%type <attrlist> optattrs attrlist
%type <caseexpr> caseexpr
%type <caseexprlist> caseexprlist
%type <casefield> casefield casefield0
%type <casefieldlist> casefieldlist
%type <contextfield> contextfield
%type <contextfieldlist> analyzercontext contextfieldlist
%type <decl> decl decl_with_attr decl_without_attr
%type <embedded_code> embedded_code
%type <enumlist> enumlist enumlist1
%type <enumitem> enumitem
%type <expr> expr caseindex optinit optlinebreaker
%type <exprlist> exprlist optexprlist optargs
%type <field> withinputfield letfield
%type <fieldlist> letfieldlist
%type <function> funcproto function
%type <id> TOK_ID tok_id optfieldid
%type <input> input
%type <nullp> TOK_NULLPTR
%type <num> TOK_NUMBER
%type <pacprimitive> embedded_pac_primitive
%type <param> param
%type <paramlist> optparams paramlist
%type <recordfield> recordfield recordfield0 padding
%type <recordfieldlist> recordfieldlist
%type <regex> regex
%type <statevar> statevar
%type <statevarlist> statevarlist
%type <str> TOK_EMBEDDED_STRING TOK_STRING TOK_REGEX
%type <cstr> cstr
%type <type> type type3 type2 type1 opttype
%type <val> TOK_EMBEDDED_ATOM TOK_WHEN TOK_FLOWDIR TOK_DATAUNIT

%{

#include "pac_action.h"
#include "pac_analyzer.h"
#include "pac_array.h"
#include "pac_attr.h"
#include "pac_case.h"
#include "pac_common.h"
#include "pac_conn.h"
#include "pac_context.h"
#include "pac_cstr.h"
#include "pac_dataptr.h"
#include "pac_dataunit.h"
#include "pac_dbg.h"
#include "pac_decl.h"
#include "pac_embedded.h"
#include "pac_enum.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_exttype.h"
#include "pac_flow.h"
#include "pac_func.h"
#include "pac_id.h"
#include "pac_inputbuf.h"
#include "pac_let.h"
#include "pac_nullptr.h"
#include "pac_output.h"
#include "pac_param.h"
#include "pac_paramtype.h"
#include "pac_primitive.h"
#include "pac_record.h"
#include "pac_redef.h"
#include "pac_regex.h"
#include "pac_state.h"
#include "pac_strtype.h"
#include "pac_type.h"
#include "pac_utils.h"
#include "pac_withinput.h"

extern int yyerror(const char msg[]);
extern int yylex();
extern int yychar;
extern char* yytext;
extern int yyleng;
extern void begin_RE();
extern void end_RE();

extern string input_filename;
extern int line_number;
extern Output* header_output;
extern Output* source_output;

%}

%union {
	ActionParam		*actionparam;
	ActionParamType		*actionparamtype;
	AnalyzerElement		*aelem;
	AnalyzerElementList	*aelemlist;
	Attr			*attr;
	AttrList		*attrlist;
	ConstString		*cstr;
	CaseExpr		*caseexpr;
	CaseExprList		*caseexprlist;
	CaseField		*casefield;
	CaseFieldList 		*casefieldlist;
	ContextField		*contextfield;
	ContextFieldList 	*contextfieldlist;
	Decl			*decl;
	EmbeddedCode		*embedded_code;
	Enum			*enumitem;
	EnumList		*enumlist;
	Expr			*expr;
	ExprList 		*exprlist;
	Field 			*field;
	FieldList 		*fieldlist;
	Function		*function;
	ID			*id;
	InputBuffer		*input;
	LetFieldList		*letfieldlist;
	LetField		*letfield;
	Nullptr			*nullp;
	Number			*num;
	PacPrimitive		*pacprimitive;
	Param 			*param;
	ParamList 		*paramlist;
	RecordFieldList 	*recordfieldlist;
	RecordField		*recordfield;
	RegEx			*regex;
	StateVar		*statevar;
	StateVarList		*statevarlist;
	const char		*str;
	Type 			*type;
	int			val;
}

%%

decls		:	/* empty */
				{
				// Put initialization here
				}
		|	decls  decl optsemicolon
				{
				}
		;

decl		:	decl_with_attr optattrs
				{
				$$ = $1;
				$1->AddAttrs($2);
				}
		|	decl_without_attr
				{
				$$ = $1;
				}
		;

decl_with_attr	:	TOK_TYPE tok_id { current_decl_id = $2; } optparams '=' type
				{
				TypeDecl* decl = new TypeDecl($2, $4, $6);
				$$ = decl;
				}
		|	TOK_LET tok_id { current_decl_id = $2; } opttype optinit
				{
				$$ = new LetDecl($2, $4, $5);
				}
		|	TOK_FUNCTION function
				{
				current_decl_id = $2->id();
				$$ = new FuncDecl($2);
				}
		|	TOK_ENUM tok_id { current_decl_id = $2; } '{' enumlist '}'
				{
				$$ = new EnumDecl($2, $5);
				}
		|	TOK_EXTERN TOK_TYPE tok_id { current_decl_id = $3; }
				{
				Type *extern_type = new ExternType($3, ExternType::PLAIN);
				$$ = new TypeDecl($3, 0, extern_type);
				}
		|	TOK_ANALYZER tok_id { current_decl_id = $2; } TOK_WITHCONTEXT analyzercontext
				{
				$$ = new AnalyzerContextDecl($2, $5);
				}
		|	TOK_ANALYZER tok_id { current_decl_id = $2; } optparams '{' conn '}'
				{
				$$ = new ConnDecl($2, $4, $6);
				}
		|	TOK_CONNECTION tok_id { current_decl_id = $2; } optparams '{' conn '}'
				{
				$$ = new ConnDecl($2, $4, $6);
				}
		|	TOK_FLOW tok_id { current_decl_id = $2; } optparams '{' flow '}'
				{
				$$ = new FlowDecl($2, $4, $6);
				}
		|	TOK_REFINE TOK_CASETYPE tok_id TOK_PLUSEQ '{' casefieldlist '}'
				{
				$$ = ProcessCaseTypeRedef($3, $6);
				}
		|	TOK_REFINE TOK_CASEFUNC tok_id TOK_PLUSEQ '{' caseexprlist '}'
				{
				$$ = ProcessCaseExprRedef($3, $6);
				}
		|	TOK_REFINE TOK_ANALYZER tok_id TOK_PLUSEQ '{' sahlist '}'
				{
				$$ = ProcessAnalyzerRedef($3, Decl::CONN, $6);
				}
		|	TOK_REFINE TOK_CONNECTION tok_id TOK_PLUSEQ '{' sahlist '}'
				{
				$$ = ProcessAnalyzerRedef($3, Decl::CONN, $6);
				}
		|	TOK_REFINE TOK_FLOW tok_id TOK_PLUSEQ '{' sahlist '}'
				{
				$$ = ProcessAnalyzerRedef($3, Decl::FLOW, $6);
				}
		;

decl_without_attr: 	TOK_LPB_HEADER embedded_code TOK_RPB
				{
				$$ = new HelperDecl(HelperDecl::HEADER, nullptr, $2);
				}
		|	TOK_LPB_CODE embedded_code TOK_RPB
				{
				$$ = new HelperDecl(HelperDecl::CODE, nullptr, $2);
				}
		|	TOK_LPB_EXTERN embedded_code TOK_RPB
				{
				$$ = new HelperDecl(HelperDecl::EXTERN, nullptr, $2);
				}
		|	TOK_REFINE TOK_TYPEATTR tok_id TOK_PLUSEQ attrlist
				{
				$$ = ProcessTypeAttrRedef($3, $5);
				}
		;

optsemicolon	:	/* nothing */
		|	';'
		;

tok_id		:	TOK_ID
				{
				$$ = $1;
				}
		|	TOK_CONNECTION
				{
				$$ = new ID("connection");
				}
		|	TOK_ANALYZER
				{
				$$ = new ID("analyzer");
				}
		|	TOK_FLOW
				{
				$$ = new ID("flow");
				}
		| 	TOK_FUNCTION
				{
				$$ = new ID("function");
				}
		|	TOK_TYPE
				{
				$$ = new ID("type");
				}
		;

analyzercontext :	'{' contextfieldlist '}'
				{
				$$ = $2;
				}
		;

contextfieldlist:	contextfieldlist contextfield ';'
				{
				$1->push_back($2);
				$$ = $1;
				}
		|	/* nothing */
				{
				$$ = new ContextFieldList();
				}
		;

contextfield	:	tok_id ':' type1
				{
				$$ = new ContextField($1, $3);
				}
		;

funcproto	:	tok_id '(' paramlist ')' ':' type2
				{
				$$ = new Function($1, $6, $3);
				}
		;

function	:	funcproto '=' expr
				{
				$1->set_expr($3);
				$$ = $1;
				}
		|	funcproto TOK_LPB embedded_code TOK_RPB
				{
				$1->set_code($3);
				$$ = $1;
				}
		|	funcproto ';'
				{
				$$ = $1;
				}
		;

optparams	:	'(' paramlist ')'
				{
				$$ = $2;
				}
		|	/* empty */
				{
				$$ = nullptr;
				}
		;

paramlist	:	paramlist ',' param
				{
				$1->push_back($3);
				$$ = $1;
				}
		|	param
				{
				$$ = new ParamList();
				$$->push_back($1);
				}
		|	/* empty */
				{
				$$ = new ParamList();
				}
		;

param		:	tok_id ':' type2
				{
				$$ = new Param($1, $3);
				}
		;

optinit		:	/* nothing */
				{
				$$ = nullptr;
				}
		|	'=' expr
				{
				$$ = $2;
				}
		;

opttype		:	/* nothing */
				{
				$$ = nullptr;
				}
		|	':' type2
				{
				$$ = $2;
				}
		;

type		: 	type3
				{
				$$ = $1;
				}
		;

/* type3 is for record or type2 */
type3		:	type2
				{
				$$ = $1;
				}
		|	TOK_RECORD '{' recordfieldlist '}'
				{
				$$ = new RecordType($3);
				}
		;

/* type2 is for array or case or type1 */
type2		:	type1
				{
				$$ = $1;
				}
		|	type1 '[' expr ']'
				{
				$$ = new ArrayType($1, $3);
				}
		|	type1 '[' ']'
				{
				$$ = new ArrayType($1);
				}
		|	TOK_CASE caseindex TOK_OF '{' casefieldlist '}'
				{
				$$ = new CaseType($2, $5);
				}
		;

/* type1 is for built-in, parameterized, or string types */
type1		: 	tok_id
				{
				$$ = Type::LookUpByID($1);
				}
		|	tok_id '(' exprlist ')'
				{
				$$ = new ParameterizedType($1, $3);
				}
		|	regex
				{
				$$ = new StringType($1);
				}
		|	cstr
				{
				$$ = new StringType($1);
				}
		;

recordfieldlist	:	recordfieldlist recordfield ';'
				{
				$1->push_back($2);
				$$ = $1;
				}
		|	/* empty */
				{
				$$ = new RecordFieldList();
				}
		;

recordfield	: 	recordfield0 optattrs
				{
				$1->AddAttr($2);
				$$ = $1;
				}
		;

recordfield0	:	optfieldid type2
				{
				$$ = new RecordDataField($1, $2);
				}
		|	padding
				{
				$$ = $1;
				}
		;

padding		:	optfieldid TOK_PADDING '[' expr ']'
				{
				$$ = new RecordPaddingField(
					$1, PAD_BY_LENGTH, $4);
				}
		|	optfieldid TOK_PADDING TOK_TO expr
				{
				$$ = new RecordPaddingField(
					$1, PAD_TO_OFFSET, $4);
				}
		|	optfieldid TOK_PADDING TOK_ALIGN expr
				{
				$$ = new RecordPaddingField(
					$1, PAD_TO_NEXT_WORD, $4);
				}
		;

optfieldid	:	tok_id ':'
				{
				$$ = $1;
				}
		|	':'
				{
				$$ = ID::NewAnonymousID("anonymous_field_");
				}
		;

caseindex	:	expr
				{
				$$ = $1;
				}
		;

casefieldlist	:	casefieldlist casefield ';'
				{
				$1->push_back($2);
				$$ = $1;
				}
		|	/* empty */
				{
				$$ = new CaseFieldList();
				}
		;

casefield	:	casefield0 optattrs
				{
				$1->AddAttr($2);
				$$ = $1;
				}
		;

casefield0	:	exprlist TOK_RIGHTARROW tok_id ':' type2
				{
				$$ = new CaseField($1, $3, $5);
				}
		|	TOK_DEFAULT TOK_RIGHTARROW tok_id ':' type2
				{
				$$ = new CaseField(nullptr, $3, $5);
				}
		;

optexprlist	:	/* nothing */
				{
				$$ = nullptr;
				}
		|	exprlist
				{
				$$ = $1;
				}
		;

exprlist	:	exprlist ',' expr
				{
				$1->push_back($3);
				$$ = $1;
				}
		|	expr
				{
				$$ = new ExprList();
				$$->push_back($1);
				}
		;

expr		:	tok_id
				{
				$$ = new Expr($1);
				}
		|	TOK_NUMBER
				{
				$$ = new Expr($1);
				}
		|	TOK_NULLPTR
				{
				$$ = new Expr($1);
				}
		|	expr '[' expr ']'
				{
				$$ = new Expr(Expr::EXPR_SUBSCRIPT, $1, $3);
				}
		|	expr '.' tok_id
				{
				$$ = new Expr(Expr::EXPR_MEMBER, $1, new Expr($3));
				}
		|	TOK_SIZEOF '(' tok_id ')'
				{
				$$ = new Expr(Expr::EXPR_SIZEOF, new Expr($3));
				}
		|	TOK_OFFSETOF '(' tok_id ')'
				{
				$$ = new Expr(Expr::EXPR_OFFSETOF, new Expr($3));
				}
		|	'(' expr ')'
				{
				$$ = new Expr(Expr::EXPR_PAREN, $2);
				}
		|	expr '(' optexprlist ')'
				{
				$$ = new Expr(Expr::EXPR_CALL,
				              $1,
				              new Expr($3));
				}
		|	'-' expr
				{
				$$ = new Expr(Expr::EXPR_NEG, $2);
				}
		|	expr '+' expr
				{
				$$ = new Expr(Expr::EXPR_PLUS, $1, $3);
				}
		|	expr '-' expr
				{
				$$ = new Expr(Expr::EXPR_MINUS, $1, $3);
				}
		|	expr '*' expr
				{
				$$ = new Expr(Expr::EXPR_TIMES, $1, $3);
				}
		|	expr '/' expr
				{
				$$ = new Expr(Expr::EXPR_DIV, $1, $3);
				}
		|	expr '%' expr
				{
				$$ = new Expr(Expr::EXPR_MOD, $1, $3);
				}
		|	'~' expr
				{
				$$ = new Expr(Expr::EXPR_BITNOT, $2);
				}
		|	expr '&' expr
				{
				$$ = new Expr(Expr::EXPR_BITAND, $1, $3);
				}
		|	expr '|' expr
				{
				$$ = new Expr(Expr::EXPR_BITOR, $1, $3);
				}
		|	expr '^' expr
				{
				$$ = new Expr(Expr::EXPR_BITXOR, $1, $3);
				}
		|	expr TOK_LSHIFT expr
				{
				$$ = new Expr(Expr::EXPR_LSHIFT, $1, $3);
				}
		|	expr TOK_RSHIFT expr
				{
				$$ = new Expr(Expr::EXPR_RSHIFT, $1, $3);
				}
		|	expr TOK_EQUAL expr
				{
				$$ = new Expr(Expr::EXPR_EQUAL, $1, $3);
				}
		|	expr TOK_NEQ expr
				{
				$$ = new Expr(Expr::EXPR_NEQ, $1, $3);
				}
		|	expr TOK_GE expr
				{
				$$ = new Expr(Expr::EXPR_GE, $1, $3);
				}
		|	expr TOK_LE expr
				{
				$$ = new Expr(Expr::EXPR_LE, $1, $3);
				}
		|	expr '>' expr
				{
				$$ = new Expr(Expr::EXPR_GT, $1, $3);
				}
		|	expr '<' expr
				{
				$$ = new Expr(Expr::EXPR_LT, $1, $3);
				}
		|	'!' expr
				{
				$$ = new Expr(Expr::EXPR_NOT, $2);
				}
		|	expr TOK_AND expr
				{
				$$ = new Expr(Expr::EXPR_AND, $1, $3);
				}
		|	expr TOK_OR expr
				{
				$$ = new Expr(Expr::EXPR_OR, $1, $3);
				}
		|	expr '?' expr ':' expr
				{
				$$ = new Expr(Expr::EXPR_COND, $1, $3, $5);
				}
		|	TOK_CASE expr TOK_OF '{' caseexprlist '}'
				{
				$$ = new Expr($2, $5);
				}
		|	cstr
				{
				$$ = new Expr($1);
				}
		|	regex
				{
				$$ = new Expr($1);
				}
		;

cstr		:	TOK_STRING
				{
				$$ = new ConstString($1);
				}
		;

regex		: 	TOK_BEGIN_RE TOK_REGEX TOK_END_RE
				{
				$$ = new RegEx($2);
				}
		;

caseexprlist	:	/* nothing */
				{
				$$ = new CaseExprList();
				}
		|	caseexprlist caseexpr ';'
				{
				$1->push_back($2);
				$$ = $1;
				}
		;

caseexpr	:	exprlist TOK_RIGHTARROW expr
				{
				$$ = new CaseExpr($1, $3);
				}
		|	TOK_DEFAULT TOK_RIGHTARROW expr
				{
				$$ = new CaseExpr(nullptr, $3);
				}
		;

enumlist	: 	enumlist1
				{
				$$ = $1;
				}
		|	enumlist1 ','
				{
				$$ = $1;
				}
		;

enumlist1	:	enumlist1 ',' enumitem
				{
				$1->push_back($3);
				$$ = $1;
				}
		|	enumitem
				{
				$$ = new EnumList();
				$$->push_back($1);
				}
		;

enumitem	:	tok_id
				{
				$$ = new Enum($1);
				}
		|	tok_id '=' expr
				{
				$$ = new Enum($1, $3);
				}
		;

conn		:	sahlist
				{
				$$ = $1;
				}
		;

flow		:	sahlist
				{
				$$ = $1;
				}
		;

/* State-Action-Helper List */
sahlist		:	/* empty */
				{
				$$ = new AnalyzerElementList();
				}
		|	sahlist sah
				{
				$1->push_back($2);
				$$ = $1;
				}
		;

sah		:	TOK_LPB_MEMBER embedded_code TOK_RPB
				{
				$$ = new AnalyzerHelper(AnalyzerHelper::MEMBER_DECLS, $2);
				}
		|	TOK_LPB_INIT embedded_code TOK_RPB
				{
				$$ = new AnalyzerHelper(AnalyzerHelper::INIT_CODE, $2);
				}
		|	TOK_LPB_CLEANUP embedded_code TOK_RPB
				{
				$$ = new AnalyzerHelper(AnalyzerHelper::CLEANUP_CODE, $2);
				}
		|	TOK_LPB_EOF embedded_code TOK_RPB
				{
				$$ = new AnalyzerHelper(AnalyzerHelper::EOF_CODE, $2);
				}
		|	TOK_FLOWDIR '=' tok_id optargs ';'
				{
				$$ = new AnalyzerFlow((AnalyzerFlow::Direction) $1, $3, $4);
				}
		|	TOK_DATAUNIT '=' tok_id optargs TOK_WITHCONTEXT '(' optexprlist ')' ';'
				{
				$$ = new AnalyzerDataUnit(
					(AnalyzerDataUnit::DataUnitType) $1,
					$3,
					$4,
					$7);
				}
		|	TOK_FUNCTION function
				{
				$$ = new AnalyzerFunction($2);
				}
		|	TOK_STATE '{' statevarlist '}'
				{
				$$ = new AnalyzerState($3);
				}
		|	TOK_ACTION tok_id TOK_WHEN '(' actionparam ')' TOK_LPB embedded_code TOK_RPB
				{
				$$ = new AnalyzerAction($2, (AnalyzerAction::When) $3, $5, $8);
				}
		;

statevarlist	:	/* empty */
				{
				$$ = new StateVarList();
				}
		|	statevarlist statevar ';'
				{
				$1->push_back($2);
				$$ = $1;
				}
		;

statevar	:	tok_id ':' type1
				{
				$$ = new StateVar($1, $3);
				}
		;

actionparam	:	tok_id TOK_LE actionparamtype
				{
				$$ = new ActionParam($1, $3);
				}
		;

actionparamtype :	tok_id
				{
				$$ = new ActionParamType($1);
				}
		|	tok_id '.' tok_id
				{
				$$ = new ActionParamType($1, $3);
				}
		;

embedded_code	:	/* empty */
				{
				$$ = new EmbeddedCode();
				}
		|	embedded_code TOK_EMBEDDED_ATOM
				{
				$1->Append($2);
				$$ = $1;
				}
		|	embedded_code TOK_EMBEDDED_STRING
				{
				$1->Append($2);
				$$ = $1;
				}
		|	embedded_code embedded_pac_primitive
				{
				$1->Append($2);
				$$ = $1;
				}
		;

embedded_pac_primitive:	TOK_PAC_VAL expr TOK_END_PAC
				{
				$$ = new PPVal($2);
				}
		|	TOK_PAC_SET expr TOK_END_PAC
				{
				$$ = new PPSet($2);
				}
		|	TOK_PAC_TYPE expr TOK_END_PAC
				{
				$$ = new PPType($2);
				}
		|	TOK_PAC_CONST_DEF tok_id '=' expr TOK_END_PAC
				{
				$$ = new PPConstDef($2, $4);
				}
		;

optargs		:	/* empty */
				{
				$$ = nullptr;
				}
		|	'(' optexprlist ')'
				{
				$$ = $2;
				}
		;

letfieldlist	:	letfieldlist letfield ';'
				{
				$1->push_back($2);
				$$ = $1;
				}
		|	letfieldlist withinputfield ';'
				{
				$1->push_back($2);
				$$ = $1;
				}
		|	/* empty */
				{
				$$ = new FieldList();
				}
		;

letfield	:	tok_id opttype optinit optattrs
				{
				$$ = new LetField($1, $2, $3);
				$$->AddAttr($4);
				}
		;

withinputfield	:	tok_id ':' type1 TOK_WITHINPUT input optattrs
				{
				$$ = new WithInputField($1, $3, $5);
				$$->AddAttr($6);
				}
		;

/* There can be other forms of input */
input		:	expr
				{
				$$ = new InputBuffer($1);
				}
		;

optattrs	:	/* empty */
				{
				$$ = nullptr;
				}
		|	attrlist
				{
				$$ = $1;
				}
		;

attrlist	:	attrlist optcomma attr
				{
				if ( $3 )
					$1->push_back($3);
				$$ = $1;
				}
		|	attr
				{
				$$ = new AttrList();
				if ( $1 )
					$$->push_back($1);
				}
		;

optcomma	:	/* nothing */
		|	','
		;

attr		:	TOK_ATTR_BYTEORDER '=' expr
				{
				$$ = new Attr(ATTR_BYTEORDER, $3);
				}
		|	TOK_ATTR_CHECK expr
				{
				$$ = new Attr(ATTR_CHECK, $2);
				}
		|	TOK_ATTR_CHUNKED
				{
				$$ = new Attr(ATTR_CHUNKED);
				}
		|	TOK_ATTR_ENFORCE expr
				{
				$$ = new Attr(ATTR_ENFORCE, $2);
				}
		|	TOK_ATTR_EXPORTSOURCEDATA
				{
				$$ = new Attr(ATTR_EXPORTSOURCEDATA);
				}
		|	TOK_ATTR_IF expr
				{
				$$ = new Attr(ATTR_IF, $2);
				}
		|	TOK_ATTR_LENGTH '=' expr
				{
				$$ = new Attr(ATTR_LENGTH, $3);
				}
		|	TOK_ATTR_LET '{' letfieldlist '}'
				{
				$$ = new LetAttr($3);
				}
		|	TOK_ATTR_LINEBREAKER '=' expr
				{
				$$ = new Attr(ATTR_LINEBREAKER, $3);
				}
		|	TOK_ATTR_MULTILINE '(' expr ')'
				{
				$$ = new Attr(ATTR_MULTILINE, $3);
				}
		|	TOK_ATTR_ONELINE optlinebreaker
				{
				$$ = new Attr(ATTR_ONELINE, $2);
				}
		|	TOK_ATTR_REFCOUNT
				{
				$$ = new Attr(ATTR_REFCOUNT);
				}
		|	TOK_ATTR_REQUIRES '(' optexprlist ')'
				{
				$$ = new Attr(ATTR_REQUIRES, $3);
				}
		|	TOK_ATTR_RESTOFDATA
				{
				$$ = new Attr(ATTR_RESTOFDATA);
				}
		|	TOK_ATTR_RESTOFFLOW
				{
				$$ = new Attr(ATTR_RESTOFFLOW);
				}
		|	TOK_ATTR_TRANSIENT
				{
				$$ = new Attr(ATTR_TRANSIENT);
				}
		|	TOK_ATTR_UNTIL expr
				{
				$$ = new Attr(ATTR_UNTIL, $2);
				}
		;

optlinebreaker	:	/* nothing */
				{
				$$ = nullptr;
				}
		|	'(' expr ')'
				{
				$$ = $2;
				}
		;

%%

const ID* current_decl_id = nullptr;

int yyerror(const char msg[]) {
    auto n = strlen(msg) + yyleng + 64;
    char* msgbuf = new char[n];

    if ( ! yychar || ! yytext || yytext[0] == '\0' )
        snprintf(msgbuf, n, "%s, at end of file", msg);

    else if ( yytext[0] == '\n' )
        snprintf(msgbuf, n, "%s, on previous line", msg);

    else
        snprintf(msgbuf, n, "%s, at or near \"%s\"", msg, yytext);

    /*
    extern int column;
    sprintf(msgbuf, "%*s\n%*s\n", column, "^", column, msg);
    */

    if ( ! input_filename.empty() )
        fprintf(stderr, "%s:%d: ", input_filename.c_str(), line_number);
    else
        fprintf(stderr, "line %d: ", line_number);
    fprintf(stderr, "%s", msgbuf);
    fprintf(stderr, " (yychar=%d)", yychar);
    fprintf(stderr, "\n");

    delete[] msgbuf;
    return 0;
}

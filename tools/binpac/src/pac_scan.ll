%{
#include "pac_action.h"
#include "pac_array.h"
#include "pac_attr.h"
#include "pac_case.h"
#include "pac_common.h"
#include "pac_conn.h"
#include "pac_dataptr.h"
#include "pac_dataunit.h"
#include "pac_dbg.h"
#include "pac_decl.h"
#include "pac_exception.h"
#include "pac_expr.h"
#include "pac_flow.h"
#include "pac_id.h"
#include "pac_number.h"
#include "pac_output.h"
#include "pac_param.h"
#include "pac_parse.h"
#include "pac_record.h"
#include "pac_type.h"
#include "pac_utils.h"

#include <errno.h>
#include <string_view>

#ifdef _MSC_VER
#include <filesystem>
#else
#include <libgen.h>
#include <memory>
#endif

int line_number = 1;

int begin_pac_primitive(int tok);
int end_pac_primitive();

int string_token(int tok)
	{
	yylval.str = copy_string(yytext);
	return tok;
	}

int char_token(int tok)
	{
	yylval.val = yytext[0];
	return tok;
	}

void include_file(const char *filename);

std::string do_dirname(std::string_view s)
	{
#ifdef _MSC_VER
	return std::filesystem::path(s).parent_path().string();
#else
	std::unique_ptr<char[]> tmp{new char[s.size()+1]};
	strncpy(tmp.get(), s.data(), s.size());
	tmp[s.size()] = '\0';

	char* dn = dirname(tmp.get());
	if ( !dn )
		return "";

	std::string res{dn};

	return res;
#endif
	}
%}

/* EC -- embedded code state */
/* PP -- PAC primitive state */
/* INCL -- @include line */

%s EC INCL PP RE

WS	[ \t]+
ID	[A-Za-z_][A-Za-z_0-9]*
D	[0-9]+
HEX	[0-9a-fA-F]+
FILE	[^ \t\n]+
ESCSEQ	(\\([^\n]|[0-7]{3}|x[[:xdigit:]]{2}))

%option nounput

%%

<INITIAL>"%include"		{
				BEGIN(INCL);
				}

<INCL>{WS}			/* skip whitespace */

<INCL>{FILE}			{
				BEGIN(INITIAL);
				include_file(yytext);
				}

<INITIAL>"%extern{"		{
				BEGIN(EC);
				return TOK_LPB_EXTERN;
				}
<INITIAL>"%header{"		{
				BEGIN(EC);
				return TOK_LPB_HEADER;
				}
<INITIAL>"%code{"		{
				BEGIN(EC);
				return TOK_LPB_CODE;
				}
<INITIAL>"%init{"		{
				BEGIN(EC);
				return TOK_LPB_INIT;
				}
<INITIAL>"%cleanup{"		{
				BEGIN(EC);
				return TOK_LPB_CLEANUP;
				}
<INITIAL>"%member{"		{
				BEGIN(EC);
				return TOK_LPB_MEMBER;
				}
<INITIAL>"%eof{"		{
				BEGIN(EC);
				return TOK_LPB_EOF;
				}
<INITIAL>"%{"			{
				BEGIN(EC);
				return TOK_LPB;
				}
<EC>"%}"			{
				BEGIN(INITIAL);
				return TOK_RPB;
				}

<EC>"${"			return begin_pac_primitive(TOK_PAC_VAL);
<EC>"$set{"			return begin_pac_primitive(TOK_PAC_SET); 
<EC>"$type{"			return begin_pac_primitive(TOK_PAC_TYPE);
<EC>"$typeof{"			return begin_pac_primitive(TOK_PAC_TYPEOF);
<EC>"$const_def{"		return begin_pac_primitive(TOK_PAC_CONST_DEF);

<EC>"//".*			return string_token(TOK_EMBEDDED_STRING);
<EC>.				return char_token(TOK_EMBEDDED_ATOM);
<EC>\n				{ ++line_number; return char_token(TOK_EMBEDDED_ATOM); }

<PP>"}"				return end_pac_primitive();

<INITIAL,PP>\n			++line_number;
<INITIAL>#.*			/* eat comments */
<INITIAL,PP>{WS}		/* eat whitespace */

<INITIAL>"RE/"			{
				BEGIN(RE);
				return TOK_BEGIN_RE;
				}

<RE>([^/\\\n]|{ESCSEQ})+	return string_token(TOK_REGEX);

<RE>"/"				{
				BEGIN(INITIAL);
				return TOK_END_RE;
				}

<RE>[\\\n]			return yytext[0];

<INITIAL>analyzer		return TOK_ANALYZER;
<INITIAL>enum			return TOK_ENUM;
<INITIAL>extern			return TOK_EXTERN;
<INITIAL>flow			return TOK_FLOW;
<INITIAL>function		return TOK_FUNCTION;
<INITIAL>let			return TOK_LET;
<INITIAL>refine			return TOK_REFINE;
<INITIAL>type			return TOK_TYPE;

<INITIAL>align			return TOK_ALIGN;
<INITIAL>case			return TOK_CASE;
<INITIAL>casefunc		return TOK_CASEFUNC;
<INITIAL>casetype		return TOK_CASETYPE;
<INITIAL>connection		return TOK_CONNECTION;
<INITIAL>datagram		{
				yylval.val = AnalyzerDataUnit::DATAGRAM;
				return TOK_DATAUNIT;
				}
<INITIAL>default 		return TOK_DEFAULT;
<INITIAL>downflow		{
				yylval.val = AnalyzerFlow::DOWN;
				return TOK_FLOWDIR;
				}
<INITIAL>flowunit		{
				yylval.val = AnalyzerDataUnit::FLOWUNIT;
				return TOK_DATAUNIT;
				}
<INITIAL>of			return TOK_OF;
<INITIAL>offsetof 		return TOK_OFFSETOF;
<INITIAL>padding		return TOK_PADDING;
<INITIAL>record			return TOK_RECORD;
<INITIAL>sizeof			return TOK_SIZEOF;
<INITIAL>to			return TOK_TO;
<INITIAL>typeattr		return TOK_TYPEATTR;
<INITIAL>upflow			{
				yylval.val = AnalyzerFlow::UP;
				return TOK_FLOWDIR;
				}
<INITIAL>withcontext		return TOK_WITHCONTEXT;
<INITIAL>withinput		return TOK_WITHINPUT;

<INITIAL>&also			return TOK_ATTR_ALSO;
<INITIAL>&byteorder		return TOK_ATTR_BYTEORDER;
<INITIAL>&check			{
	fprintf(stderr,
	        "warning in %s:%d: &check is a deprecated no-op, use &enforce\n",
	        input_filename.c_str(), line_number);
	return TOK_ATTR_CHECK;
	}
<INITIAL>&chunked		return TOK_ATTR_CHUNKED;
<INITIAL>&enforce			return TOK_ATTR_ENFORCE;
<INITIAL>&exportsourcedata	return TOK_ATTR_EXPORTSOURCEDATA;
<INITIAL>&if			return TOK_ATTR_IF;
<INITIAL>&length		return TOK_ATTR_LENGTH;
<INITIAL>&let			return TOK_ATTR_LET;
<INITIAL>&linebreaker		return TOK_ATTR_LINEBREAKER;
<INITIAL>&oneline		return TOK_ATTR_ONELINE;
<INITIAL>&refcount		return TOK_ATTR_REFCOUNT;
<INITIAL>&requires		return TOK_ATTR_REQUIRES;
<INITIAL>&restofdata		return TOK_ATTR_RESTOFDATA;
<INITIAL>&restofflow		return TOK_ATTR_RESTOFFLOW;
<INITIAL>&transient		return TOK_ATTR_TRANSIENT;
<INITIAL>&until			return TOK_ATTR_UNTIL;

<INITIAL,PP>"0x"{HEX}		{
				int n;
				sscanf(yytext + 2, "%x", &n);
				yylval.num = new Number(yytext, n);
				return TOK_NUMBER;
				}

<INITIAL,PP>{D}			{
				int n;
				sscanf(yytext, "%d", &n);
				yylval.num = new Number(yytext, n);
				return TOK_NUMBER;
				}

<INITIAL,PP>{ID}(::{ID})*	{
				yylval.id = new ID(yytext);
				return TOK_ID;
				}

<INITIAL>"$"{ID}		{
				yylval.id = new ID(yytext);
				return TOK_ID;
				}

<INITIAL>\"([^\\\n\"]|{ESCSEQ})*\" return string_token(TOK_STRING);

<INITIAL,PP>"=="		return TOK_EQUAL;
<INITIAL,PP>"!="		return TOK_NEQ;
<INITIAL,PP>">="		return TOK_GE;
<INITIAL,PP>"<="		return TOK_LE;
<INITIAL,PP>"<<"		return TOK_LSHIFT;
<INITIAL,PP>">>"		return TOK_RSHIFT;
<INITIAL,PP>"&&"		return TOK_AND;
<INITIAL,PP>"||"		return TOK_OR;
<INITIAL,PP>"+="		return TOK_PLUSEQ;
<INITIAL>"->"			return TOK_RIGHTARROW;

<INITIAL,PP>[\.!%*/+\-&|\^,:;<=>?()\[\]{}~]	return yytext[0];

%%

void begin_RE()
	{
	BEGIN(RE);
	}

void end_RE()
	{
	BEGIN(INITIAL);
	}

// The DECL state is deprecated
void begin_decl()
	{
	// BEGIN(DECL);
	}

void end_decl()
	{
	// BEGIN(INITIAL);
	}

int begin_pac_primitive(int tok)
	{
	BEGIN(PP);
	return tok;
	}

int end_pac_primitive()
	{
	BEGIN(EC);
	return TOK_END_PAC;
	}

const int MAX_INCLUDE_DEPTH = 100;

struct IncludeState {
	YY_BUFFER_STATE yystate;
	string input_filename;
	int line_number;
};

IncludeState include_stack[MAX_INCLUDE_DEPTH];
int include_stack_ptr = 0;

void switch_to_file(FILE *fp)
	{
	yy_switch_to_buffer(yy_create_buffer(fp, YY_BUF_SIZE));
	}

void switch_to_file(const char *filename)
	{
	if ( include_stack_ptr >= MAX_INCLUDE_DEPTH )
		{
		fprintf( stderr, "Includes nested too deeply" );
		exit( 1 );
		}

	IncludeState state = 
		{ YY_CURRENT_BUFFER, input_filename, line_number };
	include_stack[include_stack_ptr++] = state;

	FILE *fp = fopen(filename, "r");

	if ( ! fp )
		{
		fprintf(stderr, "%s:%d: error: cannot include file \"%s\"\n", 
			input_filename.c_str(), line_number,filename);
		exit( 1 );
		}

	yyin = fp;
	input_filename = string(filename);
	line_number = 1;
	switch_to_file(yyin);
	if ( !FLAGS_quiet )
		fprintf(stderr, "switching to file %s\n", input_filename.c_str());
	}

void include_file(const char *filename)
	{
	ASSERT(filename);

	string full_filename;
	if ( filename[0] == '/' )
		full_filename = filename;
	else if ( filename[0] == '.' )
		{
		string dir = do_dirname(input_filename);

		if ( ! dir.empty() )
			full_filename = dir + "/" + filename;
		else
			{
			fprintf(stderr, "%s:%d error: cannot include file \"%s\": %s\n",
					input_filename.c_str(), line_number, filename,
					strerror(errno));
			exit( 1 );
			}
		}
	else
		{
		int i;
		for ( i = 0; i < (int) FLAGS_include_directories.size(); ++i )
			{
			full_filename = FLAGS_include_directories[i] + filename;
			DEBUG_MSG("Try include file: \"%s\"\n", 
				full_filename.c_str());
			if ( access(full_filename.c_str(), R_OK) == 0 )
				break;
			}
		if ( i >= (int) FLAGS_include_directories.size() )
			full_filename = filename;
		}

	switch_to_file(full_filename.c_str());
	}

int yywrap()
	{
	yy_delete_buffer(YY_CURRENT_BUFFER);
	--include_stack_ptr;
	if ( include_stack_ptr < 0 )
		return 1;

	IncludeState state = include_stack[include_stack_ptr];
	yy_switch_to_buffer(state.yystate);
	input_filename = state.input_filename;
	line_number = state.line_number;
	return 0;
	}

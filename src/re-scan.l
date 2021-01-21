/* scan.l - scanner for Bro regular expressions */

/*
 * See the file "COPYING" in the main distribution directory for copyright.
 */

%{
#include "zeek/RE.h"
#include "zeek/CCL.h"
#include "zeek/NFA.h"
#include "zeek/util.h"

#define yylval RE_lval

#include "re-parse.h"

const char* zeek::detail::RE_parse_input = nullptr;

#define RET_CCE(func) \
	BEGIN(SC_CCL); \
	yylval.cce_val = func; \
	return TOK_CCE;

// We need the following because isblank() is not globally available.
static int my_isblank(int c)	{ return c == ' ' || c == '\t'; }

// And the following so we have portability to systems where these are
// defined as macros.
static int my_isalnum(int c)	{ return isalnum(c); }
static int my_isalpha(int c)	{ return isalpha(c); }
static int my_iscntrl(int c)	{ return iscntrl(c); }
static int my_isdigit(int c)	{ return isdigit(c); }
static int my_isgraph(int c)	{ return isgraph(c); }
static int my_islower(int c)	{ return islower(c); }
static int my_isupper(int c)	{ return isupper(c); }
static int my_isprint(int c)	{ return isprint(c); }
static int my_ispunct(int c)	{ return ispunct(c); }
static int my_isspace(int c)	{ return isspace(c); }
static int my_isxdigit(int c)	{ return isxdigit(c); }
%}

%option caseless nodefault nostdinit noyywrap

%x SC_NUM SC_QUOTE SC_FIRST_CCL SC_CCL

NAME		([[:alpha:]_][[:alnum:]_-]*)

ESCSEQ		(\\([^\n]|[0-7]+|x[[:xdigit:]]{2}))

FIRST_CCL_CHAR	([^\\\n]|{ESCSEQ})
CCL_CHAR	([^\\\n\]]|{ESCSEQ})
CCL_EXPR	("[:"[[:alpha:]]+":]")

%%

<INITIAL>{
	"^"		return '^';
	\"		BEGIN(SC_QUOTE); return '"';
	"{"/[[:digit:]]	BEGIN(SC_NUM); return '{';
	"$"		return '$';

	"["({FIRST_CCL_CHAR}|{CCL_EXPR})({CCL_CHAR}|{CCL_EXPR})*	{
			zeek::detail::curr_ccl = zeek::detail::rem->LookupCCL(yytext);
			if ( zeek::detail::curr_ccl )
				{
				if ( yyinput() != ']' )
					zeek::detail::synerr("bad character class");
				yylval.ccl_val = zeek::detail::curr_ccl;
				return TOK_CCL;
				}
			else
				{
				zeek::detail::curr_ccl = new zeek::detail::CCL();
				zeek::detail::rem->InsertCCL(yytext, zeek::detail::curr_ccl);

				// Push back everything but the leading bracket
				// so the ccl can be rescanned.
				yyless(1);

				BEGIN(SC_FIRST_CCL);
				return '[';
				}
			}

	"{"{NAME}"}"	{
			char* nmstr = zeek::util::copy_string(yytext+1);
			nmstr[yyleng - 2] = '\0';  // chop trailing brace

			std::string namedef = zeek::detail::rem->LookupDef(nmstr);
			delete nmstr;

			if ( namedef.empty() )
				zeek::detail::synerr("undefined definition");
			else
				{ // push back name surrounded by ()'s
				int len = namedef.size();

				if ( namedef[0] == '^' ||
				     (len > 0 && namedef[len - 1] == '$') )
					{ // don't use ()'s after all
					for ( int i = len - 1; i >= 0; --i )
						unput(namedef[i]);

					if ( namedef[0] == '^' )
						yy_set_bol(1);
					}

				else
					{
					unput(')');
					for ( int i = len - 1; i >= 0; --i )
						unput(namedef[i]);
					unput('(');
					}
				}
			}

	"(?i:"		zeek::detail::case_insensitive = 1; return TOK_CASE_INSENSITIVE;

	[a-zA-Z]	{
			if ( zeek::detail::case_insensitive )
				{
				char c = yytext[0];	// unput trashes yytext!
				// Push back the character inside a CCL,
				// so the parser can then expand it.
				unput(']');
				unput(c);
				unput('[');
				}
			else
				{
				yylval.int_val = yytext[0];
				return TOK_CHAR;
				}
			}

	[|*+?.(){}]	return yytext[0];
	.		yylval.int_val = yytext[0]; return TOK_CHAR;
	\n		return 0;	// treat as end of pattern
}

<SC_QUOTE>{
	[^"\n]$		zeek::detail::synerr("missing quote"); return '"';
	[^"\n]		yylval.int_val = yytext[0]; return TOK_CHAR;
	\"		BEGIN(INITIAL); return '"';
}

<SC_FIRST_CCL>{
	"^"/[^-\]\n]	BEGIN(SC_CCL); return '^';
	"^"/("-"|"]")	return '^';
	.		BEGIN(SC_CCL); yylval.int_val = yytext[0]; return TOK_CHAR;
}

<SC_CCL>{
	-/[^\]\n]	return '-';
	[^\]\n]		yylval.int_val = yytext[0]; return TOK_CHAR;
	"]"		BEGIN(INITIAL); return ']';
	[^\]]$		{
			zeek::detail::synerr("bad character class");
			BEGIN(INITIAL);
			return ']';
			}
}

<SC_FIRST_CCL,SC_CCL>{
	"[:alnum:]"	RET_CCE(my_isalnum)
	"[:alpha:]"	RET_CCE(my_isalpha)
	"[:blank:]"	RET_CCE(my_isblank)
	"[:cntrl:]"	RET_CCE(my_iscntrl)
	"[:digit:]"	RET_CCE(my_isdigit)
	"[:graph:]"	RET_CCE(my_isgraph)
	"[:print:]"	RET_CCE(my_isprint)
	"[:punct:]"	RET_CCE(my_ispunct)
	"[:space:]"	RET_CCE(my_isspace)
	"[:xdigit:]"	RET_CCE(my_isxdigit)

	"[:lower:]"	{
			BEGIN(SC_CCL);
			yylval.cce_val =
				zeek::detail::case_insensitive ? my_isalpha : my_islower;
			return TOK_CCE;
			}

	"[:upper:]"	{
			BEGIN(SC_CCL);
			yylval.cce_val =
				zeek::detail::case_insensitive ? my_isalpha : my_isupper;
			return TOK_CCE;
			}

	{CCL_EXPR}	{
			zeek::detail::synerr("bad character class expression");
			BEGIN(SC_CCL);
			yylval.cce_val = my_isalnum;
			return TOK_CCE;
			}
}

<SC_NUM>{
	[[:digit:]]+	yylval.int_val = atoi(yytext); return TOK_NUMBER;

	","		return ',';
	"}"		BEGIN(INITIAL); return '}';

	.		{
			zeek::detail::synerr("bad character inside {}'s");
			BEGIN(INITIAL);
			return '}';
			}
}

<INITIAL,SC_QUOTE,SC_FIRST_CCL,SC_CCL>{ESCSEQ}	{
			const char* esc_text = yytext + 1;
			yylval.int_val = zeek::util::detail::expand_escape(esc_text);

			if ( YY_START == SC_FIRST_CCL )
				BEGIN(SC_CCL);

			return TOK_CHAR;
			}

<*>.|\n			zeek::detail::synerr("bad character");

%%

YY_BUFFER_STATE RE_buf;

void RE_set_input(const char* str)
	{
	zeek::detail::RE_parse_input = str;
	RE_buf = yy_scan_string(str);
	}

void RE_done_with_scan()
	{
	yy_delete_buffer(RE_buf);
	}

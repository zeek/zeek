/* scan.l - scanner for Bro regular expressions */

/*
 * See the file "COPYING" in the main distribution directory for copyright.
 */

%{
#include "CCL.h"
#include "NFA.h"
#include "util.h"

#define yylval RE_lval

#include "re-parse.h"

const char* RE_parse_input = 0;

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
			curr_ccl = rem->LookupCCL(yytext);
			if ( curr_ccl )
				{
				if ( yyinput() != ']' )
					synerr("bad character class");
				yylval.ccl_val = curr_ccl;
				return TOK_CCL;
				}
			else
				{
				curr_ccl = new CCL();
				rem->InsertCCL(yytext, curr_ccl);

				// Push back everything but the leading bracket
				// so the ccl can be rescanned.
				yyless(1);

				BEGIN(SC_FIRST_CCL);
				return '[';
				}
			}

	"{"{NAME}"}"	{
			char* nmstr = copy_string(yytext+1);
			nmstr[yyleng - 2] = '\0';  // chop trailing brace

			const char* namedef = rem->LookupDef(nmstr);
			delete nmstr;

			if ( ! namedef )
				synerr("undefined definition");
			else
				{ // push back name surrounded by ()'s
				int len = strlen(namedef);

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

	[|*+?.(){}]	return yytext[0];
	.		yylval.int_val = yytext[0]; return TOK_CHAR;
	\n		return 0;	// treat as end of pattern
}

<SC_QUOTE>{
	[^"\n]$		synerr("missing quote"); return '"';
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
			synerr("bad character class");
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
	"[:lower:]"	RET_CCE(my_islower)
	"[:print:]"	RET_CCE(my_isprint)
	"[:punct:]"	RET_CCE(my_ispunct)
	"[:space:]"	RET_CCE(my_isspace)
	"[:xdigit:]"	RET_CCE(my_isxdigit)
	"[:upper:]"	{
			BEGIN(SC_CCL);
			yylval.cce_val =
				case_insensitive ? my_isupper : my_islower;
			return TOK_CCE;
			}

	{CCL_EXPR}	{
			synerr("bad character class expression");
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
			synerr("bad character inside {}'s");
			BEGIN(INITIAL);
			return '}';
			}
}

<INITIAL,SC_QUOTE,SC_FIRST_CCL,SC_CCL>{ESCSEQ}	{
			const char* esc_text = yytext + 1;
			yylval.int_val = expand_escape(esc_text);

			if ( YY_START == SC_FIRST_CCL )
				BEGIN(SC_CCL);

			return TOK_CHAR;
			}

<*>.|\n			synerr("bad character");

%%

void RE_set_input(const char* str)
	{
	RE_parse_input = str;
	yy_scan_string(str);
	}

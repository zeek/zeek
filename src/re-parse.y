// parse.y - parser for flex input

%{
#include <cstdlib>

#include "zeek/RE.h"
#include "zeek/CCL.h"
#include "zeek/NFA.h"
#include "zeek/EquivClass.h"
#include "zeek/Reporter.h"

int csize = 256;
int syntax_error = 0;

namespace zeek::detail {
	int cupper(int sym);
	int clower(int sym);
}

void yyerror(const char msg[]);
%}

%token TOK_CHAR TOK_NUMBER TOK_CCL TOK_CCE TOK_CASE_INSENSITIVE TOK_SINGLE_LINE

%union {
	int int_val;
	cce_func cce_val;
	zeek::detail::CCL* ccl_val;
	zeek::detail::NFA_Machine* mach_val;
}

%type <int_val> TOK_CHAR TOK_NUMBER
%type <cce_val> TOK_CCE
%type <ccl_val> TOK_CCL ccl full_ccl
%type <mach_val> re singleton series string

%destructor { delete $$; } <mach_val>

%%
flexrule	:	re
			{ $1->AddAccept(1); zeek::detail::nfa = $1; }

		|  error
			{ return 1; }
		;

re		:  re '|' series
			{ $$ = zeek::detail::make_alternate($1, $3); }
		|  series
		|
			{ $$ = new zeek::detail::NFA_Machine(new zeek::detail::EpsilonState()); }
		;

series		:  series singleton
			{ $1->AppendMachine($2); $$ = $1; }
		|  singleton
		;

singleton	:  singleton '*'
			{ $1->MakeClosure(); $$ = $1; }

		|  singleton '+'
			{ $1->MakePositiveClosure(); $$ = $1; }

		|  singleton '?'
			{ $1->MakeOptional(); $$ = $1; }

		|  singleton '{' TOK_NUMBER ',' TOK_NUMBER '}'
			{
			if ( $3 > $5 || $3 < 0 )
				zeek::detail::synerr("bad iteration values");
			else
				{
				if ( $3 == 0 )
					{
					if ( $5 == 0 )
						{
						$$ = new zeek::detail::NFA_Machine(new zeek::detail::EpsilonState());
						Unref($1);
						}
					else
						{
						$1->MakeRepl(1, $5);
						$1->MakeOptional();
						}
					}
				else
					$1->MakeRepl($3, $5);
				}
			}

		|  singleton '{' TOK_NUMBER ',' '}'
			{
			if ( $3 < 0 )
				zeek::detail::synerr("iteration value must be positive");
			else if ( $3 == 0 )
				$1->MakeClosure();
			else
				$1->MakeRepl($3, NO_UPPER_BOUND);

			$$ = $1;
			}

		|  singleton '{' TOK_NUMBER '}'
			{
			if ( $3 < 0 )
				zeek::detail::synerr("iteration value must be positive");
			else if ( $3 == 0 )
				{
				Unref($1);
				$$ = new zeek::detail::NFA_Machine(new zeek::detail::EpsilonState());
				}
			else
				$1->LinkCopies($3-1);
			}

		|  '.'
			{
			$$ = new zeek::detail::NFA_Machine(new zeek::detail::NFA_State(
                zeek::detail::rem->AnyCCL(zeek::detail::re_single_line)));
			}

		|  full_ccl
			{
			$1->Sort();
			zeek::detail::rem->EC()->CCL_Use($1);
			$$ = new zeek::detail::NFA_Machine(new zeek::detail::NFA_State($1));
			}

		|  TOK_CCL
			{ $$ = new zeek::detail::NFA_Machine(new zeek::detail::NFA_State($1)); }

		|  '"' string '"'
			{ $$ = $2; }

		|  '(' re ')'
			{ $$ = $2; }

		|  TOK_CASE_INSENSITIVE re ')'
			{ $$ = $2; zeek::detail::case_insensitive = false; }

		|  TOK_SINGLE_LINE re ')'
			{ $$ = $2; zeek::detail::re_single_line = false; }

		|  TOK_CHAR
			{
			auto sym = $1;

			if ( sym < 0 || ( sym >= NUM_SYM && sym != SYM_EPSILON ) )
				{
				zeek::reporter->Error("bad symbol %d (compiling pattern /%s/)", sym,
				                      zeek::detail::RE_parse_input);
				return 1;
				}

			$$ = new zeek::detail::NFA_Machine(new zeek::detail::NFA_State(sym, zeek::detail::rem->EC()));
			}

		|  '^'
			{
			$$ = new zeek::detail::NFA_Machine(new zeek::detail::NFA_State(SYM_BOL, zeek::detail::rem->EC()));
			$$->MarkBOL();
			}

		|  '$'
			{
			$$ = new zeek::detail::NFA_Machine(new zeek::detail::NFA_State(SYM_EOL, zeek::detail::rem->EC()));
			$$->MarkEOL();
			}
		;

full_ccl	:  '[' ccl ']'
			{ $$ = $2; }

		|  '[' '^' ccl ']'
			{
			$3->Negate();
			$$ = $3;
			}
		;

ccl		:  ccl TOK_CHAR '-' TOK_CHAR
			{
			if ( $2 > $4 )
				zeek::detail::synerr("negative range in character class");

			else if ( zeek::detail::case_insensitive &&
				  (isalpha($2) || isalpha($4)) )
				{
				if ( isalpha($2) && isalpha($4) &&
				     isupper($2) == isupper($4) )
					{ // Compatible range, do both versions
					int l2 = tolower($2);
					int l4 = tolower($4);

					for ( int i = l2; i<= l4; ++i )
						{
						$1->Add(i);
						$1->Add(toupper(i));
						}
					}

				else
					zeek::detail::synerr("ambiguous case-insensitive character class");
				}

			else
				{
				for ( int i = $2; i <= $4; ++i )
					$1->Add(i);
				}
			}

		|  ccl TOK_CHAR
			{
			if ( zeek::detail::case_insensitive && isalpha($2) )
				{
				$1->Add(zeek::detail::clower($2));
				$1->Add(zeek::detail::cupper($2));
				}
			else
				$1->Add($2);
			}

		|  ccl ccl_expr

		|
			{ $$ = zeek::detail::curr_ccl; }
		;

ccl_expr:	   TOK_CCE
			{
			for ( int c = 0; c < csize; ++c )
				if ( isascii(c) && $1(c) )
					zeek::detail::curr_ccl->Add(c);
			}
		;

string		:  string TOK_CHAR
			{
			// Even if case-insensitivity is set,
			// leave this alone; that provides a way
			// of "escaping" out of insensitivity
			// if needed.
			$1->AppendState(new zeek::detail::NFA_State($2, zeek::detail::rem->EC()));
			$$ = $1;
			}

		|
			{ $$ = new zeek::detail::NFA_Machine(new zeek::detail::EpsilonState()); }
		;
%%

namespace zeek::detail {

int cupper(int sym)
	{
	return (isascii(sym) && islower(sym)) ?  toupper(sym) : sym;
	}

int clower(int sym)
	{
	return (isascii(sym) && isupper(sym)) ?  tolower(sym) : sym;
	}

void synerr(const char str[])
	{
	syntax_error = true;
	zeek::reporter->Error("%s (compiling pattern /%s/)", str, RE_parse_input);
	}

} // namespace zeek::detail

void yyerror(const char msg[])
	{
	}

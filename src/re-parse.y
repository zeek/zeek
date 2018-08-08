// parse.y - parser for flex input

%{
#include <stdlib.h>

#include "CCL.h"
#include "NFA.h"
#include "EquivClass.h"
#include "Reporter.h"

int csize = 256;
int syntax_error = 0;

int cupper(int sym);
int clower(int sym);
void yyerror(const char msg[]);
%}

%token TOK_CHAR TOK_NUMBER TOK_CCL TOK_CCE TOK_CASE_INSENSITIVE

%union {
	int int_val;
	cce_func cce_val;
	CCL* ccl_val;
	NFA_Machine* mach_val;
}

%type <int_val> TOK_CHAR TOK_NUMBER
%type <cce_val> TOK_CCE
%type <ccl_val> TOK_CCL ccl full_ccl
%type <mach_val> re singleton series string

%%
flexrule	:	re
			{ $1->AddAccept(1); nfa = $1; }

		|  error
			{ return 1; }
		;

re		:  re '|' series
			{ $$ = make_alternate($1, $3); }
		|  series
		| 
			{ $$ = new NFA_Machine(new EpsilonState()); }
		;

series		:  series singleton
			{ $1->AppendMachine($2); }
		|  singleton
		;

singleton	:  singleton '*'
			{ $1->MakeClosure(); }

		|  singleton '+'
			{ $1->MakePositiveClosure(); }

		|  singleton '?'
			{ $1->MakeOptional(); }

		|  singleton '{' TOK_NUMBER ',' TOK_NUMBER '}'
			{
			if ( $3 > $5 || $3 < 0 )
				synerr("bad iteration values");
			else
				{
				if ( $3 == 0 )
					{
					if ( $5 == 0 )
						{
						$$ = new NFA_Machine(new EpsilonState());
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
				synerr("iteration value must be positive");
			else if ( $3 == 0 )
				$1->MakeClosure();
			else
				$1->MakeRepl($3, NO_UPPER_BOUND);
			}

		|  singleton '{' TOK_NUMBER '}'
			{
			if ( $3 < 0 )
				synerr("iteration value must be positive");
			else if ( $3 == 0 )
				{
				Unref($1);
				$$ = new NFA_Machine(new EpsilonState());
				}
			else
				$1->LinkCopies($3-1);
			}

		|  '.'
			{
			$$ = new NFA_Machine(new NFA_State(rem->AnyCCL()));
			}

		|  full_ccl
			{
			$1->Sort();
			rem->EC()->CCL_Use($1);
			$$ = new NFA_Machine(new NFA_State($1));
			}

		|  TOK_CCL
			{ $$ = new NFA_Machine(new NFA_State($1)); }

		|  '"' string '"'
			{ $$ = $2; }

		|  '(' re ')'
			{ $$ = $2; }

		|  TOK_CASE_INSENSITIVE re ')'
			{ $$ = $2; case_insensitive = 0; }

		|  TOK_CHAR
			{ $$ = new NFA_Machine(new NFA_State($1, rem->EC())); }

		|  '^'
			{
			$$ = new NFA_Machine(new NFA_State(SYM_BOL, rem->EC()));
			$$->MarkBOL();
			}

		|  '$'
			{
			$$ = new NFA_Machine(new NFA_State(SYM_EOL, rem->EC()));
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
				synerr("negative range in character class");

			else if ( case_insensitive &&
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
					synerr("ambiguous case-insensitive character class");
				}

			else
				{
				for ( int i = $2; i <= $4; ++i )
					$1->Add(i);
				}
			}

		|  ccl TOK_CHAR
			{
			if ( case_insensitive && isalpha($2) )
				{
				$1->Add(clower($2));
				$1->Add(cupper($2));
				}
			else
				$1->Add($2);
			}

		|  ccl ccl_expr

		|
			{ $$ = curr_ccl; }
		;

ccl_expr:	   TOK_CCE
			{
			for ( int c = 0; c < csize; ++c )
				if ( isascii(c) && $1(c) )
					curr_ccl->Add(c);
			}
		;

string		:  string TOK_CHAR
			{
			// Even if case-insensitivity is set,
			// leave this alone; that provides a way
			// of "escaping" out of insensitivity
			// if needed.
			$1->AppendState(new NFA_State($2, rem->EC()));
			}

		|
			{ $$ = new NFA_Machine(new EpsilonState()); }
		;
%%

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
	reporter->Error("%s (compiling pattern /%s/)", str, RE_parse_input);
	}

void yyerror(const char msg[])
	{
	}

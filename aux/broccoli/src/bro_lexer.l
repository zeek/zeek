%option noyywrap

%{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include "broccoli.h"
#include "bro_debug.h"
#include "bro_parser.h"

int broerror(char *fmt, ...);
#define yyerror broerror
#define yylval brolval

extern int bro_parse_lineno;

%}


%%
[\[\]]	                 return yytext[0];

yes|true|on    		 { yylval.i = 1; return BROINT; }
no|false|off    	 { yylval.i = 0; return BROINT; }
[ \t]+           	 ;
[0-9]+                   { yylval.i = strtol(yytext, NULL, 10); return BROINT; }
[0-9]+\.[0-9]+           { yylval.d = strtod(yytext, NULL); return BRODOUBLE; }
\".*\"                   { yylval.s = strdup(yytext+1);
                           yylval.s[strlen(yylval.s) - 1] = '\0';
                           return BROSTRING;
                         }
[[:alnum:][:punct:]]+    { yylval.s = strdup(yytext); return BROWORD; }

"#".*\n                  { bro_parse_lineno++; }
"//".*\n                 { bro_parse_lineno++; }
\n                       { bro_parse_lineno++; }

.                        { D(("Syntax error: '%s'\n", yytext)); }

%%

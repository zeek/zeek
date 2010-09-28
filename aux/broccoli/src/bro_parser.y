%{

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include "bro_debug.h"
#include "bro_config.h"

int brolex(void);
int broparse(void);
int broerror(char *, ...);

#define yylex brolex
#define yyparse broparse
#define yyerror broerror

int bro_parse_errors = 0;
int bro_parse_lineno = 0;
const char *bro_parse_filename = NULL;
 
%}

%union {
  int   i;
  char *s;
  double d;
}

%token <i> BROINT
%token <s> BROWORD BROSTRING
%token <d> BRODOUBLE

%%
configfile:
	   | options
           ;
options:     option
           | options option
           ;

option:      domain
           | intopt
           | stringopt
           | floatopt
           ;

intopt:      BROWORD BROINT	{ __bro_conf_add_int($1, $2);
				  free($1);
				}
           ;

stringopt:   BROWORD BROSTRING  { __bro_conf_add_str($1, $2);
                                  free($1); free($2);
				}
	   | BROWORD BROWORD    { __bro_conf_add_str($1, $2);
                                  free($1); free($2);
				}
           ;

floatopt:    BROWORD BRODOUBLE	{ __bro_conf_add_dbl($1, $2);
				  free($1);
				}
           ;

domain:      '[' BROWORD ']'	{ __bro_conf_set_storage_domain($2);
				  free($2); 
				}
           ;
%%

int
yyerror(char *fmt, ...)
{
  va_list ap;
  bro_parse_errors++;
  
#ifdef BRO_DEBUG
  va_start(ap, fmt);
  fprintf(stderr, "%s:%d: ", bro_parse_filename, bro_parse_lineno);
  vfprintf(stderr, fmt, ap);
  fprintf(stderr, "\n");
  va_end(ap);
#endif
  return 0;
}

int
__bro_parse_config(const char *filename)
{
  const char *domain;
  extern FILE *broin;

  /* Save the current config domain */
  if ( (domain = __bro_conf_get_domain()))
    domain = strdup(domain);
  
  D(("Parsing configuration from '%s'.\n", filename));

  if (! (broin = fopen(filename, "r")))
    {
      D(("Error opening config file %s: %s\n", filename, strerror(errno)));
      return -1;
    }
  
  bro_parse_lineno = 1;
  bro_parse_filename = filename;
  bro_parse_errors = 0;

  yyparse();
  fclose(broin);

  /* Reset the config domain to the original one. */
  __bro_conf_set_domain(domain);
  
  return (bro_parse_errors ? -1 : 0);
}
